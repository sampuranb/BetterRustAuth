// Have I Been Pwned plugin — checks passwords against the HIBP breach database.
//
// Maps to: packages/better-auth/src/plugins/haveibeenpwned/index.ts
//
// Before hashing a password on sign-up, password change, or password reset,
// this plugin queries the Have I Been Pwned API using k-anonymity (only the
// first 5 chars of the SHA-1 hash are sent). If the password has been seen in
// breaches, the operation is rejected with an error.

use async_trait::async_trait;

use better_auth_core::error::ErrorCode;
use better_auth_core::plugin::{BetterAuthPlugin, PluginHook};

/// HIBP plugin options.
#[derive(Debug, Clone)]
pub struct HaveIBeenPwnedOptions {
    /// Custom error message when a password is compromised.
    pub custom_message: Option<String>,
    /// Paths to check for password input.
    pub paths: Vec<String>,
    /// Minimum number of breaches before rejecting (default: 1).
    pub min_breaches: u32,
}

impl Default for HaveIBeenPwnedOptions {
    fn default() -> Self {
        Self {
            custom_message: None,
            paths: vec![
                "/sign-up/email".into(),
                "/change-password".into(),
                "/reset-password".into(),
            ],
            min_breaches: 1,
        }
    }
}

/// Have I Been Pwned plugin.
#[derive(Debug)]
pub struct HaveIBeenPwnedPlugin {
    options: HaveIBeenPwnedOptions,
}

impl HaveIBeenPwnedPlugin {
    pub fn new(options: HaveIBeenPwnedOptions) -> Self {
        Self { options }
    }

    /// Access the options (for handler integration).
    pub fn options(&self) -> &HaveIBeenPwnedOptions {
        &self.options
    }

    /// Get the error message for a compromised password.
    pub fn error_message(&self) -> &str {
        self.options.custom_message.as_deref().unwrap_or(
            "This password has been found in a data breach. Please use a different password.",
        )
    }

    /// Check if a request path should be checked for compromised passwords.
    pub fn should_check_path(&self, path: &str) -> bool {
        self.options.paths.iter().any(|p| path.starts_with(p))
    }
}

impl Default for HaveIBeenPwnedPlugin {
    fn default() -> Self {
        Self::new(HaveIBeenPwnedOptions::default())
    }
}

// ─── Core handler logic ─────────────────────────────────────────────────

/// Check if a password has been compromised using the HIBP k-anonymity API.
///
/// Uses SHA-1 hashing (the HIBP API requirement), NOT SHA-256.
/// Only the first 5 characters of the hex-encoded hash are sent to the API.
///
/// Returns `Ok(count)` where `count` is the number of times the password
/// appeared in breaches. Returns `Ok(0)` if not found.
pub async fn check_password_breach_count(password: &str) -> Result<u32, String> {
    use sha1::Digest;

    let hash = sha1::Sha1::digest(password.as_bytes());
    let sha_hash = hex::encode(hash).to_uppercase();
    let prefix = &sha_hash[..5];
    let suffix = &sha_hash[5..];

    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header("Add-Padding", "true")
        .header("User-Agent", "BetterAuth Password Checker")
        .send()
        .await
        .map_err(|e| format!("HIBP API request failed: {e}"))?;

    let body = response
        .text()
        .await
        .map_err(|e| format!("HIBP API response read failed: {e}"))?;

    // Each line is "SUFFIX:COUNT"
    let count = body
        .lines()
        .find_map(|line| {
            let mut parts = line.splitn(2, ':');
            let hash_suffix = parts.next()?.trim();
            let count_str = parts.next()?.trim();
            if hash_suffix.eq_ignore_ascii_case(suffix) {
                count_str.parse::<u32>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);

    Ok(count)
}

/// Check if a password has been compromised (convenience wrapper).
///
/// Returns `true` if the password appears in the breach database.
pub async fn check_password_compromised(password: &str) -> Result<bool, String> {
    let count = check_password_breach_count(password).await?;
    Ok(count > 0)
}

/// Check if a password exceeds the minimum breach threshold.
///
/// Returns `true` if the password should be rejected.
pub async fn should_reject_password(password: &str, min_breaches: u32) -> Result<bool, String> {
    let count = check_password_breach_count(password).await?;
    Ok(count >= min_breaches)
}

// ─── Plugin trait ───────────────────────────────────────────────────────

#[async_trait]
impl BetterAuthPlugin for HaveIBeenPwnedPlugin {
    fn id(&self) -> &str {
        "have-i-been-pwned"
    }

    fn name(&self) -> &str {
        "Have I Been Pwned"
    }

    fn hooks(&self) -> Vec<PluginHook> {
        use better_auth_core::plugin::{HookOperation, HookTiming};
        vec![PluginHook {
            model: "user".to_string(),
            timing: HookTiming::Before,
            operation: HookOperation::Create,
        }]
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![ErrorCode::InvalidPassword]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hibp_plugin_id() {
        let plugin = HaveIBeenPwnedPlugin::default();
        assert_eq!(plugin.id(), "have-i-been-pwned");
    }

    #[test]
    fn test_hibp_plugin_error_codes() {
        let plugin = HaveIBeenPwnedPlugin::default();
        let codes = plugin.error_codes();
        assert_eq!(codes.len(), 1);
        assert_eq!(codes[0], ErrorCode::InvalidPassword);
    }

    #[test]
    fn test_hibp_default_paths() {
        let plugin = HaveIBeenPwnedPlugin::default();
        assert_eq!(plugin.options.paths.len(), 3);
        assert!(plugin.options.paths.contains(&"/sign-up/email".to_string()));
    }

    #[test]
    fn test_should_check_path() {
        let plugin = HaveIBeenPwnedPlugin::default();
        assert!(plugin.should_check_path("/sign-up/email"));
        assert!(plugin.should_check_path("/change-password"));
        assert!(plugin.should_check_path("/reset-password"));
        assert!(!plugin.should_check_path("/sign-in/email"));
    }

    #[test]
    fn test_error_message_default() {
        let plugin = HaveIBeenPwnedPlugin::default();
        assert!(plugin.error_message().contains("data breach"));
    }

    #[test]
    fn test_error_message_custom() {
        let plugin = HaveIBeenPwnedPlugin::new(HaveIBeenPwnedOptions {
            custom_message: Some("Bad password!".into()),
            ..Default::default()
        });
        assert_eq!(plugin.error_message(), "Bad password!");
    }

    #[test]
    fn test_min_breaches_default() {
        let plugin = HaveIBeenPwnedPlugin::default();
        assert_eq!(plugin.options.min_breaches, 1);
    }
}
