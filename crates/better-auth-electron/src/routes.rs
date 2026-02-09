// Routes — mirrors packages/electron/src/routes.ts
//
// Implements the two Electron endpoint handlers:
// 1. `/electron/token` — PKCE token exchange
// 2. `/electron/init-oauth-proxy` — OAuth proxy initialization

use base64::Engine;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error_codes::ELECTRON_ERROR_CODES;

/// Request body for the `/electron/token` endpoint.
///
/// Maps to TS `electronTokenBodySchema`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ElectronTokenRequest {
    /// The authorization token (from the redirect cookie).
    pub token: String,
    /// The state parameter for CSRF protection.
    pub state: String,
    /// The PKCE code verifier.
    pub code_verifier: String,
}

/// Response from the `/electron/token` endpoint.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ElectronTokenResponse {
    /// Session token.
    pub token: String,
    /// The authenticated user.
    pub user: serde_json::Value,
}

/// Query parameters for the `/electron/init-oauth-proxy` endpoint.
///
/// Maps to TS `electronInitOAuthProxyQuerySchema`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ElectronInitOAuthProxyQuery {
    /// The OAuth provider name.
    pub provider: String,
    /// The state parameter.
    pub state: String,
    /// The PKCE code challenge.
    pub code_challenge: String,
    /// The PKCE code challenge method (default: "plain").
    #[serde(default = "default_challenge_method")]
    pub code_challenge_method: String,
}

fn default_challenge_method() -> String {
    "plain".to_string()
}

/// Validate the PKCE code verifier against the stored code challenge.
///
/// Mirrors the TS PKCE validation logic in `electronToken`:
/// - For S256: SHA-256 hash the verifier and compare with timing-safe equality
/// - For plain: direct string comparison
pub fn validate_pkce(
    code_challenge: &str,
    code_challenge_method: &str,
    code_verifier: &str,
) -> Result<(), &'static str> {
    if code_challenge_method == "s256" {
        // Hash the code verifier with SHA-256
        let verifier_hash = Sha256::digest(code_verifier.as_bytes());

        // Decode the stored code challenge from base64url
        let challenge_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(code_challenge)
            .map_err(|_| ELECTRON_ERROR_CODES.invalid_code_verifier)?;

        // Timing-safe comparison
        if verifier_hash.len() != challenge_bytes.len() {
            return Err(ELECTRON_ERROR_CODES.invalid_code_verifier);
        }

        if verifier_hash
            .as_slice()
            .ct_eq(&challenge_bytes)
            .unwrap_u8()
            == 0
        {
            return Err(ELECTRON_ERROR_CODES.invalid_code_verifier);
        }
    } else {
        // Plain comparison
        if code_challenge != code_verifier {
            return Err(ELECTRON_ERROR_CODES.invalid_code_verifier);
        }
    }

    Ok(())
}

/// Generate a verification identifier for Electron token exchange.
///
/// Maps to TS `electron:${identifier}` format.
pub fn make_verification_identifier(identifier: &str) -> String {
    format!("electron:{}", identifier)
}

/// Generate a random identifier for the redirect cookie.
pub fn generate_identifier() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..62);
            if idx < 10 {
                (b'0' + idx) as char
            } else if idx < 36 {
                (b'A' + idx - 10) as char
            } else {
                (b'a' + idx - 36) as char
            }
        })
        .collect()
}

/// Build the verification value payload.
///
/// Maps to the JSON stored in the verification table.
pub fn build_verification_value(
    user_id: &str,
    code_challenge: &str,
    code_challenge_method: &str,
    state: &str,
) -> serde_json::Value {
    serde_json::json!({
        "userId": user_id,
        "codeChallenge": code_challenge,
        "codeChallengeMethod": code_challenge_method.to_lowercase(),
        "state": state,
    })
}

/// Supported social providers for OAuth proxy.
///
/// Maps to TS `SocialProviderListEnum`.
pub const SOCIAL_PROVIDERS: &[&str] = &[
    "apple",
    "discord",
    "facebook",
    "github",
    "google",
    "microsoft",
    "spotify",
    "twitch",
    "twitter",
    "dropbox",
    "linkedin",
    "gitlab",
    "reddit",
    "tiktok",
    "bitbucket",
    "coinbase",
    "zoom",
    "notion",
    "atlassian",
    "slack",
    "stripe",
    "figma",
    "strava",
    "kick",
    "x",
    "roblox",
    "vk",
    "yandex",
    "patreon",
    "monday",
    "hubspot",
    "line",
    "microsoft-entra-id",
];

/// Check if a provider name is a supported social provider.
pub fn is_social_provider(provider: &str) -> bool {
    SOCIAL_PROVIDERS.contains(&provider)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_pkce_plain() {
        assert!(validate_pkce("my-verifier", "plain", "my-verifier").is_ok());
        assert!(validate_pkce("my-verifier", "plain", "wrong").is_err());
    }

    #[test]
    fn test_validate_pkce_s256() {
        // Pre-compute: SHA-256("test-verifier") = base64url encoded
        let verifier = "test-verifier";
        let hash = Sha256::digest(verifier.as_bytes());
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);

        assert!(validate_pkce(&challenge, "s256", verifier).is_ok());
        assert!(validate_pkce(&challenge, "s256", "wrong-verifier").is_err());
    }

    #[test]
    fn test_make_verification_identifier() {
        assert_eq!(
            make_verification_identifier("abc123"),
            "electron:abc123"
        );
    }

    #[test]
    fn test_generate_identifier() {
        let id = generate_identifier();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_build_verification_value() {
        let value = build_verification_value("user-1", "challenge", "S256", "state-1");
        assert_eq!(value["userId"], "user-1");
        assert_eq!(value["codeChallenge"], "challenge");
        assert_eq!(value["codeChallengeMethod"], "s256");
        assert_eq!(value["state"], "state-1");
    }

    #[test]
    fn test_is_social_provider() {
        assert!(is_social_provider("github"));
        assert!(is_social_provider("google"));
        assert!(is_social_provider("apple"));
        assert!(!is_social_provider("unknown-provider"));
    }
}
