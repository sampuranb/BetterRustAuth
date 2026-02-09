//! # better-auth-passkey
//!
//! WebAuthn/Passkey plugin for Better Auth.
//! Maps to TS `packages/passkey/` (1,424 lines).
//!
//! ## Endpoints
//! - `GET /passkey/generate-register-options`
//! - `POST /passkey/verify-registration`
//! - `GET /passkey/generate-authenticate-options`
//! - `POST /passkey/verify-authentication`
//! - `GET /passkey/list-user-passkeys`
//! - `POST /passkey/delete-passkey`
//! - `POST /passkey/update-passkey`

pub mod error;
pub mod schema;
pub mod types;
pub mod routes;

pub use error::*;
pub use schema::*;
pub use types::*;

/// Default challenge max age in seconds (5 minutes).
pub const MAX_AGE_IN_SECONDS: u64 = 300;

/// Passkey plugin configuration.
/// Maps to TS `PasskeyOptions`.
#[derive(Debug, Clone)]
pub struct PasskeyOptions {
    /// Relying Party ID (e.g. "localhost", "example.com").
    pub rp_id: Option<String>,
    /// Human-readable RP name.
    pub rp_name: Option<String>,
    /// Expected origin(s) for WebAuthn ceremonies.
    pub origin: Option<Vec<String>>,
    /// Authenticator selection criteria.
    pub authenticator_selection: Option<AuthenticatorSelection>,
    /// Cookie name for WebAuthn challenge.
    pub challenge_cookie: String,
}

impl Default for PasskeyOptions {
    fn default() -> Self {
        Self {
            rp_id: None,
            rp_name: None,
            origin: None,
            authenticator_selection: None,
            challenge_cookie: "better-auth-passkey".to_string(),
        }
    }
}

/// Authenticator selection criteria.
/// Maps to TS `AuthenticatorSelectionCriteria`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuthenticatorSelection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_resident_key: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resident_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
}

impl Default for AuthenticatorSelection {
    fn default() -> Self {
        Self {
            authenticator_attachment: None,
            require_resident_key: None,
            resident_key: Some("preferred".to_string()),
            user_verification: Some("preferred".to_string()),
        }
    }
}

/// Get the RP ID from options or derive from base URL.
pub fn get_rp_id(opts: &PasskeyOptions, base_url: &str) -> String {
    if let Some(ref rp_id) = opts.rp_id {
        return rp_id.clone();
    }
    // Extract hostname from base URL
    if let Ok(url) = url::Url::parse(base_url) {
        url.host_str().unwrap_or("localhost").to_string()
    } else {
        "localhost".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passkey_defaults() {
        let opts = PasskeyOptions::default();
        assert_eq!(opts.challenge_cookie, "better-auth-passkey");
        assert!(opts.rp_id.is_none());
    }

    #[test]
    fn test_get_rp_id() {
        let opts = PasskeyOptions::default();
        assert_eq!(get_rp_id(&opts, "https://example.com/api"), "example.com");
        assert_eq!(get_rp_id(&opts, "http://localhost:3000"), "localhost");

        let opts = PasskeyOptions { rp_id: Some("custom.com".into()), ..Default::default() };
        assert_eq!(get_rp_id(&opts, "https://example.com"), "custom.com");
    }

    #[test]
    fn test_authenticator_selection_defaults() {
        let sel = AuthenticatorSelection::default();
        assert_eq!(sel.resident_key, Some("preferred".to_string()));
        assert_eq!(sel.user_verification, Some("preferred".to_string()));
    }
}
