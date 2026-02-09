// OAuth state management — maps to packages/better-auth/src/state.ts
//
// Generates and parses OAuth state data for CSRF protection during social sign-in.
// Supports two strategies:
// 1. Cookie: state is encrypted with XChaCha20-Poly1305 and stored in a cookie
// 2. Database: state is stored in the verification table with an opaque token

use serde::{Deserialize, Serialize};

/// Data stored in OAuth state for round-trip through the provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateData {
    /// The URL to redirect to after successful authentication.
    pub callback_url: String,

    /// PKCE code verifier (if PKCE is used).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_verifier: Option<String>,

    /// URL to redirect to on error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_url: Option<String>,

    /// URL to redirect to for new users (onboarding).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_user_url: Option<String>,

    /// Whether this is an account linking flow.
    #[serde(default)]
    pub link: bool,

    /// Whether the user explicitly requested sign-up.
    #[serde(default)]
    pub request_sign_up: bool,

    /// Expiration timestamp (epoch millis).
    pub expires_at: i64,
}

/// Errors from parsing state.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("State expired")]
    Expired,

    #[error("Invalid state data: {0}")]
    Invalid(String),

    #[error("State not found")]
    NotFound,

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
}

/// Generate OAuth state for the "cookie" strategy.
///
/// The state data is encrypted and returned as a hex string.
/// The caller stores this in a cookie.
pub fn generate_cookie_state(
    data: &StateData,
    secret: &str,
) -> Result<String, better_auth_core::error::BetterAuthError> {
    let json = serde_json::to_string(data).map_err(|e| {
        better_auth_core::error::BetterAuthError::Other(format!(
            "Failed to serialize state: {e}"
        ))
    })?;

    crate::crypto::symmetric_encrypt(secret, &json)
}

/// Parse OAuth state from the "cookie" strategy.
///
/// Decrypts the hex string and deserializes the state data.
/// Returns an error if expired or decryption fails.
pub fn parse_cookie_state(
    encrypted: &str,
    secret: &str,
) -> Result<StateData, StateError> {
    let json = crate::crypto::symmetric_decrypt(secret, encrypted)
        .map_err(|e| StateError::DecryptionFailed(e.to_string()))?;

    let data: StateData = serde_json::from_str(&json)
        .map_err(|e| StateError::Invalid(e.to_string()))?;

    // Check expiration
    let now = chrono::Utc::now().timestamp_millis();
    if data.expires_at < now {
        return Err(StateError::Expired);
    }

    Ok(data)
}

/// Generate OAuth state for the "database" strategy.
///
/// Returns a random token. The caller stores the `StateData` in the
/// verification table with this token as the identifier.
pub fn generate_db_state_token() -> String {
    crate::crypto::generate_random_string(32)
}

/// Default state expiry: 10 minutes.
pub fn default_state_expires_at() -> i64 {
    chrono::Utc::now().timestamp_millis() + (10 * 60 * 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cookie_state_round_trip() {
        let data = StateData {
            callback_url: "https://example.com/callback".into(),
            code_verifier: Some("verifier-123".into()),
            error_url: None,
            new_user_url: None,
            link: false,
            request_sign_up: false,
            expires_at: default_state_expires_at(),
        };

        let secret = "my-32-char-secret-for-encryption";
        let encrypted = generate_cookie_state(&data, secret).unwrap();
        assert!(!encrypted.is_empty());

        let parsed = parse_cookie_state(&encrypted, secret).unwrap();
        assert_eq!(parsed.callback_url, "https://example.com/callback");
        assert_eq!(parsed.code_verifier.as_deref(), Some("verifier-123"));
        assert!(!parsed.link);
    }

    #[test]
    fn test_cookie_state_expired() {
        let data = StateData {
            callback_url: "https://example.com/callback".into(),
            code_verifier: None,
            error_url: None,
            new_user_url: None,
            link: false,
            request_sign_up: false,
            expires_at: 0, // Already expired
        };

        let secret = "my-32-char-secret-for-encryption";
        let encrypted = generate_cookie_state(&data, secret).unwrap();
        let result = parse_cookie_state(&encrypted, secret);
        assert!(matches!(result, Err(StateError::Expired)));
    }

    #[test]
    fn test_cookie_state_wrong_key() {
        let data = StateData {
            callback_url: "https://example.com/callback".into(),
            code_verifier: None,
            error_url: None,
            new_user_url: None,
            link: false,
            request_sign_up: false,
            expires_at: default_state_expires_at(),
        };

        let encrypted = generate_cookie_state(&data, "correct-key").unwrap();
        let result = parse_cookie_state(&encrypted, "wrong-key");
        assert!(matches!(result, Err(StateError::DecryptionFailed(_))));
    }

    #[test]
    fn test_db_state_token() {
        let token = generate_db_state_token();
        assert_eq!(token.len(), 32);

        // Tokens should be unique
        let token2 = generate_db_state_token();
        assert_ne!(token, token2);
    }
}
