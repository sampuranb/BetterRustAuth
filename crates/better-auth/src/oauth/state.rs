// OAuth2 state management — maps to packages/better-auth/src/state.ts + oauth2/state.ts
//
// Handles generating and parsing OAuth state parameters for CSRF protection
// and callback data passing during the OAuth flow.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::context::AuthContext;
use crate::internal_adapter::AdapterError;

/// State data stored during the OAuth flow.
///
/// Matches TS `StateData` schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateData {
    pub callback_url: String,
    pub code_verifier: String,
    #[serde(default)]
    pub error_url: Option<String>,
    #[serde(default)]
    pub new_user_url: Option<String>,
    #[serde(default)]
    pub expires_at: i64,
    #[serde(default)]
    pub link: Option<LinkData>,
    #[serde(default)]
    pub request_sign_up: Option<bool>,
}

/// Link data for account linking during OAuth.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkData {
    pub email: String,
    pub user_id: String,
}

/// Error codes for state operations.
#[derive(Debug, Clone, PartialEq)]
pub enum StateErrorCode {
    GenerationError,
    Invalid,
    Mismatch,
    SecurityMismatch,
}

impl std::fmt::Display for StateErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GenerationError => write!(f, "state_generation_error"),
            Self::Invalid => write!(f, "state_invalid"),
            Self::Mismatch => write!(f, "state_mismatch"),
            Self::SecurityMismatch => write!(f, "state_security_mismatch"),
        }
    }
}

/// State error with code and message.
#[derive(Debug)]
pub struct StateError {
    pub code: StateErrorCode,
    pub message: String,
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for StateError {}

/// Generate a new OAuth state.
///
/// Matches TS `generateGenericState` using the database strategy:
/// 1. Generate a random state identifier
/// 2. Store the state data as a verification record in the database
/// 3. Return the state identifier and code verifier
pub async fn generate_state(
    ctx: Arc<AuthContext>,
    state_data: StateData,
) -> Result<GeneratedState, StateError> {
    let state = crate::crypto::random::generate_random_string(32);

    let expires_at = chrono::Utc::now() + chrono::TimeDelta::minutes(10);
    let value = serde_json::to_string(&state_data).map_err(|e| StateError {
        code: StateErrorCode::GenerationError,
        message: format!("Failed to serialize state: {}", e),
    })?;

    let verification = ctx
        .adapter
        .create_verification(&state, &value, expires_at)
        .await
        .map_err(|_| StateError {
            code: StateErrorCode::GenerationError,
            message: "Unable to create verification. Make sure the database adapter is properly working and there is a verification table.".into(),
        })?;

    let identifier = verification["identifier"]
        .as_str()
        .unwrap_or(&state)
        .to_string();

    Ok(GeneratedState {
        state: identifier,
        code_verifier: state_data.code_verifier,
    })
}

/// Parse and validate an OAuth state.
///
/// Matches TS `parseGenericState` using the database strategy:
/// 1. Look up the verification record by state identifier
/// 2. Parse the stored state data
/// 3. Check expiration
/// 4. Delete the verification record
pub async fn parse_state(
    ctx: Arc<AuthContext>,
    state: &str,
) -> Result<StateData, StateError> {
    // Look up verification
    let data = ctx
        .adapter
        .find_verification(state)
        .await
        .map_err(|_| StateError {
            code: StateErrorCode::Mismatch,
            message: "Failed to query verification".into(),
        })?
        .ok_or(StateError {
            code: StateErrorCode::Mismatch,
            message: "State mismatch: verification not found".into(),
        })?;

    // Parse the stored data
    let value = data["value"].as_str().unwrap_or("{}");
    let parsed: StateData = serde_json::from_str(value).map_err(|e| StateError {
        code: StateErrorCode::Invalid,
        message: format!("Failed to parse state data: {}", e),
    })?;

    // Check expiration
    let now = chrono::Utc::now().timestamp_millis();
    if parsed.expires_at < now && parsed.expires_at > 0 {
        return Err(StateError {
            code: StateErrorCode::Mismatch,
            message: "Invalid state: request expired".into(),
        });
    }

    // Delete the verification record after retrieval
    if let Some(id) = data["id"].as_str() {
        let _ = ctx.adapter.delete_verification(id).await;
    }

    Ok(parsed)
}

/// Result of state generation.
#[derive(Debug, Clone)]
pub struct GeneratedState {
    pub state: String,
    pub code_verifier: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_data_serde() {
        let data = StateData {
            callback_url: "https://example.com/callback".into(),
            code_verifier: "verifier-123".into(),
            error_url: Some("https://example.com/error".into()),
            new_user_url: None,
            expires_at: 1234567890000,
            link: Some(LinkData {
                email: "test@example.com".into(),
                user_id: "user-1".into(),
            }),
            request_sign_up: Some(true),
        };

        let json = serde_json::to_value(&data).unwrap();
        assert_eq!(json["callbackUrl"], "https://example.com/callback");
        assert_eq!(json["codeVerifier"], "verifier-123");
        assert_eq!(json["link"]["email"], "test@example.com");

        let roundtrip: StateData = serde_json::from_value(json).unwrap();
        assert_eq!(roundtrip.callback_url, "https://example.com/callback");
    }

    #[test]
    fn test_state_error_display() {
        let err = StateError {
            code: StateErrorCode::Mismatch,
            message: "verification not found".into(),
        };
        assert!(err.to_string().contains("state_mismatch"));
    }

    #[test]
    fn test_state_error_codes() {
        assert_eq!(StateErrorCode::GenerationError.to_string(), "state_generation_error");
        assert_eq!(StateErrorCode::Invalid.to_string(), "state_invalid");
        assert_eq!(StateErrorCode::Mismatch.to_string(), "state_mismatch");
        assert_eq!(StateErrorCode::SecurityMismatch.to_string(), "state_security_mismatch");
    }
}
