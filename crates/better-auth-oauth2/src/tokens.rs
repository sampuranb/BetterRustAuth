// OAuth2 token types — maps to packages/core/src/oauth2/oauth-provider.ts
//
// OAuth2Tokens: Standard token response fields.
// OAuth2UserInfo: Normalized user information from a provider.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Standard OAuth2 token response.
/// Maps to the TypeScript `OAuth2Tokens` interface.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2Tokens {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// Raw token response — preserves provider-specific fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,
}

/// Raw token response from the provider (snake_case wire format).
/// Used to deserialize the raw JSON before converting to `OAuth2Tokens`.
#[derive(Debug, Deserialize)]
pub(crate) struct RawTokenResponse {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub token_type: Option<String>,
    pub expires_in: Option<i64>,
    pub refresh_token_expires_in: Option<i64>,
    pub scope: Option<String>,
    pub id_token: Option<String>,
}

impl OAuth2Tokens {
    /// Parse a raw provider token response into `OAuth2Tokens`.
    /// Maps to `getOAuth2Tokens()` in TypeScript.
    pub fn from_raw(data: &serde_json::Value) -> Self {
        let raw: RawTokenResponse =
            serde_json::from_value(data.clone()).unwrap_or(RawTokenResponse {
                access_token: None,
                refresh_token: None,
                token_type: None,
                expires_in: None,
                refresh_token_expires_in: None,
                scope: None,
                id_token: None,
            });

        let now = Utc::now();
        let expires_at = raw
            .expires_in
            .map(|secs| now + chrono::Duration::seconds(secs));
        let refresh_expires_at = raw
            .refresh_token_expires_in
            .map(|secs| now + chrono::Duration::seconds(secs));

        let scopes = raw
            .scope
            .map(|s| s.split(' ').map(String::from).collect())
            .unwrap_or_default();

        Self {
            token_type: raw.token_type,
            access_token: raw.access_token,
            refresh_token: raw.refresh_token,
            access_token_expires_at: expires_at,
            refresh_token_expires_at: refresh_expires_at,
            scopes,
            id_token: raw.id_token,
            raw: Some(data.clone()),
        }
    }
}

/// Normalized user information returned by a provider.
/// Maps to `OAuth2UserInfo` in TypeScript.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2UserInfo {
    /// Provider-specific user ID (may be a string or numeric converted to string).
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    pub email_verified: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_oauth2_tokens() {
        let raw = serde_json::json!({
            "access_token": "ya29.abc",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "1//xyz",
            "scope": "openid email profile",
            "id_token": "ey.jwt.token"
        });

        let tokens = OAuth2Tokens::from_raw(&raw);
        assert_eq!(tokens.access_token.as_deref(), Some("ya29.abc"));
        assert_eq!(tokens.token_type.as_deref(), Some("Bearer"));
        assert_eq!(tokens.refresh_token.as_deref(), Some("1//xyz"));
        assert_eq!(tokens.scopes, vec!["openid", "email", "profile"]);
        assert_eq!(tokens.id_token.as_deref(), Some("ey.jwt.token"));
        assert!(tokens.access_token_expires_at.is_some());
        assert!(tokens.raw.is_some());
    }

    #[test]
    fn test_parse_minimal_tokens() {
        let raw = serde_json::json!({
            "access_token": "token123"
        });

        let tokens = OAuth2Tokens::from_raw(&raw);
        assert_eq!(tokens.access_token.as_deref(), Some("token123"));
        assert!(tokens.refresh_token.is_none());
        assert!(tokens.scopes.is_empty());
    }
}
