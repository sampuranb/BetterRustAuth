//! OAuth Provider configuration.

use serde::{Deserialize, Serialize};

/// OAuth Provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthProviderOptions {
    /// Issuer URL (used in discovery metadata).
    pub issuer: String,
    /// Access token TTL in seconds.
    #[serde(default = "default_access_token_ttl")]
    pub access_token_ttl: i64,
    /// Refresh token TTL in seconds.
    #[serde(default = "default_refresh_token_ttl")]
    pub refresh_token_ttl: i64,
    /// Authorization code TTL in seconds.
    #[serde(default = "default_code_ttl")]
    pub authorization_code_ttl: i64,
    /// Require PKCE for public clients.
    #[serde(default = "default_true")]
    pub require_pkce: bool,
    /// Allowed scopes.
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// Allow refresh token rotation.
    #[serde(default = "default_true")]
    pub rotate_refresh_tokens: bool,
}

fn default_access_token_ttl() -> i64 { 3600 }        // 1 hour
fn default_refresh_token_ttl() -> i64 { 2592000 }    // 30 days
fn default_code_ttl() -> i64 { 600 }                  // 10 minutes
fn default_true() -> bool { true }
fn default_scopes() -> Vec<String> {
    vec!["openid".into(), "profile".into(), "email".into()]
}

impl Default for OAuthProviderOptions {
    fn default() -> Self {
        Self {
            issuer: "http://localhost:3000".to_string(),
            access_token_ttl: default_access_token_ttl(),
            refresh_token_ttl: default_refresh_token_ttl(),
            authorization_code_ttl: default_code_ttl(),
            require_pkce: true,
            scopes: default_scopes(),
            rotate_refresh_tokens: true,
        }
    }
}
