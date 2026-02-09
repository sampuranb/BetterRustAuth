// OAuthProvider trait and ProviderOptions — maps to packages/core/src/oauth2/oauth-provider.ts
//
// The trait that every social provider (Google, GitHub, Apple, etc.) implements.
// ProviderOptions captures the per-provider configuration.

use std::collections::HashMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::tokens::{OAuth2Tokens, OAuth2UserInfo};

/// Configuration options for an OAuth provider.
/// Maps to the TypeScript `ProviderOptions` type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderOptions {
    /// OAuth client ID.
    pub client_id: String,

    /// OAuth client secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,

    /// Requested scopes.
    #[serde(default)]
    pub scope: Vec<String>,

    /// Remove default scopes of the provider.
    #[serde(default)]
    pub disable_default_scope: bool,

    /// Custom redirect URI (overrides the auto-generated one).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,

    /// Custom authorization endpoint URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,

    /// Client key (used by TikTok instead of client_id).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_key: Option<String>,

    /// Disable ID token sign-in for this provider.
    #[serde(default)]
    pub disable_id_token_sign_in: bool,

    /// Disable implicit sign-up (require explicit requestSignUp=true).
    #[serde(default)]
    pub disable_implicit_sign_up: bool,

    /// Disable sign-up entirely for this provider.
    #[serde(default)]
    pub disable_sign_up: bool,

    /// OAuth prompt parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,

    /// Response mode (query or form_post).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<String>,

    /// Override user info on each sign-in (default: false).
    #[serde(default)]
    pub override_user_info_on_sign_in: bool,
}

impl ProviderOptions {
    pub fn new(client_id: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: None,
            scope: Vec::new(),
            disable_default_scope: false,
            redirect_uri: None,
            authorization_endpoint: None,
            client_key: None,
            disable_id_token_sign_in: false,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            prompt: None,
            response_mode: None,
            override_user_info_on_sign_in: false,
        }
    }

    pub fn with_secret(mut self, secret: impl Into<String>) -> Self {
        self.client_secret = Some(secret.into());
        self
    }

    pub fn with_scopes(mut self, scopes: &[&str]) -> Self {
        self.scope = scopes.iter().map(|s| s.to_string()).collect();
        self
    }
}

/// Data passed to `create_authorization_url`.
#[derive(Debug, Clone)]
pub struct AuthorizationUrlData {
    pub state: String,
    pub code_verifier: String,
    pub scopes: Option<Vec<String>>,
    pub redirect_uri: String,
    pub display: Option<String>,
    pub login_hint: Option<String>,
}

/// Data passed to `validate_authorization_code`.
#[derive(Debug, Clone)]
pub struct CodeValidationData {
    pub code: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub device_id: Option<String>,
}

/// Result of `get_user_info`.
#[derive(Debug, Clone)]
pub struct UserInfoResult {
    pub user: OAuth2UserInfo,
    /// Provider-specific raw data (e.g., full Google profile).
    pub data: serde_json::Value,
}

/// Authentication method for token requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthenticationMethod {
    /// Send credentials as HTTP Basic auth header.
    Basic,
    /// Send credentials in POST body (default).
    #[default]
    Post,
}

/// The core OAuthProvider trait.
///
/// Every social provider (Google, GitHub, Apple, Discord, etc.) implements this.
/// Maps to `OAuthProvider` interface in TypeScript.
#[async_trait]
pub trait OAuthProvider: Send + Sync + std::fmt::Debug {
    /// Unique provider identifier (e.g., "google", "github", "apple").
    fn id(&self) -> &str;

    /// Human-readable provider name.
    fn name(&self) -> &str;

    /// Provider options (client ID, secret, scopes, etc.).
    fn options(&self) -> &ProviderOptions;

    /// Authorization endpoint URL.
    fn authorization_endpoint(&self) -> &str;

    /// Token endpoint URL.
    fn token_endpoint(&self) -> &str;

    /// Authentication method for token requests.
    fn authentication_method(&self) -> AuthenticationMethod {
        AuthenticationMethod::Post
    }

    /// Default scopes for this provider.
    fn default_scopes(&self) -> Vec<String> {
        Vec::new()
    }

    /// Character used to join scopes (default: " ").
    fn scope_joiner(&self) -> &str {
        " "
    }

    /// Additional query parameters for the authorization URL.
    fn additional_auth_params(&self) -> HashMap<String, String> {
        HashMap::new()
    }

    /// Build the authorization URL.
    /// Default implementation uses the standard OAuth2 flow.
    async fn create_authorization_url(
        &self,
        data: &AuthorizationUrlData,
    ) -> Result<url::Url, better_auth_core::error::BetterAuthError>;

    /// Exchange an authorization code for tokens.
    async fn validate_authorization_code(
        &self,
        data: &CodeValidationData,
    ) -> Result<Option<OAuth2Tokens>, better_auth_core::error::BetterAuthError>;

    /// Fetch user info from the provider using the tokens.
    async fn get_user_info(
        &self,
        tokens: &OAuth2Tokens,
    ) -> Result<Option<UserInfoResult>, better_auth_core::error::BetterAuthError>;

    /// Refresh an access token (optional — not all providers support this).
    async fn refresh_access_token(
        &self,
        _refresh_token: &str,
    ) -> Result<OAuth2Tokens, better_auth_core::error::BetterAuthError> {
        Err(better_auth_core::error::BetterAuthError::Other(
            format!("Provider '{}' does not support token refresh", self.id()),
        ))
    }

    /// Revoke a token (optional).
    async fn revoke_token(
        &self,
        _token: &str,
    ) -> Result<(), better_auth_core::error::BetterAuthError> {
        Err(better_auth_core::error::BetterAuthError::Other(
            format!("Provider '{}' does not support token revocation", self.id()),
        ))
    }

    /// Verify an ID token (optional — used by Google, Apple).
    async fn verify_id_token(
        &self,
        _token: &str,
        _nonce: Option<&str>,
    ) -> Result<bool, better_auth_core::error::BetterAuthError> {
        Ok(false)
    }

    /// Whether this provider disables implicit sign-up.
    fn disable_implicit_sign_up(&self) -> bool {
        self.options().disable_implicit_sign_up
    }

    /// Whether this provider disables sign-up entirely.
    fn disable_sign_up(&self) -> bool {
        self.options().disable_sign_up
    }
}
