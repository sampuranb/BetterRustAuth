// Generic OAuth plugin — configurable OAuth2 providers.
//
// Maps to: packages/better-auth/src/plugins/generic-oauth/index.ts + routes.ts
//
// Endpoints (Rust-native per-provider paths):
//   GET  /sign-in/oauth2/<providerId>   — redirect to provider authorization URL
//   GET  /callback/oauth2/<providerId>  — handle OAuth callback
//   GET  /oauth2/callback/<providerId>  — handle OAuth callback (TS path alias)
//   POST /oauth2/link/<providerId>      — programmatic account linking
//
// Endpoints (TS SDK-compatible, providerId in body):
//   POST /sign-in/oauth2               — { providerId, callbackURL?, ... }
//   POST /oauth2/link                  — { providerId, callbackURL, ... }
//
// Features:
//   - User-defined OAuth2 providers with configurable endpoints
//   - PKCE support
//   - State parameter for CSRF protection
//   - Token exchange and user info fetching
//   - Account linking
//   - Configurable scopes

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use better_auth_core::error::ErrorCode;
use better_auth_core::plugin::{BetterAuthPlugin, HttpMethod, PluginEndpoint};

// ─── Provider configuration ────────────────────────────────────────────

/// A generic OAuth2 provider configuration.
#[derive(Debug, Clone)]
pub struct GenericOAuthProvider {
    /// Unique provider identifier (e.g., "my-provider").
    pub id: String,
    /// Human-readable provider name.
    pub name: String,
    /// OAuth2 authorization endpoint.
    pub authorization_url: String,
    /// OAuth2 token endpoint.
    pub token_url: String,
    /// User info endpoint (GET with Bearer token).
    pub user_info_url: String,
    /// Client ID.
    pub client_id: String,
    /// Client secret.
    pub client_secret: String,
    /// OAuth scopes (space-separated).
    pub scopes: Vec<String>,
    /// Whether to use PKCE (default: false).
    pub pkce: bool,
    /// Redirect URI (auto-computed if not set).
    pub redirect_uri: Option<String>,
    /// Response type (default: "code").
    pub response_type: String,
    /// Token endpoint auth method (default: "client_secret_post").
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    /// Prompt parameter (optional, e.g., "consent").
    pub prompt: Option<String>,
    /// Access type parameter (optional, e.g., "offline").
    pub access_type: Option<String>,
    /// Additional custom query parameters for the authorization URL.
    pub custom_auth_params: Option<std::collections::HashMap<String, String>>,
    /// Additional custom headers for the token exchange request.
    pub custom_headers: Option<std::collections::HashMap<String, String>>,
    /// Token refresh URL (defaults to token_url if not set).
    pub token_refresh_url: Option<String>,
    /// OpenID Connect discovery URL (e.g., `https://provider.com/.well-known/openid-configuration`).
    pub discoverable_config_url: Option<String>,
    /// Whether to disable implicit sign-up (i.e., only allow linking to existing accounts).
    pub disable_implicit_sign_up: bool,
    /// Mapping of user info response fields to Better Auth user fields.
    pub user_info_mapping: Option<UserInfoMapping>,
}

/// How to authenticate at the token endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenEndpointAuthMethod {
    ClientSecretPost,
    ClientSecretBasic,
}

impl Default for TokenEndpointAuthMethod {
    fn default() -> Self {
        Self::ClientSecretPost
    }
}

impl GenericOAuthProvider {
    /// Build the authorization URL with the given state and redirect URI.
    pub fn build_authorization_url(
        &self,
        state: &str,
        redirect_uri: &str,
        code_challenge: Option<&str>,
    ) -> String {
        let scopes = self.scopes.join(" ");
        let mut url = format!(
            "{}?client_id={}&redirect_uri={}&response_type={}&scope={}&state={}",
            self.authorization_url,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(&self.response_type),
            urlencoding::encode(&scopes),
            urlencoding::encode(state),
        );
        if let Some(challenge) = code_challenge {
            url.push_str(&format!(
                "&code_challenge={}&code_challenge_method=S256",
                urlencoding::encode(challenge)
            ));
        }
        if let Some(prompt) = &self.prompt {
            url.push_str(&format!("&prompt={}", urlencoding::encode(prompt)));
        }
        if let Some(access_type) = &self.access_type {
            url.push_str(&format!("&access_type={}", urlencoding::encode(access_type)));
        }
        // Append custom authorization parameters
        if let Some(params) = &self.custom_auth_params {
            for (key, value) in params {
                url.push_str(&format!(
                    "&{}={}",
                    urlencoding::encode(key),
                    urlencoding::encode(value)
                ));
            }
        }
        url
    }

    /// Get the token refresh URL (falls back to token_url).
    pub fn refresh_url(&self) -> &str {
        self.token_refresh_url.as_deref().unwrap_or(&self.token_url)
    }

    /// Build token exchange form body parameters.
    pub fn build_token_exchange_params(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> Vec<(String, String)> {
        let mut params = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("redirect_uri".to_string(), redirect_uri.to_string()),
        ];

        if self.token_endpoint_auth_method == TokenEndpointAuthMethod::ClientSecretPost {
            params.push(("client_id".to_string(), self.client_id.clone()));
            params.push(("client_secret".to_string(), self.client_secret.clone()));
        }

        if let Some(verifier) = code_verifier {
            params.push(("code_verifier".to_string(), verifier.to_string()));
        }

        params
    }

    /// Build token refresh form body parameters.
    pub fn build_token_refresh_params(
        &self,
        refresh_token: &str,
    ) -> Vec<(String, String)> {
        let mut params = vec![
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), refresh_token.to_string()),
        ];

        if self.token_endpoint_auth_method == TokenEndpointAuthMethod::ClientSecretPost {
            params.push(("client_id".to_string(), self.client_id.clone()));
            params.push(("client_secret".to_string(), self.client_secret.clone()));
        }

        params
    }

    /// Build Authorization header value for client_secret_basic.
    pub fn basic_auth_header(&self) -> String {
        use base64::Engine;
        let creds = format!("{}:{}", self.client_id, self.client_secret);
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(creds))
    }

    /// Build the callback redirect URI from the base URL.
    pub fn build_redirect_uri(&self, base_url: &str, base_path: &str) -> String {
        if let Some(uri) = &self.redirect_uri {
            return uri.clone();
        }
        format!(
            "{}{}/callback/oauth2/{}",
            base_url.trim_end_matches('/'),
            base_path,
            self.id
        )
    }
}

// ─── PKCE helpers ──────────────────────────────────────────────────────

/// Generate a PKCE code verifier (43-128 chars, URL-safe).
pub fn generate_code_verifier() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let chars: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    (0..64)
        .map(|_| chars[rng.gen_range(0..chars.len())] as char)
        .collect()
}

/// Generate a PKCE code challenge from a verifier (S256).
pub fn generate_code_challenge(verifier: &str) -> String {
    use base64::Engine;
    use sha2::Digest;
    let hash = sha2::Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

// ─── State management ──────────────────────────────────────────────────

/// OAuth state value stored in verification.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthState {
    pub provider_id: String,
    pub callback_url: String,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub error_callback_url: Option<String>,
}

/// Generate a random state parameter.
pub fn generate_state() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        .chars()
        .collect();
    (0..32).map(|_| chars[rng.gen_range(0..chars.len())]).collect()
}

// ─── Token exchange types ──────────────────────────────────────────────

/// Token response from the OAuth provider.
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
}

/// User info field mapping — maps provider's user info response fields
/// to Better Auth's internal user fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfoMapping {
    /// Field name for user ID in the provider's response (default: "sub" or "id").
    pub id: Option<String>,
    /// Field name for email.
    pub email: Option<String>,
    /// Field name for the user's display name.
    pub name: Option<String>,
    /// Field name for the user's avatar/image URL.
    pub image: Option<String>,
    /// Field name for email_verified flag.
    pub email_verified: Option<String>,
}

impl Default for UserInfoMapping {
    fn default() -> Self {
        Self {
            id: Some("sub".to_string()),
            email: Some("email".to_string()),
            name: Some("name".to_string()),
            image: Some("picture".to_string()),
            email_verified: Some("email_verified".to_string()),
        }
    }
}

impl UserInfoMapping {
    /// Extract a user field from a JSON user-info response.
    pub fn extract_field<'a>(&self, response: &'a serde_json::Value, field: &str) -> Option<&'a serde_json::Value> {
        let key = match field {
            "id" => self.id.as_deref().unwrap_or("sub"),
            "email" => self.email.as_deref().unwrap_or("email"),
            "name" => self.name.as_deref().unwrap_or("name"),
            "image" => self.image.as_deref().unwrap_or("picture"),
            "email_verified" => self.email_verified.as_deref().unwrap_or("email_verified"),
            other => other,
        };
        response.get(key)
    }
}

/// OpenID Connect discovery document.
#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryDocument {
    pub issuer: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub scopes_supported: Option<Vec<String>>,
    pub response_types_supported: Option<Vec<String>>,
    pub grant_types_supported: Option<Vec<String>>,
    pub end_session_endpoint: Option<String>,
    pub revocation_endpoint: Option<String>,
}

/// Error types specific to generic OAuth flows.
#[derive(Debug)]
pub enum GenericOAuthError {
    /// Provider not found by ID.
    ProviderNotFound(String),
    /// Token exchange failed.
    TokenExchangeFailed(String),
    /// User info fetch failed.
    UserInfoFetchFailed(String),
    /// Invalid state parameter (CSRF mismatch).
    InvalidState,
    /// Code verifier mismatch.
    PkceVerificationFailed,
    /// Implicit sign-up disabled and user does not exist.
    ImplicitSignUpDisabled,
    /// Error from the provider's error response.
    ProviderError { error: String, description: Option<String> },
}

impl std::fmt::Display for GenericOAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProviderNotFound(id) => write!(f, "OAuth provider '{}' not found", id),
            Self::TokenExchangeFailed(msg) => write!(f, "Token exchange failed: {}", msg),
            Self::UserInfoFetchFailed(msg) => write!(f, "User info fetch failed: {}", msg),
            Self::InvalidState => write!(f, "Invalid OAuth state parameter"),
            Self::PkceVerificationFailed => write!(f, "PKCE verification failed"),
            Self::ImplicitSignUpDisabled => write!(f, "Implicit sign-up is disabled for this provider"),
            Self::ProviderError { error, description } => {
                write!(f, "Provider error: {}", error)?;
                if let Some(desc) = description {
                    write!(f, " — {}", desc)?;
                }
                Ok(())
            }
        }
    }
}

// ─── Options ────────────────────────────────────────────────────────────

/// Configuration for the generic OAuth plugin.
#[derive(Debug, Clone)]
pub struct GenericOAuthOptions {
    /// List of configured providers.
    pub providers: Vec<GenericOAuthProvider>,
}

impl Default for GenericOAuthOptions {
    fn default() -> Self {
        Self {
            providers: Vec::new(),
        }
    }
}

impl GenericOAuthOptions {
    /// Find a provider by ID.
    pub fn find_provider(&self, id: &str) -> Option<&GenericOAuthProvider> {
        self.providers.iter().find(|p| p.id == id)
    }
}

// ─── Plugin struct ─────────────────────────────────────────────────────

#[derive(Debug)]
pub struct GenericOAuthPlugin {
    options: GenericOAuthOptions,
}

impl GenericOAuthPlugin {
    pub fn new(options: GenericOAuthOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &GenericOAuthOptions {
        &self.options
    }
}

impl Default for GenericOAuthPlugin {
    fn default() -> Self {
        Self::new(GenericOAuthOptions::default())
    }
}

// ─── Plugin trait ──────────────────────────────────────────────────────

#[async_trait]
impl BetterAuthPlugin for GenericOAuthPlugin {
    fn id(&self) -> &str {
        "generic-oauth"
    }

    fn name(&self) -> &str {
        "Generic OAuth"
    }

    fn endpoints(&self) -> Vec<PluginEndpoint> {
        use std::sync::Arc;
        use better_auth_core::plugin::{PluginHandlerFn, PluginHandlerRequest, PluginHandlerResponse};

        let mut endpoints = Vec::new();
        for provider in &self.options.providers {
            let provider_id = provider.id.clone();
            let provider_config = provider.clone();
            // GET /sign-in/oauth2/{provider}
            let sign_in_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
                let provider = provider_config.clone();
                Box::pin(async move {
                    let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                        .expect("Expected AuthContext");
                    let callback_url = req.query.get("callbackURL")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    // Build OAuth authorization URL
                    let state = uuid::Uuid::new_v4().to_string();
                    let expires = chrono::Utc::now() + chrono::Duration::minutes(10);
                    let _ = ctx.adapter.create_verification(&state, &callback_url, expires).await;
                    let auth_url = format!(
                        "{}?client_id={}&redirect_uri={}&state={}&response_type=code&scope={}",
                        provider.authorization_url,
                        provider.client_id,
                        urlencoding::encode(&format!("{}/callback/oauth2/{}", ctx.base_url.as_deref().unwrap_or(""), provider.id)),
                        state,
                        urlencoding::encode(&provider.scopes.join(" ")),
                    );
                    PluginHandlerResponse::redirect_to(auth_url)
                })
            });
            endpoints.push(PluginEndpoint::with_handler(
                &format!("/sign-in/oauth2/{}", provider_id), HttpMethod::Get, false, sign_in_handler));

            let provider_id2 = provider.id.clone();
            let provider_config2 = provider.clone();
            // GET /callback/oauth2/{provider}
            let callback_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
                let provider = provider_config2.clone();
                Box::pin(async move {
                    let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                        .expect("Expected AuthContext");
                    let error_param = req.query.get("error").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let code = req.query.get("code").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let state = req.query.get("state").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let default_error_url = format!("{}/error", ctx.base_url.as_deref().unwrap_or(""));

                    // Handle error from provider
                    if !error_param.is_empty() || code.is_empty() {
                        let error = if error_param.is_empty() { "oAuth_code_missing".to_string() } else { error_param };
                        let error_desc = req.query.get("error_description").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let error_url = format!("{}?error={}&error_description={}", default_error_url, error, urlencoding::encode(&error_desc));
                        return PluginHandlerResponse { status: 302, body: serde_json::json!({}), headers: HashMap::from([("Location".into(), error_url)]), redirect: None };
                    }

                    // Verify state and get stored data
                    let state_data = match ctx.adapter.find_verification(&state).await {
                        Ok(Some(v)) => {
                            let _ = ctx.adapter.delete_verification(&state).await;
                            let val_str = v.get("value").and_then(|v| v.as_str()).unwrap_or("{}");
                            serde_json::from_str::<serde_json::Value>(val_str).unwrap_or(serde_json::json!({"callbackURL": val_str}))
                        }
                        _ => {
                            let error_url = format!("{}?error=invalid_state", default_error_url);
                            return PluginHandlerResponse { status: 302, body: serde_json::json!({}), headers: HashMap::from([("Location".into(), error_url)]), redirect: None };
                        }
                    };
                    let callback_url = state_data.get("callbackURL").and_then(|v| v.as_str()).unwrap_or("/").to_string();
                    let link_data = state_data.get("link").cloned();

                    // Exchange authorization code for tokens
                    let redirect_uri = format!("{}/callback/oauth2/{}", ctx.base_url.as_deref().unwrap_or(""), provider.id);
                    let token_body = serde_json::json!({
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": redirect_uri,
                        "client_id": provider.client_id,
                        "client_secret": provider.client_secret,
                    });

                    // Perform token exchange HTTP request
                    let http_client = reqwest::Client::new();
                    let token_resp = match http_client
                        .post(&provider.token_url)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .header("Accept", "application/json")
                        .form(&[
                            ("grant_type", "authorization_code"),
                            ("code", &code),
                            ("redirect_uri", &redirect_uri),
                            ("client_id", &provider.client_id),
                            ("client_secret", &provider.client_secret),
                        ])
                        .send()
                        .await
                    {
                        Ok(resp) => match resp.json::<serde_json::Value>().await {
                            Ok(data) => data,
                            Err(_) => {
                                let error_url = format!("{}?error=oauth_token_exchange_failed", callback_url);
                                return PluginHandlerResponse { status: 302, body: serde_json::json!({}), headers: HashMap::from([("Location".into(), error_url)]), redirect: None };
                            }
                        },
                        Err(_) => {
                            let error_url = format!("{}?error=oauth_code_verification_failed", callback_url);
                            return PluginHandlerResponse { status: 302, body: serde_json::json!({}), headers: HashMap::from([("Location".into(), error_url)]), redirect: None };
                        }
                    };

                    let access_token = token_resp.get("access_token").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    if access_token.is_empty() {
                        let error_url = format!("{}?error=oauth_token_missing", callback_url);
                        return PluginHandlerResponse { status: 302, body: serde_json::json!({}), headers: HashMap::from([("Location".into(), error_url)]), redirect: None };
                    }

                    // Fetch user info from provider
                    let user_info = match http_client
                        .get(&provider.user_info_url)
                        .header("Authorization", format!("Bearer {}", access_token))
                        .send()
                        .await
                    {
                        Ok(resp) => resp.json::<serde_json::Value>().await.unwrap_or_default(),
                        Err(_) => {
                            let error_url = format!("{}?error=user_info_fetch_failed", callback_url);
                            return PluginHandlerResponse { status: 302, body: serde_json::json!({}), headers: HashMap::from([("Location".into(), error_url)]), redirect: None };
                        }
                    };

                    let provider_user_id = user_info.get("sub")
                        .or_else(|| user_info.get("id"))
                        .and_then(|v| v.as_str().or_else(|| v.as_i64().map(|_| "")))
                        .map(|s| s.to_string())
                        .or_else(|| user_info.get("id").and_then(|v| v.as_i64()).map(|i| i.to_string()))
                        .unwrap_or_default();
                    let email = user_info.get("email").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
                    let name = user_info.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let image = user_info.get("picture")
                        .or_else(|| user_info.get("avatar_url"))
                        .or_else(|| user_info.get("image"))
                        .and_then(|v| v.as_str())
                        .map(String::from);

                    if email.is_empty() {
                        let error_url = format!("{}?error=email_is_missing", callback_url);
                        return PluginHandlerResponse { status: 302, body: serde_json::json!({}), headers: HashMap::from([("Location".into(), error_url)]), redirect: None };
                    }

                    // Handle account linking if link context exists
                    if let Some(link) = link_data {
                        let link_user_id = link.get("userId").and_then(|v| v.as_str()).unwrap_or("");
                        if link_user_id.is_empty() {
                            let error_url = format!("{}?error=link_user_id_missing", callback_url);
                            return PluginHandlerResponse { status: 302, body: serde_json::json!({}), headers: HashMap::from([("Location".into(), error_url)]), redirect: None };
                        }
                        // Create linked account record
                        let _ = ctx.adapter.create("account", serde_json::json!({
                            "id": uuid::Uuid::new_v4().to_string(),
                            "userId": link_user_id,
                            "providerId": provider.id,
                            "accountId": provider_user_id,
                            "accessToken": access_token,
                            "refreshToken": token_resp.get("refresh_token").and_then(|v| v.as_str()),
                            "createdAt": chrono::Utc::now().to_rfc3339(),
                            "updatedAt": chrono::Utc::now().to_rfc3339(),
                        })).await;
                        return PluginHandlerResponse { status: 302, body: serde_json::json!({}), headers: HashMap::from([("Location".into(), callback_url)]), redirect: None };
                    }

                    // Check if user exists by email
                    let existing_user = ctx.adapter.find_user_by_email(&email).await.ok().flatten();

                    let user_id = if let Some(ref user) = existing_user {
                        // Existing user — update/create linked account
                        let uid = user.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        // Check if account link already exists
                        let existing_accounts = ctx.adapter.find_many("account", serde_json::json!({
                            "userId": uid.clone(),
                            "providerId": provider.id.clone(),
                        })).await.unwrap_or_default();
                        if existing_accounts.is_empty() {
                            let _ = ctx.adapter.create("account", serde_json::json!({
                                "id": uuid::Uuid::new_v4().to_string(),
                                "userId": uid,
                                "providerId": provider.id,
                                "accountId": provider_user_id,
                                "accessToken": access_token,
                                "refreshToken": token_resp.get("refresh_token").and_then(|v| v.as_str()),
                                "createdAt": chrono::Utc::now().to_rfc3339(),
                                "updatedAt": chrono::Utc::now().to_rfc3339(),
                            })).await;
                        }
                        uid
                    } else {
                        // New user — check if sign up is allowed
                        if provider.disable_implicit_sign_up {
                            let error_url = format!("{}?error=signup_disabled", callback_url);
                            return PluginHandlerResponse { status: 302, body: serde_json::json!({}), headers: HashMap::from([("Location".into(), error_url)]), redirect: None };
                        }
                        let new_user_id = uuid::Uuid::new_v4().to_string();
                        let mut user_data = serde_json::json!({
                            "id": new_user_id,
                            "email": email,
                            "name": name,
                            "emailVerified": user_info.get("email_verified").and_then(|v| v.as_bool()).unwrap_or(false),
                            "createdAt": chrono::Utc::now().to_rfc3339(),
                            "updatedAt": chrono::Utc::now().to_rfc3339(),
                        });
                        if let Some(ref img) = image {
                            user_data["image"] = serde_json::Value::String(img.clone());
                        }
                        let _ = ctx.adapter.create_user(user_data).await;
                        // Create account link
                        let _ = ctx.adapter.create("account", serde_json::json!({
                            "id": uuid::Uuid::new_v4().to_string(),
                            "userId": new_user_id,
                            "providerId": provider.id,
                            "accountId": provider_user_id,
                            "accessToken": access_token,
                            "refreshToken": token_resp.get("refresh_token").and_then(|v| v.as_str()),
                            "createdAt": chrono::Utc::now().to_rfc3339(),
                            "updatedAt": chrono::Utc::now().to_rfc3339(),
                        })).await;
                        new_user_id.to_string()
                    };

                    // Create session
                    let session_token = uuid::Uuid::new_v4().to_string();
                    let session_expires = chrono::Utc::now() + chrono::Duration::days(7);
                    let _ = ctx.adapter.create_session(&user_id, None, Some(session_expires.timestamp_millis())).await;

                    // Set session cookie and redirect
                    PluginHandlerResponse {
                        status: 302,
                        body: serde_json::json!({}),
                        headers: HashMap::from([
                            ("Location".into(), callback_url),
                            ("Set-Cookie".into(), format!(
                                "better-auth.session_token={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
                                session_token, 7 * 24 * 60 * 60
                            )),
                        ]),
                        redirect: None,
                    }
                })
            });
            // Register callback at both Rust path and TS path
            endpoints.push(PluginEndpoint::with_handler(
                &format!("/callback/oauth2/{}", provider_id2), HttpMethod::Get, false, callback_handler.clone()));
            endpoints.push(PluginEndpoint::with_handler(
                &format!("/oauth2/callback/{}", provider_id2), HttpMethod::Get, false, callback_handler));

            let provider_id3 = provider.id.clone();
            let provider_config3 = provider.clone();
            // POST /oauth2/link/{provider} — Link an OAuth2 account to the current user session
            let link_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
                let provider = provider_config3.clone();
                Box::pin(async move {
                    let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                        .expect("Expected AuthContext");
                    // Require authenticated session
                    let user_id = match req.session.as_ref()
                        .and_then(|s| s.get("user"))
                        .and_then(|u| u.get("id"))
                        .and_then(|id| id.as_str())
                    {
                        Some(uid) => uid.to_string(),
                        None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Session required to link account"),
                    };
                    let user_email = req.session.as_ref()
                        .and_then(|s| s.get("user"))
                        .and_then(|u| u.get("email"))
                        .and_then(|e| e.as_str())
                        .unwrap_or("")
                        .to_string();

                    let callback_url = req.body.get("callbackURL")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    // Generate state with link context
                    let state = uuid::Uuid::new_v4().to_string();
                    let expires = chrono::Utc::now() + chrono::Duration::minutes(10);
                    let state_value = serde_json::json!({
                        "callbackURL": callback_url,
                        "link": {
                            "userId": user_id,
                            "email": user_email,
                        },
                    });
                    let _ = ctx.adapter.create_verification(&state, &state_value.to_string(), expires).await;

                    // Build authorization URL
                    let redirect_uri = if let Some(ref custom) = provider.redirect_uri {
                        custom.clone()
                    } else {
                        format!("{}/callback/oauth2/{}", ctx.base_url.as_deref().unwrap_or(""), provider.id)
                    };

                    let additional_scopes: Vec<String> = req.body.get("scopes")
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                        .unwrap_or_default();
                    let all_scopes: Vec<&str> = provider.scopes.iter().map(|s| s.as_str())
                        .chain(additional_scopes.iter().map(|s| s.as_str()))
                        .collect();

                    let mut auth_url = format!(
                        "{}?client_id={}&redirect_uri={}&state={}&response_type=code&scope={}",
                        provider.authorization_url,
                        provider.client_id,
                        urlencoding::encode(&redirect_uri),
                        state,
                        urlencoding::encode(&all_scopes.join(" ")),
                    );

                    if let Some(ref prompt) = provider.prompt {
                        auth_url.push_str(&format!("&prompt={}", prompt));
                    }
                    if let Some(ref access_type) = provider.access_type {
                        auth_url.push_str(&format!("&access_type={}", access_type));
                    }

                    PluginHandlerResponse::ok(serde_json::json!({
                        "url": auth_url,
                        "redirect": true,
                    }))
                })
            });
            endpoints.push(PluginEndpoint::with_handler(
                &format!("/oauth2/link/{}", provider_id3), HttpMethod::Post, true, link_handler));
        }

        // ─── TS SDK-compatible dispatching endpoints ───────────────────
        //
        // The TS client sends:
        //   POST /sign-in/oauth2        { providerId: "xxx", ... }
        //   POST /oauth2/link           { providerId: "xxx", callbackURL: "..." }
        //
        // These endpoints extract providerId from the JSON body and
        // delegate to the matching per-provider handler registered above.

        // POST /sign-in/oauth2 — TS client sign-in (body contains providerId)
        {
            let providers: Vec<GenericOAuthProvider> = self.options.providers.clone();
            let sign_in_dispatch: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
                let providers = providers.clone();
                Box::pin(async move {
                    let provider_id = match req.body.get("providerId").and_then(|v| v.as_str()) {
                        Some(id) => id.to_string(),
                        None => return PluginHandlerResponse::error(400, "BAD_REQUEST", "providerId is required"),
                    };
                    let provider = match providers.iter().find(|p| p.id == provider_id) {
                        Some(p) => p.clone(),
                        None => return PluginHandlerResponse::error(400, "PROVIDER_NOT_FOUND", &format!("Provider '{}' not found", provider_id)),
                    };
                    let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                        .expect("Expected AuthContext");

                    let callback_url = req.body.get("callbackURL")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let disable_redirect = req.body.get("disableRedirect")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    // Build OAuth authorization URL
                    let state = uuid::Uuid::new_v4().to_string();
                    let expires = chrono::Utc::now() + chrono::Duration::minutes(10);
                    let _ = ctx.adapter.create_verification(&state, &callback_url, expires).await;

                    // Use /oauth2/callback/{provider} (TS path)
                    let redirect_uri = if let Some(ref custom) = provider.redirect_uri {
                        custom.clone()
                    } else {
                        format!("{}{}/oauth2/callback/{}",
                            ctx.base_url.as_deref().unwrap_or(""),
                            ctx.base_path,
                            provider.id)
                    };

                    let extra_scopes: Vec<String> = req.body.get("scopes")
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                        .unwrap_or_default();
                    let all_scopes: Vec<&str> = provider.scopes.iter().map(|s| s.as_str())
                        .chain(extra_scopes.iter().map(|s| s.as_str()))
                        .collect();

                    let mut auth_url = format!(
                        "{}?client_id={}&redirect_uri={}&state={}&response_type=code&scope={}",
                        provider.authorization_url,
                        provider.client_id,
                        urlencoding::encode(&redirect_uri),
                        state,
                        urlencoding::encode(&all_scopes.join(" ")),
                    );
                    if let Some(ref prompt) = provider.prompt {
                        auth_url.push_str(&format!("&prompt={}", prompt));
                    }
                    if let Some(ref access_type) = provider.access_type {
                        auth_url.push_str(&format!("&access_type={}", access_type));
                    }

                    PluginHandlerResponse::ok(serde_json::json!({
                        "url": auth_url,
                        "redirect": !disable_redirect,
                    }))
                })
            });
            endpoints.push(PluginEndpoint::with_handler(
                "/sign-in/oauth2", HttpMethod::Post, false, sign_in_dispatch));
        }

        // POST /oauth2/link — TS client account linking (body contains providerId)
        {
            let providers: Vec<GenericOAuthProvider> = self.options.providers.clone();
            let link_dispatch: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
                let providers = providers.clone();
                Box::pin(async move {
                    let provider_id = match req.body.get("providerId").and_then(|v| v.as_str()) {
                        Some(id) => id.to_string(),
                        None => return PluginHandlerResponse::error(400, "BAD_REQUEST", "providerId is required"),
                    };
                    let provider = match providers.iter().find(|p| p.id == provider_id) {
                        Some(p) => p.clone(),
                        None => return PluginHandlerResponse::error(400, "PROVIDER_NOT_FOUND", &format!("Provider '{}' not found", provider_id)),
                    };
                    let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                        .expect("Expected AuthContext");

                    // Require authenticated session
                    let user_id = match req.session.as_ref()
                        .and_then(|s| s.get("user"))
                        .and_then(|u| u.get("id"))
                        .and_then(|id| id.as_str())
                    {
                        Some(uid) => uid.to_string(),
                        None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Session required to link account"),
                    };
                    let user_email = req.session.as_ref()
                        .and_then(|s| s.get("user"))
                        .and_then(|u| u.get("email"))
                        .and_then(|e| e.as_str())
                        .unwrap_or("")
                        .to_string();

                    let callback_url = req.body.get("callbackURL")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    // Generate state with link context
                    let state = uuid::Uuid::new_v4().to_string();
                    let expires = chrono::Utc::now() + chrono::Duration::minutes(10);
                    let state_value = serde_json::json!({
                        "callbackURL": callback_url,
                        "link": {
                            "userId": user_id,
                            "email": user_email,
                        },
                    });
                    let _ = ctx.adapter.create_verification(&state, &state_value.to_string(), expires).await;

                    let redirect_uri = if let Some(ref custom) = provider.redirect_uri {
                        custom.clone()
                    } else {
                        format!("{}{}/oauth2/callback/{}",
                            ctx.base_url.as_deref().unwrap_or(""),
                            ctx.base_path,
                            provider.id)
                    };

                    let extra_scopes: Vec<String> = req.body.get("scopes")
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                        .unwrap_or_default();
                    let all_scopes: Vec<&str> = provider.scopes.iter().map(|s| s.as_str())
                        .chain(extra_scopes.iter().map(|s| s.as_str()))
                        .collect();

                    let mut auth_url = format!(
                        "{}?client_id={}&redirect_uri={}&state={}&response_type=code&scope={}",
                        provider.authorization_url,
                        provider.client_id,
                        urlencoding::encode(&redirect_uri),
                        state,
                        urlencoding::encode(&all_scopes.join(" ")),
                    );
                    if let Some(ref prompt) = provider.prompt {
                        auth_url.push_str(&format!("&prompt={}", prompt));
                    }
                    if let Some(ref access_type) = provider.access_type {
                        auth_url.push_str(&format!("&access_type={}", access_type));
                    }

                    PluginHandlerResponse::ok(serde_json::json!({
                        "url": auth_url,
                        "redirect": true,
                    }))
                })
            });
            endpoints.push(PluginEndpoint::with_handler(
                "/oauth2/link", HttpMethod::Post, true, link_dispatch));
        }

        endpoints
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![
            ErrorCode::ProviderNotFound,
            ErrorCode::InvalidToken,
            ErrorCode::InternalServerError,
        ]
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_provider() -> GenericOAuthProvider {
        GenericOAuthProvider {
            id: "my-provider".into(),
            name: "My Provider".into(),
            authorization_url: "https://auth.example.com/authorize".into(),
            token_url: "https://auth.example.com/token".into(),
            user_info_url: "https://api.example.com/userinfo".into(),
            client_id: "client-123".into(),
            client_secret: "secret-456".into(),
            scopes: vec!["openid".into(), "email".into(), "profile".into()],
            pkce: false,
            redirect_uri: None,
            response_type: "code".into(),
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretPost,
            prompt: None,
            access_type: None,
            custom_auth_params: None,
            custom_headers: None,
            token_refresh_url: None,
            discoverable_config_url: None,
            disable_implicit_sign_up: false,
            user_info_mapping: None,
        }
    }

    #[test]
    fn test_build_authorization_url() {
        let provider = sample_provider();
        let url = provider.build_authorization_url("state123", "https://app.com/callback", None);
        assert!(url.starts_with("https://auth.example.com/authorize?"));
        assert!(url.contains("client_id=client-123"));
        assert!(url.contains("state=state123"));
        assert!(url.contains("response_type=code"));
    }

    #[test]
    fn test_build_authorization_url_with_pkce() {
        let provider = sample_provider();
        let url = provider.build_authorization_url(
            "state123",
            "https://app.com/callback",
            Some("challenge-value"),
        );
        assert!(url.contains("code_challenge=challenge-value"));
        assert!(url.contains("code_challenge_method=S256"));
    }

    #[test]
    fn test_build_redirect_uri() {
        let provider = sample_provider();
        let uri = provider.build_redirect_uri("https://app.com", "/api/auth");
        assert_eq!(uri, "https://app.com/api/auth/callback/oauth2/my-provider");
    }

    #[test]
    fn test_build_redirect_uri_custom() {
        let mut provider = sample_provider();
        provider.redirect_uri = Some("https://custom.com/cb".into());
        let uri = provider.build_redirect_uri("https://app.com", "/api/auth");
        assert_eq!(uri, "https://custom.com/cb");
    }

    #[test]
    fn test_generate_code_verifier() {
        let verifier = generate_code_verifier();
        assert_eq!(verifier.len(), 64);
    }

    #[test]
    fn test_generate_code_challenge() {
        let challenge = generate_code_challenge("test-verifier");
        // SHA-256 base64url-no-pad encoded
        assert!(!challenge.is_empty());
        assert!(!challenge.contains('='));
    }

    #[test]
    fn test_generate_state() {
        let s1 = generate_state();
        let s2 = generate_state();
        assert_eq!(s1.len(), 32);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_oauth_state_serialization() {
        let state = OAuthState {
            provider_id: "github".into(),
            callback_url: "/dashboard".into(),
            code_verifier: Some("verifier123".into()),
            error_callback_url: None,
        };
        let json = serde_json::to_string(&state).unwrap();
        let parsed: OAuthState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.provider_id, "github");
        assert_eq!(parsed.code_verifier, Some("verifier123".into()));
    }

    #[test]
    fn test_find_provider() {
        let options = GenericOAuthOptions {
            providers: vec![sample_provider()],
        };
        assert!(options.find_provider("my-provider").is_some());
        assert!(options.find_provider("nonexistent").is_none());
    }

    #[test]
    fn test_plugin_id() {
        let plugin = GenericOAuthPlugin::default();
        assert_eq!(plugin.id(), "generic-oauth");
    }

    #[test]
    fn test_plugin_endpoints() {
        let plugin = GenericOAuthPlugin::new(GenericOAuthOptions {
            providers: vec![sample_provider()],
        });
        let endpoints = plugin.endpoints();
        assert_eq!(endpoints.len(), 6); // per-provider: sign-in(GET) + callback(GET)×2 + link(POST) + TS dispatchers: sign-in(POST) + link(POST)
    }

    #[test]
    fn test_token_response_deserialization() {
        let json = serde_json::json!({
            "access_token": "at-123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "rt-456"
        });
        let resp: TokenResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.access_token, "at-123");
        assert_eq!(resp.refresh_token, Some("rt-456".into()));
    }
}
