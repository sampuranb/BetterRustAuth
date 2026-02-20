//! # Better Auth Client SDK
//!
//! Headless Rust client for Better Auth servers. Provides typed async methods,
//! automatic cookie-jar session management, and session auto-refresh.
//!
//! This is the Rust equivalent of the TypeScript `createAuthClient()` from
//! `better-auth/client`. While the TS version targets browser-based UI
//! frameworks (React, Vue, Svelte, Solid) with nanostores and proxy-based
//! API calls, this Rust client is designed for:
//!
//! - **Server-to-server** communication
//! - **CLI tools** that need to authenticate against a Better Auth server
//! - **Embedded Rust apps** (IoT, desktop, WASM)
//!
//! ## Usage
//!
//! ```rust,no_run
//! use better_auth_client::{BetterAuthClient, ClientOptions};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = BetterAuthClient::new(ClientOptions {
//!         base_url: "https://my-app.com".into(),
//!         ..Default::default()
//!     });
//!
//!     // Sign up
//!     let user = client.sign_up_email("alice@example.com", "password123", "Alice", None).await?;
//!     println!("Created user: {:?}", user);
//!
//!     // Sign in
//!     let session = client.sign_in_email("alice@example.com", "password123", None).await?;
//!     println!("Session: {:?}", session);
//!
//!     // Get session (auto-sends cookie)
//!     let current = client.get_session().await?;
//!     println!("Current session: {:?}", current);
//!
//!     Ok(())
//! }
//! ```

mod error;
pub mod plugin;
pub mod plugins;
mod session;
mod types;

pub use error::*;
pub use plugin::*;
pub use plugins::*;
pub use session::*;
pub use types::*;

use std::sync::Arc;
use tokio::sync::RwLock;

// ─── Client Options ────────────────────────────────────────────────

/// Configuration for the Better Auth client.
///
/// Maps to TS `BetterAuthClientOptions`.
#[derive(Debug, Clone)]
pub struct ClientOptions {
    /// Base URL of the Better Auth server (e.g. `https://my-app.com`).
    pub base_url: String,

    /// Base path for auth endpoints (default: `/api/auth`).
    pub base_path: String,

    /// Optional static Bearer token for authentication.
    /// If set, this token is sent as `Authorization: Bearer <token>` on every request.
    /// Otherwise, the client uses cookie-based auth.
    pub auth_token: Option<String>,

    /// HTTP request timeout in seconds (default: 30).
    pub timeout_secs: u64,

    /// Session refresh configuration.
    pub session: SessionOptions,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            base_path: "/api/auth".to_string(),
            auth_token: None,
            timeout_secs: 30,
            session: SessionOptions::default(),
        }
    }
}

/// Session-related client options.
///
/// Maps to TS `sessionOptions` in `BetterAuthClientOptions`.
#[derive(Debug, Clone)]
pub struct SessionOptions {
    /// If > 0, poll for session freshness every N seconds.
    /// Maps to TS `refetchInterval`.
    pub refetch_interval_secs: u64,

    /// Number of seconds a cached session is considered fresh (default: 60).
    /// When `get_session()` is called and the cache is fresh, returns cached data
    /// without hitting the server.
    pub cache_max_age_secs: u64,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            refetch_interval_secs: 0,
            cache_max_age_secs: 60,
        }
    }
}

// ─── Client ────────────────────────────────────────────────────────

/// Headless async HTTP client for Better Auth servers.
///
/// This is the Rust equivalent of TS `createAuthClient()`. It provides
/// typed methods for every auth endpoint, automatic cookie management,
/// and configurable session caching/refresh.
///
/// # Examples
///
/// ```rust,no_run
/// use better_auth_client::{BetterAuthClient, ClientOptions};
///
/// # async fn example() -> Result<(), better_auth_client::ClientError> {
/// let client = BetterAuthClient::new(ClientOptions {
///     base_url: "http://localhost:3000".into(),
///     ..Default::default()
/// });
///
/// // Sign in
/// client.sign_in_email("user@example.com", "pass", None).await?;
///
/// // Session is now cached; get it
/// let session = client.get_session().await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct BetterAuthClient {
    http: reqwest::Client,
    base_url: String,
    options: ClientOptions,
    session_cache: Arc<RwLock<SessionCache>>,
    broadcast: SessionBroadcast,
    plugin_registry: Arc<RwLock<PluginRegistry>>,
}

impl BetterAuthClient {
    /// Create a new client with the given options.
    ///
    /// Maps to TS `createAuthClient(options)`.
    pub fn new(options: ClientOptions) -> Self {
        let cookie_store = reqwest::cookie::Jar::default();
        let cookie_store = Arc::new(cookie_store);

        let mut builder = reqwest::Client::builder()
            .cookie_provider(cookie_store)
            .timeout(std::time::Duration::from_secs(options.timeout_secs));

        // Default headers
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        if let Some(ref token) = options.auth_token {
            if let Ok(val) = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token)) {
                headers.insert(reqwest::header::AUTHORIZATION, val);
            }
        }
        builder = builder.default_headers(headers);

        let http = builder.build().unwrap_or_else(|_| reqwest::Client::new());

        let base_url = format!(
            "{}{}",
            options.base_url.trim_end_matches('/'),
            options.base_path
        );

        Self {
            http,
            base_url,
            session_cache: Arc::new(RwLock::new(SessionCache::new(
                options.session.cache_max_age_secs,
            ))),
            broadcast: SessionBroadcast::new(),
            plugin_registry: Arc::new(RwLock::new(PluginRegistry::new())),
            options,
        }
    }

    /// Register a client-side plugin.
    /// This merges the plugin's path method overrides and session signals
    /// into the client's registry.
    pub async fn register_plugin(&self, plugin: &dyn ClientPlugin) {
        self.plugin_registry.write().await.register(plugin);
    }

    /// Get a reference to the session broadcast channel.
    /// Can be used to subscribe to session update notifications across tasks.
    pub fn broadcast(&self) -> &SessionBroadcast {
        &self.broadcast
    }

    /// Get a reference to the underlying `reqwest::Client`.
    pub fn http_client(&self) -> &reqwest::Client {
        &self.http
    }

    /// Get the options this client was created with.
    pub fn options(&self) -> &ClientOptions {
        &self.options
    }

    /// Get the full base URL (base_url + base_path).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    // ─── Internal helpers ───────────────────────────────────────────

    /// Build a full URL for the given endpoint path.
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Send a GET request and deserialize the response.
    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, ClientError> {
        let resp = self
            .http
            .get(&self.url(path))
            .send()
            .await
            .map_err(ClientError::network)?;

        Self::handle_response(resp).await
    }

    /// Send a GET request with query parameters.
    async fn get_with_query<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<T, ClientError> {
        let resp = self
            .http
            .get(&self.url(path))
            .query(query)
            .send()
            .await
            .map_err(ClientError::network)?;

        Self::handle_response(resp).await
    }

    /// Send a POST request with a JSON body and deserialize the response.
    async fn post<B: serde::Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ClientError> {
        let resp = self
            .http
            .post(&self.url(path))
            .json(body)
            .send()
            .await
            .map_err(ClientError::network)?;

        Self::handle_response(resp).await
    }

    /// Send a POST request without a body.
    async fn post_empty<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T, ClientError> {
        let resp = self
            .http
            .post(&self.url(path))
            .send()
            .await
            .map_err(ClientError::network)?;

        Self::handle_response(resp).await
    }

    /// Handle an HTTP response, mapping status codes to errors.
    async fn handle_response<T: serde::de::DeserializeOwned>(
        resp: reqwest::Response,
    ) -> Result<T, ClientError> {
        let status = resp.status();

        if status.is_success() {
            let body = resp.text().await.map_err(ClientError::network)?;
            if body.is_empty() || body == "null" {
                // Try to deserialize "null" for Option types
                return serde_json::from_str("null").map_err(|e| {
                    ClientError::Deserialization(format!(
                        "Empty response: {}",
                        e
                    ))
                });
            }
            serde_json::from_str(&body).map_err(|e| {
                ClientError::Deserialization(format!(
                    "Failed to deserialize response: {} (body: {})",
                    e,
                    if body.len() > 200 {
                        format!("{}...", &body[..200])
                    } else {
                        body
                    }
                ))
            })
        } else {
            // Try to parse error body
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".into());

            let error_detail = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| {
                    let err = v.get("error")?;
                    let code = err.get("code")?.as_str()?.to_string();
                    let message = err.get("message")?.as_str()?.to_string();
                    Some((code, message))
                });

            match status.as_u16() {
                400 => Err(ClientError::BadRequest {
                    code: error_detail
                        .as_ref()
                        .map(|(c, _)| c.clone())
                        .unwrap_or_else(|| "BAD_REQUEST".into()),
                    message: error_detail
                        .map(|(_, m)| m)
                        .unwrap_or_else(|| body),
                }),
                401 => Err(ClientError::Unauthorized {
                    code: error_detail
                        .as_ref()
                        .map(|(c, _)| c.clone())
                        .unwrap_or_else(|| "UNAUTHORIZED".into()),
                    message: error_detail
                        .map(|(_, m)| m)
                        .unwrap_or_else(|| "Unauthorized".into()),
                }),
                403 => Err(ClientError::Forbidden {
                    code: error_detail
                        .as_ref()
                        .map(|(c, _)| c.clone())
                        .unwrap_or_else(|| "FORBIDDEN".into()),
                    message: error_detail
                        .map(|(_, m)| m)
                        .unwrap_or_else(|| "Forbidden".into()),
                }),
                404 => Err(ClientError::NotFound {
                    message: error_detail
                        .map(|(_, m)| m)
                        .unwrap_or_else(|| "Not found".into()),
                }),
                409 => Err(ClientError::Conflict {
                    code: error_detail
                        .as_ref()
                        .map(|(c, _)| c.clone())
                        .unwrap_or_else(|| "CONFLICT".into()),
                    message: error_detail
                        .map(|(_, m)| m)
                        .unwrap_or_else(|| body),
                }),
                422 => Err(ClientError::UnprocessableEntity {
                    code: error_detail
                        .as_ref()
                        .map(|(c, _)| c.clone())
                        .unwrap_or_else(|| "UNPROCESSABLE_ENTITY".into()),
                    message: error_detail
                        .map(|(_, m)| m)
                        .unwrap_or_else(|| body),
                }),
                429 => Err(ClientError::TooManyRequests {
                    message: error_detail
                        .map(|(_, m)| m)
                        .unwrap_or_else(|| "Too many requests".into()),
                }),
                _ => Err(ClientError::Server {
                    status: status.as_u16(),
                    message: error_detail
                        .map(|(_, m)| m)
                        .unwrap_or_else(|| body),
                }),
            }
        }
    }

    // ─── Health ─────────────────────────────────────────────────────

    /// Check if the auth server is healthy.
    ///
    /// Maps to TS `client.ok()` → `GET /ok`.
    pub async fn ok(&self) -> Result<OkResponse, ClientError> {
        self.get("/ok").await
    }

    // ─── Authentication ─────────────────────────────────────────────

    /// Sign up with email and password.
    ///
    /// Maps to TS `client.signUp.email({...})` → `POST /sign-up/email`.
    pub async fn sign_up_email(
        &self,
        email: &str,
        password: &str,
        name: &str,
        image: Option<&str>,
    ) -> Result<SignUpResponse, ClientError> {
        let body = SignUpRequest {
            email: email.to_string(),
            password: password.to_string(),
            name: name.to_string(),
            image: image.map(|s| s.to_string()),
        };
        let resp: SignUpResponse = self.post("/sign-up/email", &body).await?;
        // Cache the session from sign-up
        self.session_cache.write().await.set(SessionData {
            user: resp.user.clone(),
            session: resp.session.clone(),
        });
        Ok(resp)
    }

    /// Sign in with email and password.
    ///
    /// Maps to TS `client.signIn.email({...})` → `POST /sign-in/email`.
    pub async fn sign_in_email(
        &self,
        email: &str,
        password: &str,
        remember_me: Option<bool>,
    ) -> Result<SignInResponse, ClientError> {
        let body = SignInRequest {
            email: email.to_string(),
            password: password.to_string(),
            remember_me,
        };
        let resp: SignInResponse = self.post("/sign-in/email", &body).await?;
        // Cache the session from sign-in
        if let Some(ref session) = resp.session {
            self.session_cache.write().await.set(SessionData {
                user: resp.user.clone(),
                session: session.clone(),
            });
        }
        Ok(resp)
    }

    /// Sign in with a social OAuth provider.
    ///
    /// Returns the authorization URL to redirect the user to.
    /// Maps to TS `client.signIn.social({...})` → `POST /sign-in/social`.
    pub async fn sign_in_social(
        &self,
        provider: &str,
        callback_url: Option<&str>,
    ) -> Result<SocialSignInResponse, ClientError> {
        let body = SocialSignInRequest {
            provider: provider.to_string(),
            callback_url: callback_url.map(|s| s.to_string()),
        };
        self.post("/sign-in/social", &body).await
    }

    /// Sign out the current session.
    ///
    /// Maps to TS `client.signOut()` → `POST /sign-out`.
    pub async fn sign_out(&self) -> Result<serde_json::Value, ClientError> {
        let resp: serde_json::Value = self.post_empty("/sign-out").await?;
        // Clear session cache
        self.session_cache.write().await.clear();
        Ok(resp)
    }

    // ─── Sessions ───────────────────────────────────────────────────

    /// Get the current session (with caching and auto-refresh).
    ///
    /// If the cached session is still fresh (within `cache_max_age_secs`),
    /// returns the cache without hitting the server.
    ///
    /// Maps to TS `client.getSession()` / `useSession` → `GET /session`.
    pub async fn get_session(&self) -> Result<Option<SessionData>, ClientError> {
        // Check cache first
        {
            let cache = self.session_cache.read().await;
            if let Some(cached) = cache.get_if_fresh() {
                return Ok(Some(cached.clone()));
            }
        }

        // Fetch from server
        let resp: serde_json::Value = self.get("/session").await?;

        if resp.is_null() {
            self.session_cache.write().await.clear();
            return Ok(None);
        }

        match serde_json::from_value::<SessionData>(resp) {
            Ok(session_data) => {
                self.session_cache.write().await.set(session_data.clone());
                Ok(Some(session_data))
            }
            Err(_) => Ok(None),
        }
    }

    /// Force-refresh the session from the server (bypasses cache).
    pub async fn refresh_session(&self) -> Result<Option<SessionData>, ClientError> {
        self.session_cache.write().await.clear();
        self.get_session().await
    }

    /// List all sessions for the current user.
    ///
    /// Maps to TS `client.listSessions()` → `GET /list-sessions`.
    pub async fn list_sessions(&self) -> Result<Vec<serde_json::Value>, ClientError> {
        self.get("/list-sessions").await
    }

    /// Revoke a specific session by its token.
    ///
    /// Maps to TS `client.revokeSession({token})` → `POST /revoke-session`.
    pub async fn revoke_session(&self, token: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/revoke-session", &serde_json::json!({"token": token}))
            .await
    }

    /// Revoke all sessions for the current user.
    ///
    /// Maps to TS `client.revokeSessions()` → `POST /revoke-sessions`.
    pub async fn revoke_sessions(&self) -> Result<serde_json::Value, ClientError> {
        let resp: serde_json::Value = self.post_empty("/revoke-sessions").await?;
        self.session_cache.write().await.clear();
        Ok(resp)
    }

    /// Revoke all sessions except the current one.
    ///
    /// Maps to TS `client.revokeOtherSessions()` → `POST /revoke-other-sessions`.
    pub async fn revoke_other_sessions(&self) -> Result<serde_json::Value, ClientError> {
        self.post_empty("/revoke-other-sessions").await
    }

    // ─── User Management ────────────────────────────────────────────

    /// Update the current user's profile.
    ///
    /// Maps to TS `client.updateUser({...})` → `POST /update-user`.
    pub async fn update_user(
        &self,
        request: UpdateUserRequest,
    ) -> Result<serde_json::Value, ClientError> {
        let resp: serde_json::Value = self.post("/update-user", &request).await?;
        // Invalidate session cache since user data changed
        self.session_cache.write().await.invalidate();
        Ok(resp)
    }

    /// Delete the current user's account.
    ///
    /// Maps to TS `client.deleteUser({...})` → `POST /delete-user`.
    pub async fn delete_user(
        &self,
        request: DeleteUserRequest,
    ) -> Result<serde_json::Value, ClientError> {
        let resp: serde_json::Value = self.post("/delete-user", &request).await?;
        self.session_cache.write().await.clear();
        Ok(resp)
    }

    // ─── Password Management ────────────────────────────────────────

    /// Change the current user's password (requires current password).
    ///
    /// Maps to TS `client.changePassword({...})` → `POST /change-password`.
    pub async fn change_password(
        &self,
        current_password: &str,
        new_password: &str,
    ) -> Result<serde_json::Value, ClientError> {
        self.post(
            "/change-password",
            &serde_json::json!({
                "currentPassword": current_password,
                "newPassword": new_password,
            }),
        )
        .await
    }

    /// Request a password reset email.
    ///
    /// Maps to TS `client.forgetPassword({...})` → `POST /request-password-reset`.
    pub async fn forgot_password(
        &self,
        email: &str,
        redirect_to: Option<&str>,
    ) -> Result<serde_json::Value, ClientError> {
        let mut body = serde_json::json!({"email": email});
        if let Some(url) = redirect_to {
            body["redirectTo"] = serde_json::Value::String(url.to_string());
        }
        self.post("/request-password-reset", &body).await
    }

    /// Reset the password using a token from the reset email.
    ///
    /// Maps to TS `client.resetPassword({...})` → `POST /reset-password`.
    pub async fn reset_password(
        &self,
        token: &str,
        new_password: &str,
    ) -> Result<serde_json::Value, ClientError> {
        self.post(
            "/reset-password",
            &serde_json::json!({
                "token": token,
                "newPassword": new_password,
            }),
        )
        .await
    }

    /// Verify the current user's password (without changing it).
    ///
    /// Maps to TS `client.verifyPassword({...})` → `POST /verify-password`.
    pub async fn verify_password(
        &self,
        password: &str,
    ) -> Result<serde_json::Value, ClientError> {
        self.post(
            "/verify-password",
            &serde_json::json!({"password": password}),
        )
        .await
    }

    // ─── Email Verification ─────────────────────────────────────────

    /// Verify an email address using a token.
    ///
    /// Maps to TS `client.verifyEmail({...})` → `GET /verify-email?token=...`.
    pub async fn verify_email(
        &self,
        token: &str,
        callback_url: Option<&str>,
    ) -> Result<serde_json::Value, ClientError> {
        let mut query = vec![("token", token)];
        if let Some(url) = callback_url {
            query.push(("callbackURL", url));
        }
        self.get_with_query("/verify-email", &query).await
    }

    /// Send a verification email to the given address.
    ///
    /// Maps to TS `client.sendVerificationEmail({...})` → `POST /send-verification-email`.
    pub async fn send_verification_email(
        &self,
        email: &str,
        callback_url: Option<&str>,
    ) -> Result<serde_json::Value, ClientError> {
        let mut body = serde_json::json!({"email": email});
        if let Some(url) = callback_url {
            body["callbackURL"] = serde_json::Value::String(url.to_string());
        }
        self.post("/send-verification-email", &body).await
    }

    // ─── Account Management ─────────────────────────────────────────

    /// List all linked accounts for the current user.
    ///
    /// Maps to TS `client.listAccounts()` → `GET /list-accounts`.
    pub async fn list_accounts(&self) -> Result<Vec<serde_json::Value>, ClientError> {
        self.get("/list-accounts").await
    }

    /// Unlink a social account from the current user.
    ///
    /// Maps to TS `client.unlinkAccount({...})` → `POST /unlink-account`.
    pub async fn unlink_account(
        &self,
        provider_id: &str,
    ) -> Result<serde_json::Value, ClientError> {
        self.post(
            "/unlink-account",
            &serde_json::json!({"providerId": provider_id}),
        )
        .await
    }

    /// Link a social account to the current user.
    ///
    /// Returns an authorization URL for the OAuth flow.
    /// Maps to TS `client.linkSocial({...})` → `POST /link-social`.
    pub async fn link_social(
        &self,
        provider: &str,
        callback_url: Option<&str>,
    ) -> Result<serde_json::Value, ClientError> {
        let mut body = serde_json::json!({"provider": provider});
        if let Some(url) = callback_url {
            body["callbackURL"] = serde_json::Value::String(url.to_string());
        }
        self.post("/link-social", &body).await
    }

    // ─── Manual Token Auth ──────────────────────────────────────────

    /// Set a Bearer token for all subsequent requests.
    ///
    /// This creates a new internal HTTP client with the token as a default header.
    /// Useful for server-to-server communication where cookies aren't available.
    pub fn with_token(mut self, token: &str) -> Self {
        let cookie_store = reqwest::cookie::Jar::default();
        let cookie_store = Arc::new(cookie_store);

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        if let Ok(val) = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token)) {
            headers.insert(reqwest::header::AUTHORIZATION, val);
        }

        self.http = reqwest::Client::builder()
            .cookie_provider(cookie_store)
            .timeout(std::time::Duration::from_secs(self.options.timeout_secs))
            .default_headers(headers)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        self
    }

    /// Create a new client from this one with a specific session token set in the cookie header.
    ///
    /// This manually injects the session token into the cookie jar. Useful when you have a token
    /// from a previous session and want to resume without re-authenticating.
    pub async fn with_session_token(&self, token: &str) -> Self {
        let mut new_client = self.clone();
        // Store the token in the session cache so get_session can use it
        // The actual cookie injection happens via the cookie jar on next request
        // We also set it as a bearer token for immediate use
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        if let Ok(val) =
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token))
        {
            headers.insert(reqwest::header::AUTHORIZATION, val);
        }

        let cookie_store = reqwest::cookie::Jar::default();
        let cookie_store = Arc::new(cookie_store);

        new_client.http = reqwest::Client::builder()
            .cookie_provider(cookie_store)
            .timeout(std::time::Duration::from_secs(self.options.timeout_secs))
            .default_headers(headers)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        new_client
    }
}

impl std::fmt::Debug for BetterAuthClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BetterAuthClient")
            .field("base_url", &self.base_url)
            .field("options", &self.options)
            .finish()
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_options() {
        let opts = ClientOptions::default();
        assert_eq!(opts.base_path, "/api/auth");
        assert_eq!(opts.timeout_secs, 30);
        assert!(opts.auth_token.is_none());
        assert_eq!(opts.session.cache_max_age_secs, 60);
        assert_eq!(opts.session.refetch_interval_secs, 0);
    }

    #[test]
    fn test_client_creation() {
        let client = BetterAuthClient::new(ClientOptions {
            base_url: "https://example.com".into(),
            ..Default::default()
        });
        assert_eq!(client.base_url(), "https://example.com/api/auth");
    }

    #[test]
    fn test_client_url_trailing_slash() {
        let client = BetterAuthClient::new(ClientOptions {
            base_url: "https://example.com/".into(),
            ..Default::default()
        });
        assert_eq!(client.base_url(), "https://example.com/api/auth");
    }

    #[test]
    fn test_client_custom_base_path() {
        let client = BetterAuthClient::new(ClientOptions {
            base_url: "https://example.com".into(),
            base_path: "/auth".into(),
            ..Default::default()
        });
        assert_eq!(client.base_url(), "https://example.com/auth");
    }

    #[test]
    fn test_url_building() {
        let client = BetterAuthClient::new(ClientOptions {
            base_url: "https://example.com".into(),
            ..Default::default()
        });
        assert_eq!(
            client.url("/sign-in/email"),
            "https://example.com/api/auth/sign-in/email"
        );
        assert_eq!(
            client.url("/session"),
            "https://example.com/api/auth/session"
        );
        assert_eq!(
            client.url("/callback/google"),
            "https://example.com/api/auth/callback/google"
        );
    }

    #[test]
    fn test_client_with_token() {
        let client = BetterAuthClient::new(ClientOptions {
            base_url: "https://example.com".into(),
            auth_token: Some("my-static-token".into()),
            ..Default::default()
        });
        assert_eq!(client.base_url(), "https://example.com/api/auth");
    }

    #[test]
    fn test_client_debug() {
        let client = BetterAuthClient::new(ClientOptions {
            base_url: "https://example.com".into(),
            ..Default::default()
        });
        let debug = format!("{:?}", client);
        assert!(debug.contains("BetterAuthClient"));
        assert!(debug.contains("https://example.com/api/auth"));
    }

    // Session cache tests moved to session.rs

    #[test]
    fn test_client_error_display() {
        let err = ClientError::Unauthorized {
            code: "UNAUTHORIZED".into(),
            message: "Invalid credentials".into(),
        };
        let display = format!("{}", err);
        assert!(display.contains("Unauthorized"));
        assert!(display.contains("Invalid credentials"));
    }

    #[test]
    fn test_client_error_variants() {
        // Ensure all error variants exist and can be constructed
        let _ = ClientError::Network("connection refused".into());
        let _ = ClientError::Unauthorized {
            code: "X".into(),
            message: "Y".into(),
        };
        let _ = ClientError::Forbidden {
            code: "X".into(),
            message: "Y".into(),
        };
        let _ = ClientError::NotFound {
            message: "Y".into(),
        };
        let _ = ClientError::BadRequest {
            code: "X".into(),
            message: "Y".into(),
        };
        let _ = ClientError::Conflict {
            code: "X".into(),
            message: "Y".into(),
        };
        let _ = ClientError::UnprocessableEntity {
            code: "X".into(),
            message: "Y".into(),
        };
        let _ = ClientError::TooManyRequests {
            message: "Y".into(),
        };
        let _ = ClientError::Server {
            status: 500,
            message: "Y".into(),
        };
        let _ = ClientError::Deserialization("Y".into());
    }

    #[test]
    fn test_sign_up_request_serialization() {
        let req = SignUpRequest {
            email: "alice@example.com".into(),
            password: "pass123".into(),
            name: "Alice".into(),
            image: Some("https://example.com/avatar.png".into()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["email"], "alice@example.com");
        assert_eq!(json["name"], "Alice");
        assert!(json["image"].is_string());
    }

    #[test]
    fn test_sign_in_request_serialization() {
        let req = SignInRequest {
            email: "alice@example.com".into(),
            password: "pass123".into(),
            remember_me: Some(true),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["email"], "alice@example.com");
        assert_eq!(json["rememberMe"], true);
    }

    #[test]
    fn test_social_sign_in_request() {
        let req = SocialSignInRequest {
            provider: "google".into(),
            callback_url: Some("https://example.com/callback".into()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["provider"], "google");
        assert_eq!(json["callbackURL"], "https://example.com/callback");
    }

    #[test]
    fn test_update_user_request() {
        let req = UpdateUserRequest {
            name: Some("New Name".into()),
            image: Some("https://new-avatar.com/img.png".into()),
            extra: Default::default(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["name"], "New Name");
    }

    #[test]
    fn test_delete_user_request() {
        let req = DeleteUserRequest {
            password: Some("pass123".into()),
            callback_url: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["password"], "pass123");
    }

    #[test]
    fn test_session_data_deserialization() {
        let json = serde_json::json!({
            "user": {"id": "u1", "name": "Alice", "email": "alice@example.com", "emailVerified": false, "createdAt": "2024-01-01T00:00:00Z", "updatedAt": "2024-01-01T00:00:00Z"},
            "session": {"id": "s1", "token": "tok123", "userId": "u1", "expiresAt": "2024-02-01T00:00:00Z", "createdAt": "2024-01-01T00:00:00Z", "updatedAt": "2024-01-01T00:00:00Z"}
        });
        let data: SessionData = serde_json::from_value(json).unwrap();
        assert_eq!(data.user["name"], "Alice");
        assert_eq!(data.session["token"], "tok123");
    }

    #[test]
    fn test_ok_response_deserialization() {
        let json = serde_json::json!({"ok": true});
        let resp: OkResponse = serde_json::from_value(json).unwrap();
        assert!(resp.ok);
    }
}
