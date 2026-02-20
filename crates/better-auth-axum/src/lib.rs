#![doc = include_str!("../README.md")]

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    middleware as axum_mw,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};

use better_auth::context::AuthContext;
use better_auth::cookies::ResponseCookies;
use better_auth::internal_adapter::{AdapterError, InternalAdapter};
use better_auth::middleware::MiddlewareError;
use better_auth::routes;
use better_auth::routes::session::{GetSessionOptions, SessionResponse};
use better_auth_core::options::BetterAuthOptions;

// ─── Auth Response with Cookies ─────────────────────────────────

/// An Axum response that includes both a JSON body and Set-Cookie headers.
///
/// Route handlers that need to set cookies return this type.
/// Usage: `AuthResponse::new(Json(data), cookies)` or `AuthResponse::json(data)`
pub struct AuthResponse {
    body: Response,
    cookies: ResponseCookies,
}

impl AuthResponse {
    /// Create from an existing response and cookies.
    pub fn new(body: impl IntoResponse, cookies: ResponseCookies) -> Self {
        Self {
            body: body.into_response(),
            cookies,
        }
    }

    /// Create a JSON response with cookies.
    pub fn json<T: serde::Serialize>(data: T, cookies: ResponseCookies) -> Self {
        Self {
            body: Json(data).into_response(),
            cookies,
        }
    }

    /// Create a JSON response without cookies.
    pub fn json_only<T: serde::Serialize>(data: T) -> Self {
        Self {
            body: Json(data).into_response(),
            cookies: ResponseCookies::new(),
        }
    }
}

impl IntoResponse for AuthResponse {
    fn into_response(self) -> Response {
        let (mut parts, body) = self.body.into_parts();

        // Add all Set-Cookie headers
        for (_, header_value) in self.cookies.into_headers() {
            if let Ok(val) = axum::http::HeaderValue::from_str(&header_value) {
                parts.headers.append(axum::http::header::SET_COOKIE, val);
            }
        }

        Response::from_parts(parts, body)
    }
}

// ─── Error Handling ──────────────────────────────────────────────

/// Convert `AdapterError` into an Axum HTTP response.
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": {
                "message": self.message,
                "code": self.code,
                "status": self.status.as_u16(),
            }
        });

        (self.status, Json(body)).into_response()
    }
}

/// API error with HTTP status code, error code, and human-readable message.
struct ApiError {
    status: StatusCode,
    code: String,
    message: String,
}

impl From<AdapterError> for ApiError {
    fn from(e: AdapterError) -> Self {
        let (status, code, message) = match &e {
            AdapterError::NotFound => (StatusCode::NOT_FOUND, "NOT_FOUND", "Not found".to_string()),
            AdapterError::Duplicate(msg) => (StatusCode::CONFLICT, "DUPLICATE", msg.clone()),
            AdapterError::Serialization(msg) => (StatusCode::INTERNAL_SERVER_ERROR, "SERIALIZATION_ERROR", msg.clone()),
            AdapterError::Database(msg) => {
                if msg.contains("Invalid email or password") {
                    (StatusCode::UNAUTHORIZED, "INVALID_CREDENTIALS", msg.clone())
                } else if msg.contains("Authentication required") || msg.contains("Invalid session") {
                    (StatusCode::UNAUTHORIZED, "UNAUTHORIZED", msg.clone())
                } else if msg.contains("already exists") {
                    (StatusCode::CONFLICT, "DUPLICATE", msg.clone())
                } else if msg.contains("expired") || msg.contains("Invalid") {
                    (StatusCode::BAD_REQUEST, "BAD_REQUEST", msg.clone())
                } else {
                    (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR", msg.clone())
                }
            }
        };
        ApiError { status, code: code.to_string(), message }
    }
}

impl From<routes::sign_up::SignUpHandlerError> for ApiError {
    fn from(e: routes::sign_up::SignUpHandlerError) -> Self {
        use routes::sign_up::SignUpHandlerError;
        match e {
            SignUpHandlerError::BadRequest(err) => ApiError {
                status: StatusCode::BAD_REQUEST,
                code: format!("{err:?}"),
                message: err.to_string(),
            },
            SignUpHandlerError::UnprocessableEntity(err) => ApiError {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                code: format!("{err:?}"),
                message: err.to_string(),
            },
            SignUpHandlerError::Internal(msg) => ApiError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "INTERNAL_SERVER_ERROR".to_string(),
                message: msg,
            },
            SignUpHandlerError::Adapter(adapter_err) => ApiError::from(adapter_err),
        }
    }
}

impl From<routes::sign_in::SignInHandlerError> for ApiError {
    fn from(e: routes::sign_in::SignInHandlerError) -> Self {
        use routes::sign_in::SignInHandlerError;
        match e {
            SignInHandlerError::BadRequest(err) => ApiError {
                status: StatusCode::BAD_REQUEST,
                code: format!("{err:?}"),
                message: err.to_string(),
            },
            SignInHandlerError::Unauthorized(err) => ApiError {
                status: StatusCode::UNAUTHORIZED,
                code: format!("{err:?}"),
                message: err.to_string(),
            },
            SignInHandlerError::Forbidden(err) => ApiError {
                status: StatusCode::FORBIDDEN,
                code: format!("{err:?}"),
                message: err.to_string(),
            },
            SignInHandlerError::Internal(msg) => ApiError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "INTERNAL_SERVER_ERROR".to_string(),
                message: msg,
            },
            SignInHandlerError::Adapter(adapter_err) => ApiError::from(adapter_err),
        }
    }
}

impl From<routes::update_user::UpdateUserError> for ApiError {
    fn from(e: routes::update_user::UpdateUserError) -> Self {
        use routes::update_user::UpdateUserError;
        match e {
            UpdateUserError::Api(api_err) => ApiError {
                status: StatusCode::BAD_REQUEST,
                code: "UPDATE_USER_ERROR".to_string(),
                message: api_err.to_string(),
            },
            UpdateUserError::Database(adapter_err) => ApiError::from(adapter_err),
        }
    }
}

impl From<routes::account::UnlinkError> for ApiError {
    fn from(e: routes::account::UnlinkError) -> Self {
        use routes::account::UnlinkError;
        match e {
            UnlinkError::LastAccount => ApiError {
                status: StatusCode::BAD_REQUEST,
                code: "LAST_ACCOUNT".to_string(),
                message: e.to_string(),
            },
            UnlinkError::AccountNotFound => ApiError {
                status: StatusCode::NOT_FOUND,
                code: "ACCOUNT_NOT_FOUND".to_string(),
                message: e.to_string(),
            },
            UnlinkError::Database(adapter_err) => ApiError::from(adapter_err),
        }
    }
}

// ─── Cookie / Token Extraction ───────────────────────────────────

/// Extract the session token using a specific cookie prefix.
fn extract_session_token_with_prefix(headers: &axum::http::HeaderMap, prefix: &str) -> Option<String> {
    // Try Authorization: Bearer <token>
    if let Some(auth) = headers.get("authorization") {
        if let Ok(val) = auth.to_str() {
            if let Some(token) = val.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }

    // Try cookie with configurable prefix
    if let Some(cookie_header) = headers.get("cookie") {
        if let Ok(cookies) = cookie_header.to_str() {
            let cookie_name = format!("{}.session_token", prefix);
            let secure_cookie_name = format!("__Secure-{}", cookie_name);

            for cookie in cookies.split(';') {
                let cookie = cookie.trim();
                if let Some((name, value)) = cookie.split_once('=') {
                    let name = name.trim();
                    if name == secure_cookie_name || name == cookie_name {
                        return Some(value.to_string());
                    }
                }
            }
        }
    }

    None
}

/// Extract session token from headers using the configured prefix from AuthContext.
fn extract_session_token_ctx(headers: &axum::http::HeaderMap, ctx: &AuthContext) -> Option<String> {
    let prefix = ctx.options.advanced.cookie_prefix.as_deref().unwrap_or("better-auth");
    extract_session_token_with_prefix(headers, prefix)
}

// ─── BetterAuth Builder ─────────────────────────────────────────

/// The main entry point for integrating Better Auth with Axum.
///
/// # Example
///
/// ```rust,ignore
/// use better_auth_axum::BetterAuth;
/// use better_auth_core::options::BetterAuthOptions;
///
/// let options = BetterAuthOptions::new("my-secret-key-at-least-32-chars!");
/// let adapter = /* your InternalAdapter implementation */;
/// let auth = BetterAuth::new(options, adapter);
///
/// let app = axum::Router::new()
///     .merge(auth.router());
/// ```
pub struct BetterAuth {
    ctx: Arc<AuthContext>,
}

impl BetterAuth {
    /// Create a new BetterAuth instance from options and a database adapter.
    pub fn new(options: BetterAuthOptions, adapter: Arc<dyn InternalAdapter>) -> Self {
        let ctx = AuthContext::new(options, adapter);
        Self { ctx }
    }

    /// Create from an existing `AuthContext`.
    pub fn from_context(ctx: Arc<AuthContext>) -> Self {
        Self { ctx }
    }

    /// Get a reference to the auth context.
    pub fn context(&self) -> &Arc<AuthContext> {
        &self.ctx
    }

    /// Build the Axum `Router` with all auth endpoints.
    ///
    /// The router is nested under the configured `base_path` (default: `/api/auth`).
    pub fn router(&self) -> Router {
        let base_path = self.ctx.base_path.clone();
        let auth_routes = self.auth_routes();

        Router::new().nest(&base_path, auth_routes)
    }

    /// Build the Axum `Router` with CORS enabled.
    ///
    /// Allows all origins by default. For production, configure CORS manually.
    pub fn router_with_cors(&self) -> Router {
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);

        self.router().layer(cors)
    }

    /// Build the internal auth routes (not nested under base_path).
    fn auth_routes(&self) -> Router {
        let core_routes = Router::new()
            // Health
            .route("/ok", get(handle_ok))
            // Auth
            .route("/sign-up/email", post(handle_sign_up))
            .route("/sign-in/email", post(handle_sign_in))
            .route("/sign-in/social", post(handle_social_sign_in))
            .route("/sign-out", post(handle_sign_out))
            .route("/session", get(handle_get_session))
            .route("/list-sessions", get(handle_axum_list_sessions))
            .route("/revoke-session", post(handle_axum_revoke_session))
            .route("/revoke-sessions", post(handle_axum_revoke_sessions))
            .route("/revoke-other-sessions", post(handle_axum_revoke_other_sessions))
            // OAuth (supports both GET for normal callback and POST for form-encoded redirect)
            .route("/callback/{provider}", get(handle_callback).post(handle_callback_post))
            // User
            .route("/update-user", post(handle_update_user))
            .route("/delete-user", post(handle_delete_user))
            // Password
            .route("/change-password", post(handle_change_password))
            .route("/set-password", post(handle_set_password))
            .route("/request-password-reset", post(handle_forgot_password))
            .route("/reset-password", post(handle_reset_password))
            .route("/reset-password/{token}", get(handle_reset_password_callback))
            .route("/verify-password", post(handle_verify_password))
            // Account
            .route("/list-accounts", get(handle_list_accounts))
            .route("/unlink-account", post(handle_unlink_account))
            .route("/link-social", post(handle_link_social))
            .route("/get-access-token", post(handle_get_access_token))
            .route("/refresh-token", post(handle_refresh_token))
            .route("/account-info", get(handle_account_info))
            // Email verification
            .route("/verify-email", get(handle_verify_email))
            .route("/send-verification-email", post(handle_send_verification))
            // User — additional
            .route("/change-email", post(handle_change_email))
            .route("/delete-user/callback", get(handle_delete_user_callback))
            // Error page
            .route("/error", get(handle_error_page));

        core_routes
            // /get-session is an alias for /session (TS client compatibility)
            .route("/get-session", get(handle_get_session))
            // Plugin endpoint dispatch — catch-all for any path not handled above
            .fallback(handle_plugin_dispatch)
            .layer(axum_mw::from_fn_with_state(self.ctx.clone(), origin_check_middleware))
            .layer(axum_mw::from_fn_with_state(self.ctx.clone(), rate_limit_middleware))
            .with_state(self.ctx.clone())
    }
}

// ─── Route Handlers ─────────────────────────────────────────────

/// Create a 302 Found redirect response (matches TS `c.redirect()` behavior).
fn redirect_found(url: &str) -> Response {
    (StatusCode::FOUND, [(header::LOCATION, url.to_string())]).into_response()
}

async fn handle_ok() -> impl IntoResponse {
    Json(routes::ok::handle_ok())
}

async fn handle_sign_up(
    State(ctx): State<Arc<AuthContext>>,
    Json(body): Json<routes::sign_up::SignUpRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let result = routes::sign_up::handle_sign_up(ctx, body).await?;
    Ok((StatusCode::CREATED, Json(result)))
}

async fn handle_sign_in(
    State(ctx): State<Arc<AuthContext>>,
    Json(body): Json<routes::sign_in::SignInRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let result = routes::sign_in::handle_sign_in(ctx, body).await?;
    Ok(Json(result))
}

async fn handle_social_sign_in(
    State(ctx): State<Arc<AuthContext>>,
    Json(body): Json<routes::sign_in::SocialSignInRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let result = routes::sign_in::handle_social_sign_in(ctx, body).await?;

    // Always return JSON — the TS client SDK does the redirect client-side
    Ok(Json(result).into_response())
}

async fn handle_sign_out(
    State(ctx): State<Arc<AuthContext>>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let token = extract_session_token_ctx(&headers, &ctx);

    let result = routes::sign_out::handle_sign_out(ctx.clone(), token.as_deref()).await?;

    // Build cookie deletion headers matching TS behavior
    let mut response_cookies = ResponseCookies::new();
    for cookie_name in &result.cookies_to_delete {
        let attrs = better_auth::cookies::CookieAttributes {
            value: String::new(),
            max_age: Some(0),
            expires: None,
            domain: None,
            path: Some("/".to_string()),
            secure: false,
            http_only: true,
            same_site: Some(better_auth::cookies::SameSite::Lax),
        };
        response_cookies.set_cookie(cookie_name, &attrs);
    }

    Ok(AuthResponse::json(result.response, response_cookies))
}

/// Helper: get session, validate, and return the response.
/// Used by many handlers that need session + user info.
async fn require_session(
    ctx: Arc<AuthContext>,
    token: &str,
) -> Result<SessionResponse, ApiError> {
    let result = routes::session::handle_get_session(ctx, token, GetSessionOptions::default()).await?;
    result.response.ok_or_else(|| ApiError::from(AdapterError::Database("Invalid session".into())))
}

async fn handle_get_session(
    State(ctx): State<Arc<AuthContext>>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let token = match extract_session_token_ctx(&headers, &ctx) {
        Some(t) => t,
        None => return Ok(Json(serde_json::json!(null)).into_response()),
    };

    let result = routes::session::handle_get_session(ctx, &token, GetSessionOptions::default()).await?;
    match result.response {
        Some(session) => Ok(Json(session).into_response()),
        None => Ok(Json(serde_json::json!(null)).into_response()),
    }
}

async fn handle_callback(
    State(ctx): State<Arc<AuthContext>>,
    axum::extract::Path(_provider): axum::extract::Path<String>,
    Query(query): Query<routes::callback::CallbackQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let result = routes::callback::handle_callback(ctx, query).await?;
    Ok(redirect_found(result.url()))
}

/// OAuth callback POST handler — merges body+query and redirects to GET.
///
/// Matches TS behavior: POST on `/callback/:id` merges body params with query
/// params and redirects to the same URL as GET to ensure cookies are set.
async fn handle_callback_post(
    State(ctx): State<Arc<AuthContext>>,
    axum::extract::Path(provider): axum::extract::Path<String>,
    Query(url_query): Query<routes::callback::CallbackQuery>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // Parse body as CallbackQuery (handles both JSON and form-encoded)
    let body_query: routes::callback::CallbackQuery = if body.is_empty() {
        routes::callback::CallbackQuery {
            code: None, state: None, error: None,
            error_description: None, device_id: None, user: None,
        }
    } else {
        // Try JSON first, then manual form-encoded parsing
        serde_json::from_slice(&body)
            .unwrap_or_else(|_| {
                // Parse application/x-www-form-urlencoded manually
                let body_str = String::from_utf8_lossy(&body);
                let mut code = None;
                let mut state = None;
                let mut error = None;
                let mut error_description = None;
                let mut device_id = None;
                let mut user = None;
                for pair in body_str.split('&') {
                    if let Some((key, value)) = pair.split_once('=') {
                        let value = value.replace('+', " ");
                        match key {
                            "code" => code = Some(value),
                            "state" => state = Some(value),
                            "error" => error = Some(value),
                            "error_description" => error_description = Some(value),
                            "device_id" => device_id = Some(value),
                            "user" => user = Some(value),
                            _ => {}
                        }
                    }
                }
                routes::callback::CallbackQuery {
                    code, state, error, error_description, device_id, user,
                }
            })
    };

    let base_url = ctx.base_url.as_deref().unwrap_or("");
    let full_base = format!("{}{}", base_url, ctx.base_path);

    let result = routes::callback::handle_callback_post(
        &full_base, &provider, &body_query, &url_query,
    );
    redirect_found(result.url())
}

async fn handle_update_user(
    State(ctx): State<Arc<AuthContext>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<routes::update_user::UpdateUserRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let token = extract_session_token_ctx(&headers, &ctx)
        .ok_or_else(|| ApiError::from(AdapterError::Database("Authentication required".into())))?;

    // Get session to find user_id
    let session = require_session(ctx.clone(), &token).await?;

    let user_id = session.user["id"]
        .as_str()
        .ok_or_else(|| ApiError::from(AdapterError::Serialization("No user id".into())))?;

    let result = routes::update_user::handle_update_user(ctx, user_id, body).await?;
    Ok(Json(result))
}

async fn handle_delete_user(
    State(ctx): State<Arc<AuthContext>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<routes::update_user::DeleteUserRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let token = extract_session_token_ctx(&headers, &ctx)
        .ok_or_else(|| ApiError::from(AdapterError::Database("Authentication required".into())))?;
    let session = require_session(ctx.clone(), &token).await?;
    let user_id = session.user["id"]
        .as_str()
        .ok_or_else(|| ApiError::from(AdapterError::Serialization("No user id".into())))?;
    let result = routes::update_user::handle_delete_user(ctx, user_id, body).await?;
    Ok(Json(result))
}

async fn handle_change_password(
    State(ctx): State<Arc<AuthContext>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<routes::password::ChangePasswordRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let token = extract_session_token_ctx(&headers, &ctx)
        .ok_or_else(|| ApiError::from(AdapterError::Database("Authentication required".into())))?;

    let session = require_session(ctx.clone(), &token).await?;

    let user_id = session.user["id"]
        .as_str()
        .ok_or_else(|| ApiError::from(AdapterError::Serialization("No user id".into())))?;

    routes::password::handle_change_password(ctx, user_id, body).await?;
    Ok(StatusCode::OK)
}

async fn handle_set_password(
    State(ctx): State<Arc<AuthContext>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<routes::update_user::SetPasswordRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let token = extract_session_token_ctx(&headers, &ctx)
        .ok_or_else(|| ApiError::from(AdapterError::Database("Authentication required".into())))?;
    let session = require_session(ctx.clone(), &token).await?;
    let user_id = session.user["id"]
        .as_str()
        .ok_or_else(|| ApiError::from(AdapterError::Serialization("No user id".into())))?;
    let result = routes::update_user::handle_set_password(ctx, user_id, body).await
        .map_err(|e| ApiError::from(AdapterError::Database(e.to_string())))?;
    Ok(Json(result))
}

async fn handle_forgot_password(
    State(ctx): State<Arc<AuthContext>>,
    Json(body): Json<routes::password::ForgotPasswordRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let result = routes::password::handle_forgot_password(ctx, body).await?;
    Ok(Json(result))
}

async fn handle_reset_password(
    State(ctx): State<Arc<AuthContext>>,
    Json(body): Json<routes::password::ResetPasswordRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let result = routes::password::handle_reset_password(ctx, body).await?;
    Ok(Json(result))
}

async fn handle_reset_password_callback(
    State(ctx): State<Arc<AuthContext>>,
    axum::extract::Path(token): axum::extract::Path<String>,
    Query(query): Query<routes::password::PasswordResetCallbackQuery>,
) -> impl IntoResponse {
    let result = routes::password::handle_password_reset_callback(ctx, &token, query).await;
    match result {
        routes::password::PasswordResetCallbackResult::Redirect(url) => redirect_found(&url),
        routes::password::PasswordResetCallbackResult::ErrorRedirect(url) => redirect_found(&url),
    }
}

async fn handle_verify_password(
    State(ctx): State<Arc<AuthContext>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<routes::password::VerifyPasswordRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let token = extract_session_token_ctx(&headers, &ctx)
        .ok_or_else(|| ApiError::from(AdapterError::Database("Authentication required".into())))?;
    let session = require_session(ctx.clone(), &token).await?;
    let user_id = session.user["id"]
        .as_str()
        .ok_or_else(|| ApiError::from(AdapterError::Serialization("No user id".into())))?;
    let result = routes::password::handle_verify_password(ctx, user_id, body).await?;
    Ok(Json(result))
}

async fn handle_list_accounts(
    State(ctx): State<Arc<AuthContext>>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let token = extract_session_token_ctx(&headers, &ctx)
        .ok_or_else(|| ApiError::from(AdapterError::Database("Authentication required".into())))?;

    let session = require_session(ctx.clone(), &token).await?;

    let user_id = session.user["id"]
        .as_str()
        .ok_or_else(|| ApiError::from(AdapterError::Serialization("No user id".into())))?;

    let result = routes::account::handle_list_accounts(ctx, user_id).await?;
    Ok(Json(result))
}

async fn handle_unlink_account(
    State(ctx): State<Arc<AuthContext>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<routes::account::UnlinkAccountRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let token = extract_session_token_ctx(&headers, &ctx)
        .ok_or_else(|| ApiError::from(AdapterError::Database("Authentication required".into())))?;

    let session = require_session(ctx.clone(), &token).await?;

    let user_id = session.user["id"]
        .as_str()
        .ok_or_else(|| ApiError::from(AdapterError::Serialization("No user id".into())))?;

    let result = routes::account::handle_unlink_account(ctx, user_id, body).await?;
    Ok(Json(result))
}

async fn handle_link_social(
    State(ctx): State<Arc<AuthContext>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<routes::account::LinkSocialRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let token = extract_session_token_ctx(&headers, &ctx)
        .ok_or_else(|| ApiError::from(AdapterError::Database("Authentication required".into())))?;
    let session = require_session(ctx.clone(), &token).await?;
    let user_id = session.user["id"]
        .as_str()
        .ok_or_else(|| ApiError::from(AdapterError::Serialization("No user id".into())))?;
    let user_email = session.user["email"]
        .as_str()
        .ok_or_else(|| ApiError::from(AdapterError::Serialization("No user email".into())))?;
    let result = routes::account::handle_link_social(ctx, user_id, user_email, body).await?;
    Ok(Json(result))
}

async fn handle_verify_email(
    State(ctx): State<Arc<AuthContext>>,
    Query(query): Query<routes::email_verification::VerifyEmailQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let result = routes::email_verification::handle_verify_email(ctx, query).await?;
    Ok(Json(result))
}

async fn handle_send_verification(
    State(ctx): State<Arc<AuthContext>>,
    Json(body): Json<routes::email_verification::SendVerificationRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let result = routes::email_verification::handle_send_verification(ctx, body).await?;
    Ok(Json(result))
}

async fn handle_change_email(
    State(ctx): State<Arc<AuthContext>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<routes::update_user::ChangeEmailRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let token = extract_session_token_ctx(&headers, &ctx)
        .ok_or_else(|| ApiError::from(AdapterError::Database("Authentication required".into())))?;
    let session = require_session(ctx.clone(), &token).await?;
    let user_id = session.user["id"]
        .as_str()
        .ok_or_else(|| ApiError::from(AdapterError::Serialization("No user id".into())))?;
    let result = routes::update_user::handle_change_email(ctx, user_id, body).await
        .map_err(|e| ApiError::from(AdapterError::Database(e.to_string())))?;
    Ok(Json(result))
}

async fn handle_get_access_token(
    State(ctx): State<Arc<AuthContext>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<routes::account::GetAccessTokenRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let token = extract_session_token_ctx(&headers, &ctx)
        .ok_or_else(|| ApiError::from(AdapterError::Database("Authentication required".into())))?;
    let session = require_session(ctx.clone(), &token).await?;
    let user_id = session.user["id"]
        .as_str()
        .ok_or_else(|| ApiError::from(AdapterError::Serialization("No user id".into())))?;
    let result = routes::account::handle_get_access_token(ctx, user_id, body).await?;
    Ok(Json(result))
}

async fn handle_refresh_token(
    State(ctx): State<Arc<AuthContext>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<routes::account::RefreshTokenRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let token = extract_session_token_ctx(&headers, &ctx)
        .ok_or_else(|| ApiError::from(AdapterError::Database("Authentication required".into())))?;
    let session = require_session(ctx.clone(), &token).await?;
    let user_id = session.user["id"]
        .as_str()
        .ok_or_else(|| ApiError::from(AdapterError::Serialization("No user id".into())))?;
    let result = routes::account::handle_refresh_token(ctx, user_id, body).await
        .map_err(|e| ApiError::from(AdapterError::Database(e.to_string())))?;
    Ok(Json(result))
}

async fn handle_account_info(
    State(ctx): State<Arc<AuthContext>>,
    headers: axum::http::HeaderMap,
    Query(query): Query<routes::account::AccountInfoQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let token = extract_session_token_ctx(&headers, &ctx)
        .ok_or_else(|| ApiError::from(AdapterError::Database("Authentication required".into())))?;
    let session = require_session(ctx.clone(), &token).await?;
    let user_id = session.user["id"]
        .as_str()
        .ok_or_else(|| ApiError::from(AdapterError::Serialization("No user id".into())))?;
    let result = routes::account::handle_account_info(ctx, user_id, query).await
        .map_err(|e| ApiError::from(AdapterError::Database(e.to_string())))?;
    Ok(Json(result))
}

async fn handle_delete_user_callback(
    State(ctx): State<Arc<AuthContext>>,
    Query(query): Query<routes::update_user::DeleteUserCallbackQuery>,
) -> Result<impl IntoResponse, ApiError> {
    // For delete-user/callback, the session is optional
    let result = routes::update_user::handle_delete_user_callback(ctx, None, query).await
        .map_err(|e| ApiError::from(AdapterError::Database(e.to_string())))?;
    Ok(Json(result))
}

async fn handle_error_page(
    Query(query): Query<routes::error_page::ErrorPageQuery>,
) -> impl IntoResponse {
    let html = routes::error_page::render_error_page(&query);
    axum::response::Html(html)
}

// ─── Plugin Dispatch Handler ────────────────────────────────────

/// Generic plugin endpoint dispatch handler.
///
/// This is the fallback handler for the auth router. It catches any request
/// not matched by the explicit core routes, looks up the matching plugin
/// endpoint in the PluginRegistry, and dispatches to the plugin's handler fn.
async fn handle_plugin_dispatch(
    State(ctx): State<Arc<AuthContext>>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    use better_auth_core::plugin::{HttpMethod, PluginHandlerRequest};
    use better_auth::plugin_runtime::endpoint_router;

    // Convert Axum method to our HttpMethod
    let plugin_method = match method {
        axum::http::Method::GET => HttpMethod::Get,
        axum::http::Method::POST => HttpMethod::Post,
        axum::http::Method::PUT => HttpMethod::Put,
        axum::http::Method::DELETE => HttpMethod::Delete,
        axum::http::Method::PATCH => HttpMethod::Patch,
        _ => {
            return (StatusCode::METHOD_NOT_ALLOWED, Json(serde_json::json!({
                "error": "Method not allowed"
            }))).into_response();
        }
    };

    let path = uri.path().to_string();

    // Check if a plugin endpoint exists for this path+method
    if !endpoint_router::has_plugin_endpoint(&ctx.plugin_registry, plugin_method, &path) {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "Not found",
            "path": path,
        }))).into_response();
    }

    // Extract headers into a HashMap
    let mut header_map = std::collections::HashMap::new();
    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            header_map.insert(name.as_str().to_lowercase(), v.to_string());
        }
    }

    // Extract session token
    let session_token = extract_session_token_ctx(&headers, &ctx);

    // If endpoint requires auth, validate the session
    let session = if endpoint_router::endpoint_requires_auth(&ctx.plugin_registry, plugin_method, &path) {
        match &session_token {
            Some(token) => {
                match routes::session::handle_get_session(
                    ctx.clone(), token, GetSessionOptions::default()
                ).await {
                    Ok(result) => {
                        match result.response {
                            Some(session) => Some(serde_json::json!({
                                "user": session.user,
                                "session": session.session,
                            })),
                            None => {
                                return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
                                    "error": "Unauthorized",
                                    "code": "UNAUTHORIZED",
                                }))).into_response();
                            }
                        }
                    }
                    Err(_) => {
                        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
                            "error": "Unauthorized",
                            "code": "UNAUTHORIZED",
                        }))).into_response();
                    }
                }
            }
            None => {
                return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
                    "error": "Unauthorized",
                    "code": "UNAUTHORIZED",
                }))).into_response();
            }
        }
    } else {
        // Try to get session anyway (optional auth)
        if let Some(ref token) = session_token {
            routes::session::handle_get_session(
                ctx.clone(), token, GetSessionOptions::default()
            ).await.ok().and_then(|r| r.response).map(|s| serde_json::json!({
                "user": s.user,
                "session": s.session,
            }))
        } else {
            None
        }
    };

    // Parse body as JSON (default to empty object for GET)
    let body_json: serde_json::Value = if body.is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_slice(&body).unwrap_or(serde_json::json!({}))
    };

    // Parse query params as JSON object
    let query_json: serde_json::Value = if let Some(q) = uri.query() {
        let mut map = serde_json::Map::new();
        for pair in q.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                map.insert(key.to_string(), serde_json::Value::String(value.to_string()));
            }
        }
        serde_json::Value::Object(map)
    } else {
        serde_json::json!({})
    };

    // Build the plugin handler request
    let request = PluginHandlerRequest {
        body: body_json,
        query: query_json,
        headers: header_map,
        session_token,
        session,
    };

    // Dispatch to the plugin handler
    let ctx_any: Arc<dyn std::any::Any + Send + Sync> = ctx.clone();
    match endpoint_router::dispatch_to_handler(
        &ctx.plugin_registry, ctx_any, plugin_method, &path, request
    ).await {
        Some(response) => plugin_response_to_axum(response),
        None => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({
                "error": "Not found",
                "path": path,
            }))).into_response()
        }
    }
}

/// Convert a `PluginHandlerResponse` into an Axum `Response`.
fn plugin_response_to_axum(resp: better_auth_core::plugin::PluginHandlerResponse) -> Response {
    // Handle redirects
    if let Some(ref url) = resp.redirect {
        return redirect_found(url).into_response();
    }

    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = (status, Json(resp.body)).into_response();

    // Set additional headers
    for (key, value) in &resp.headers {
        if let (Ok(name), Ok(val)) = (
            axum::http::header::HeaderName::from_bytes(key.as_bytes()),
            axum::http::header::HeaderValue::from_str(value),
        ) {
            response.headers_mut().insert(name, val);
        }
    }

    response
}

/// Revoke session request body.
#[derive(serde::Deserialize)]
struct RevokeSessionRequest {
    token: String,
}

// ─── Session Management Handlers ────────────────────────────────

async fn handle_axum_list_sessions(
    State(ctx): State<Arc<AuthContext>>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let token = extract_session_token_ctx(&headers, &ctx)
        .ok_or_else(|| ApiError::from(AdapterError::Database("Authentication required".into())))?;
    let session = require_session(ctx.clone(), &token).await?;
    let user_id = session.user["id"]
        .as_str()
        .ok_or_else(|| ApiError::from(AdapterError::Serialization("No user id".into())))?;
    let result = routes::session::handle_list_sessions(ctx, user_id).await?;
    Ok(Json(result))
}

async fn handle_axum_revoke_session(
    State(ctx): State<Arc<AuthContext>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<RevokeSessionRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let token = extract_session_token_ctx(&headers, &ctx)
        .ok_or_else(|| ApiError::from(AdapterError::Database("Authentication required".into())))?;
    let session = require_session(ctx.clone(), &token).await?;
    let user_id = session.user["id"]
        .as_str()
        .ok_or_else(|| ApiError::from(AdapterError::Serialization("No user id".into())))?;
    let result = routes::session::handle_revoke_session(ctx, user_id, &body.token).await?;
    Ok(Json(result))
}

async fn handle_axum_revoke_sessions(
    State(ctx): State<Arc<AuthContext>>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let token = extract_session_token_ctx(&headers, &ctx)
        .ok_or_else(|| ApiError::from(AdapterError::Database("Authentication required".into())))?;
    let session = require_session(ctx.clone(), &token).await?;
    let user_id = session.user["id"]
        .as_str()
        .ok_or_else(|| ApiError::from(AdapterError::Serialization("No user id".into())))?;
    let result = routes::session::handle_revoke_sessions(ctx, user_id).await?;
    Ok(Json(result))
}

async fn handle_axum_revoke_other_sessions(
    State(ctx): State<Arc<AuthContext>>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let token = extract_session_token_ctx(&headers, &ctx)
        .ok_or_else(|| ApiError::from(AdapterError::Database("Authentication required".into())))?;
    let session = require_session(ctx.clone(), &token).await?;
    let user_id = session.user["id"]
        .as_str()
        .ok_or_else(|| ApiError::from(AdapterError::Serialization("No user id".into())))?;
    let session_token = session.session["token"]
        .as_str()
        .ok_or_else(|| ApiError::from(AdapterError::Serialization("No session token".into())))?;
    let result = routes::session::handle_revoke_other_sessions(ctx, user_id, session_token).await?;
    Ok(Json(result))
}

// ─── Request Types ──────────────────────────────────────────────

// ─── Middleware ─────────────────────────────────────────────────

/// Convert a MiddlewareError to an Axum Response.
fn middleware_error_response(err: MiddlewareError) -> Response {
    match err {
        MiddlewareError::Forbidden { code, message } => {
            let body = serde_json::json!({
                "code": code,
                "message": message,
            });
            (StatusCode::FORBIDDEN, Json(body)).into_response()
        }
        MiddlewareError::TooManyRequests {
            retry_after,
            message,
        } => {
            let body = serde_json::json!({ "message": message });
            let mut response = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
            response.headers_mut().insert(
                "X-Retry-After",
                retry_after.to_string().parse().unwrap(),
            );
            response
        }
    }
}

/// Extract client IP from request headers for rate limiting.
fn extract_ip(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("unknown").trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// Normalize the request path by stripping the base path prefix.
fn normalize_path(path: &str, base_path: &str) -> String {
    let stripped = path.strip_prefix(base_path).unwrap_or(path);
    if stripped.is_empty() {
        "/".to_string()
    } else if stripped.starts_with('/') {
        stripped.to_string()
    } else {
        format!("/{}", stripped)
    }
}

/// Axum middleware for origin/CSRF validation.
async fn origin_check_middleware(
    State(ctx): State<Arc<AuthContext>>,
    req: axum::http::Request<axum::body::Body>,
    next: axum_mw::Next,
) -> Response {
    let method = req.method().as_str().to_uppercase();
    let path = req.uri().path().to_string();

    // Build a simple header map for the origin check module
    let mut headers = std::collections::HashMap::new();
    for (name, value) in req.headers().iter() {
        if let Ok(v) = value.to_str() {
            headers.insert(
                name.as_str().to_lowercase(),
                better_auth::middleware::origin_check::HeaderValue::new(v),
            );
        }
    }

    let normalized_path = normalize_path(&path, &ctx.base_path);

    if let Err(e) = better_auth::middleware::origin_check::validate_origin(
        &method,
        &headers,
        &normalized_path,
        &ctx.trusted_origins,
        &ctx.origin_check_config,
    ) {
        return middleware_error_response(e);
    }

    next.run(req).await
}

/// Axum middleware for rate limiting.
async fn rate_limit_middleware(
    State(ctx): State<Arc<AuthContext>>,
    req: axum::http::Request<axum::body::Body>,
    next: axum_mw::Next,
) -> Response {
    let ip = extract_ip(req.headers());
    let path = req.uri().path().to_string();
    let normalized_path = normalize_path(&path, &ctx.base_path);

    if let Err(e) = ctx.rate_limiter.check(&ip, &normalized_path) {
        return middleware_error_response(e);
    }

    next.run(req).await
}

// ─── Tests ──────────────────────────────────────────────────────


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_session_from_bearer() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer my-token-123".parse().unwrap(),
        );
        assert_eq!(
            extract_session_token_with_prefix(&headers, "better-auth"),
            Some("my-token-123".to_string())
        );
    }

    #[test]
    fn test_extract_session_from_cookie() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "cookie",
            "other=value; test-prefix.session_token=abc123; another=xyz"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            extract_session_token_with_prefix(&headers, "test-prefix"),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn test_extract_session_none() {
        let headers = axum::http::HeaderMap::new();
        assert_eq!(extract_session_token_with_prefix(&headers, "better-auth"), None);
    }

    #[test]
    fn test_router_creation() {
        use better_auth::internal_adapter::InternalAdapter;

        // Minimal mock adapter for testing router creation
        struct TestAdapter;

        #[async_trait::async_trait]
        impl InternalAdapter for TestAdapter {
            async fn create_user(&self, _: serde_json::Value) -> Result<serde_json::Value, AdapterError> { Ok(serde_json::json!({})) }
            async fn find_user_by_id(&self, _: &str) -> Result<Option<serde_json::Value>, AdapterError> { Ok(None) }
            async fn find_user_by_email(&self, _: &str) -> Result<Option<serde_json::Value>, AdapterError> { Ok(None) }
            async fn update_user(&self, _: &str, _: serde_json::Value) -> Result<serde_json::Value, AdapterError> { Ok(serde_json::json!({})) }
            async fn update_user_by_email(&self, _: &str, _: serde_json::Value) -> Result<serde_json::Value, AdapterError> { Ok(serde_json::json!({})) }
            async fn update_password(&self, _: &str, _: &str) -> Result<(), AdapterError> { Ok(()) }
            async fn list_users(&self, _: Option<usize>, _: Option<usize>, _: Option<&str>, _: Option<&str>) -> Result<Vec<serde_json::Value>, AdapterError> { Ok(vec![]) }
            async fn count_total_users(&self) -> Result<u64, AdapterError> { Ok(0) }
            async fn delete_user(&self, _: &str) -> Result<(), AdapterError> { Ok(()) }
            async fn create_session(&self, _: &str, _: Option<better_auth::internal_adapter::CreateSessionOptions>, _: Option<i64>) -> Result<serde_json::Value, AdapterError> { Ok(serde_json::json!({})) }
            async fn find_session_by_token(&self, _: &str) -> Result<Option<serde_json::Value>, AdapterError> { Ok(None) }
            async fn find_session_and_user(&self, _: &str) -> Result<Option<better_auth::internal_adapter::SessionWithUser>, AdapterError> { Ok(None) }
            async fn update_session(&self, _: &str, _: serde_json::Value) -> Result<serde_json::Value, AdapterError> { Ok(serde_json::json!({})) }
            async fn delete_session(&self, _: &str) -> Result<(), AdapterError> { Ok(()) }
            async fn list_sessions_for_user(&self, _: &str) -> Result<Vec<serde_json::Value>, AdapterError> { Ok(vec![]) }
            async fn find_sessions(&self, _: &[String]) -> Result<Vec<serde_json::Value>, AdapterError> { Ok(vec![]) }
            async fn delete_sessions_for_user(&self, _: &str) -> Result<(), AdapterError> { Ok(()) }
            async fn create_account(&self, _: serde_json::Value) -> Result<serde_json::Value, AdapterError> { Ok(serde_json::json!({})) }
            async fn find_accounts_by_user_id(&self, _: &str) -> Result<Vec<serde_json::Value>, AdapterError> { Ok(vec![]) }
            async fn find_account_by_provider(&self, _: &str, _: &str) -> Result<Option<serde_json::Value>, AdapterError> { Ok(None) }
            async fn update_account(&self, _: &str, _: &str, _: serde_json::Value) -> Result<serde_json::Value, AdapterError> { Ok(serde_json::json!({})) }
            async fn delete_account(&self, _: &str, _: &str) -> Result<(), AdapterError> { Ok(()) }
            async fn delete_accounts_by_user_id(&self, _: &str) -> Result<(), AdapterError> { Ok(()) }
            async fn find_account_by_id(&self, _: &str) -> Result<Option<serde_json::Value>, AdapterError> { Ok(None) }
            async fn update_account_by_id(&self, _: &str, _: serde_json::Value) -> Result<serde_json::Value, AdapterError> { Ok(serde_json::json!({})) }
            async fn create_oauth_user(&self, _: serde_json::Value, _: serde_json::Value) -> Result<serde_json::Value, AdapterError> { Ok(serde_json::json!({})) }
            async fn find_oauth_user(&self, _: &str, _: &str, _: &str) -> Result<Option<better_auth::internal_adapter::OAuthUserResult>, AdapterError> { Ok(None) }
            async fn link_account(&self, _: serde_json::Value) -> Result<serde_json::Value, AdapterError> { Ok(serde_json::json!({})) }
            async fn create_verification(&self, _: &str, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<serde_json::Value, AdapterError> { Ok(serde_json::json!({})) }
            async fn find_verification(&self, _: &str) -> Result<Option<serde_json::Value>, AdapterError> { Ok(None) }
            async fn delete_verification(&self, _: &str) -> Result<(), AdapterError> { Ok(()) }
            async fn delete_verification_by_identifier(&self, _: &str) -> Result<(), AdapterError> { Ok(()) }
            async fn update_verification(&self, _: &str, _: serde_json::Value) -> Result<serde_json::Value, AdapterError> { Ok(serde_json::json!({})) }
            async fn delete_user_cascade(&self, _: &str) -> Result<(), AdapterError> { Ok(()) }
            async fn create(&self, _: &str, _: serde_json::Value) -> Result<serde_json::Value, AdapterError> { Ok(serde_json::json!({})) }
            async fn find_by_id(&self, _: &str, _: &str) -> Result<serde_json::Value, AdapterError> { Ok(serde_json::json!({})) }
            async fn find_one(&self, _: &str, _: serde_json::Value) -> Result<serde_json::Value, AdapterError> { Ok(serde_json::json!({})) }
            async fn find_many(&self, _: &str, _: serde_json::Value) -> Result<Vec<serde_json::Value>, AdapterError> { Ok(vec![]) }
            async fn update_by_id(&self, _: &str, _: &str, _: serde_json::Value) -> Result<serde_json::Value, AdapterError> { Ok(serde_json::json!({})) }
            async fn delete_by_id(&self, _: &str, _: &str) -> Result<(), AdapterError> { Ok(()) }
            async fn delete_many(&self, _: &str, _: serde_json::Value) -> Result<i64, AdapterError> { Ok(0) }
        }

        let options = BetterAuthOptions::new("test-secret-that-is-long-enough-32");
        let adapter: Arc<dyn InternalAdapter> = Arc::new(TestAdapter);
        let auth = BetterAuth::new(options, adapter);
        let _router = auth.router();
        // Router created successfully — endpoints are registered
    }
}
