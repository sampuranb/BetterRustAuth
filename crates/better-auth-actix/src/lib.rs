#![doc = include_str!("../README.md")]

use std::collections::HashMap;
use std::sync::Arc;

use actix_web::web::{self, Data, Json, Query};
use actix_web::{HttpRequest, HttpResponse, ResponseError};

use better_auth::context::AuthContext;
use better_auth::cookies::ResponseCookies;
use better_auth::handler::{GenericRequest, GenericResponse};
use better_auth::internal_adapter::{AdapterError, InternalAdapter};
use better_auth::middleware::MiddlewareError;
use better_auth::routes;
use better_auth::routes::session::{GetSessionOptions, SessionResponse};
use better_auth_core::options::BetterAuthOptions;

// ─── Error Type ─────────────────────────────────────────────────

/// API error that implements Actix-web's `ResponseError` trait.
#[derive(Debug)]
pub struct ApiError {
    pub status: actix_web::http::StatusCode,
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        let body = serde_json::json!({
            "error": {
                "message": self.message,
                "code": self.code,
                "status": self.status.as_u16(),
            }
        });
        HttpResponse::build(self.status).json(body)
    }

    fn status_code(&self) -> actix_web::http::StatusCode {
        self.status
    }
}

impl From<AdapterError> for ApiError {
    fn from(e: AdapterError) -> Self {
        let (status, code, message) = match &e {
            AdapterError::NotFound => (
                actix_web::http::StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "Not found".to_string(),
            ),
            AdapterError::Duplicate(msg) => (
                actix_web::http::StatusCode::CONFLICT,
                "DUPLICATE",
                msg.clone(),
            ),
            AdapterError::Serialization(msg) => (
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                "SERIALIZATION_ERROR",
                msg.clone(),
            ),
            AdapterError::Database(msg) => {
                if msg.contains("Invalid email or password") {
                    (
                        actix_web::http::StatusCode::UNAUTHORIZED,
                        "INVALID_CREDENTIALS",
                        msg.clone(),
                    )
                } else if msg.contains("already exists") {
                    (
                        actix_web::http::StatusCode::CONFLICT,
                        "DUPLICATE",
                        msg.clone(),
                    )
                } else if msg.contains("expired") || msg.contains("Invalid") {
                    (
                        actix_web::http::StatusCode::BAD_REQUEST,
                        "BAD_REQUEST",
                        msg.clone(),
                    )
                } else {
                    (
                        actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL_SERVER_ERROR",
                        msg.clone(),
                    )
                }
            }
        };
        ApiError {
            status,
            code: code.to_string(),
            message,
        }
    }
}

impl From<routes::sign_up::SignUpHandlerError> for ApiError {
    fn from(e: routes::sign_up::SignUpHandlerError) -> Self {
        use routes::sign_up::SignUpHandlerError;
        match e {
            SignUpHandlerError::BadRequest(err) => ApiError {
                status: actix_web::http::StatusCode::BAD_REQUEST,
                code: format!("{err:?}"),
                message: err.to_string(),
            },
            SignUpHandlerError::UnprocessableEntity(err) => ApiError {
                status: actix_web::http::StatusCode::UNPROCESSABLE_ENTITY,
                code: format!("{err:?}"),
                message: err.to_string(),
            },
            SignUpHandlerError::Internal(msg) => ApiError {
                status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
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
                status: actix_web::http::StatusCode::BAD_REQUEST,
                code: format!("{err:?}"),
                message: err.to_string(),
            },
            SignInHandlerError::Unauthorized(err) => ApiError {
                status: actix_web::http::StatusCode::UNAUTHORIZED,
                code: format!("{err:?}"),
                message: err.to_string(),
            },
            SignInHandlerError::Forbidden(err) => ApiError {
                status: actix_web::http::StatusCode::FORBIDDEN,
                code: format!("{err:?}"),
                message: err.to_string(),
            },
            SignInHandlerError::Internal(msg) => ApiError {
                status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
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
                status: actix_web::http::StatusCode::BAD_REQUEST,
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
                status: actix_web::http::StatusCode::BAD_REQUEST,
                code: "LAST_ACCOUNT".to_string(),
                message: e.to_string(),
            },
            UnlinkError::AccountNotFound => ApiError {
                status: actix_web::http::StatusCode::NOT_FOUND,
                code: "ACCOUNT_NOT_FOUND".to_string(),
                message: e.to_string(),
            },
            UnlinkError::Database(adapter_err) => ApiError::from(adapter_err),
        }
    }
}

// ─── Cookie / Token Extraction ──────────────────────────────────

/// Extract the session token from cookies or Authorization header.
fn extract_session_token(req: &HttpRequest, ctx: &AuthContext) -> Option<String> {
    // Try Authorization: Bearer <token>
    if let Some(auth) = req.headers().get("authorization") {
        if let Ok(val) = auth.to_str() {
            if let Some(token) = val.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }

    // Try cookie with configurable prefix
    let prefix = ctx.options.advanced.cookie_prefix.as_deref().unwrap_or("better-auth");
    let cookie_name = format!("{}.session_token", prefix);
    let secure_cookie_name = format!("__Secure-{}", cookie_name);

    if let Some(cookie_header) = req.headers().get("cookie") {
        if let Ok(cookies) = cookie_header.to_str() {
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

/// Extract client IP from request headers for rate limiting.
#[allow(dead_code)]
fn extract_ip(req: &HttpRequest) -> String {
    req.headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("unknown").trim().to_string())
        .or_else(|| {
            req.headers()
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .or_else(|| {
            req.peer_addr().map(|addr| addr.ip().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// Add Set-Cookie headers from ResponseCookies to an HttpResponse.
#[allow(dead_code)]
fn apply_cookies(
    mut builder: actix_web::HttpResponseBuilder,
    cookies: ResponseCookies,
) -> actix_web::HttpResponseBuilder {
    for (_, header_value) in cookies.into_headers() {
        builder.append_header(("Set-Cookie", header_value));
    }
    builder
}

// ─── BetterAuth Builder ─────────────────────────────────────────

/// The main entry point for integrating Better Auth with Actix-web.
///
/// # Example
///
/// ```rust,ignore
/// use better_auth_actix::BetterAuth;
/// use better_auth_core::options::BetterAuthOptions;
///
/// let options = BetterAuthOptions::new("my-secret-key-at-least-32-chars!");
/// let adapter = /* your InternalAdapter implementation */;
/// let auth = BetterAuth::new(options, adapter);
///
/// HttpServer::new(move || {
///     App::new().configure(auth.configure())
/// })
/// .bind("0.0.0.0:3000")?
/// .run()
/// .await
/// ```
#[derive(Clone)]
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

    /// Return a closure that configures Actix-web with all auth routes.
    ///
    /// Usage: `App::new().configure(auth.configure())`
    pub fn configure(&self) -> impl FnOnce(&mut web::ServiceConfig) + Clone {
        let ctx = self.ctx.clone();
        let base_path = self.ctx.base_path.clone();

        move |cfg: &mut web::ServiceConfig| {
            cfg.app_data(Data::new(ctx))
                .service(
                    web::scope(&base_path)
                        // Health
                        .route("/ok", web::get().to(handle_ok))
                        // Auth
                        .route("/sign-up/email", web::post().to(handle_sign_up))
                        .route("/sign-in/email", web::post().to(handle_sign_in))
                        .route("/sign-in/social", web::post().to(handle_social_sign_in))
                        .route("/sign-out", web::post().to(handle_sign_out))
                        .route("/session", web::get().to(handle_get_session))
                        .route("/session", web::post().to(handle_get_session))
                        .route("/get-session", web::get().to(handle_get_session))
                        .route("/get-session", web::post().to(handle_get_session))
                        .route("/list-sessions", web::get().to(handle_list_sessions))
                        .route("/revoke-session", web::post().to(handle_revoke_session))
                        .route("/revoke-sessions", web::post().to(handle_revoke_sessions))
                        .route("/revoke-other-sessions", web::post().to(handle_revoke_other_sessions))
                        // OAuth
                        .route("/callback/{provider}", web::get().to(handle_callback))
                        .route("/callback/{provider}", web::post().to(handle_callback_post))
                        // User
                        .route("/update-user", web::post().to(handle_update_user))
                        .route("/delete-user", web::post().to(handle_delete_user))
                        .route("/delete-user/callback", web::get().to(handle_delete_user_callback))
                        // Password
                        .route("/change-password", web::post().to(handle_change_password))
                        .route("/request-password-reset", web::post().to(handle_forgot_password))
                        .route("/reset-password", web::post().to(handle_reset_password))
                        .route("/reset-password/{token}", web::get().to(handle_reset_password_callback))
                        .route("/verify-password", web::post().to(handle_verify_password))
                        .route("/set-password", web::post().to(handle_set_password))
                        // Account
                        .route("/list-accounts", web::get().to(handle_list_accounts))
                        .route("/unlink-account", web::post().to(handle_unlink_account))
                        .route("/link-social", web::post().to(handle_link_social))
                        .route("/get-access-token", web::post().to(handle_get_access_token))
                        .route("/refresh-token", web::post().to(handle_refresh_token))
                        .route("/account-info", web::get().to(handle_account_info))
                        // Email verification
                        .route("/verify-email", web::get().to(handle_verify_email))
                        .route("/send-verification-email", web::post().to(handle_send_verification))
                        .route("/change-email", web::post().to(handle_change_email))
                        // Error page
                        .route("/error", web::get().to(handle_error_page))
                        // Plugin dispatch — catch-all for any path not handled above
                        .default_service(web::route().to(handle_plugin_dispatch)),
                );
        }
    }

    /// Return a handler that uses the framework-agnostic `handle_auth_request`.
    ///
    /// This is the Actix-web equivalent of the TS `toNodeHandler`.
    /// It catches ALL requests under the base path and routes them through
    /// the generic handler.
    pub fn generic_handler(&self) -> impl FnOnce(&mut web::ServiceConfig) + Clone {
        let ctx = self.ctx.clone();
        let base_path = self.ctx.base_path.clone();

        move |cfg: &mut web::ServiceConfig| {
            cfg.app_data(Data::new(ctx)).service(
                web::scope(&base_path).default_service(
                    web::route().to(handle_generic_request),
                ),
            );
        }
    }
}

// ─── Plugin Dispatch Handler ────────────────────────────────────

/// Generic plugin endpoint dispatch handler for Actix-web.
///
/// This is the default_service handler for the auth scope. It catches any
/// request not matched by the explicit core routes, looks up the matching
/// plugin endpoint in the PluginRegistry, and dispatches to the plugin's handler fn.
async fn handle_plugin_dispatch(
    ctx: Data<Arc<AuthContext>>,
    req: HttpRequest,
    body: web::Bytes,
) -> HttpResponse {
    use better_auth_core::plugin::{HttpMethod, PluginHandlerRequest};
    use better_auth::plugin_runtime::endpoint_router;

    // Convert Actix method to our HttpMethod
    let plugin_method = match req.method().as_str() {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "DELETE" => HttpMethod::Delete,
        "PATCH" => HttpMethod::Patch,
        _ => {
            return HttpResponse::MethodNotAllowed()
                .json(serde_json::json!({"error": "Method not allowed"}));
        }
    };

    // Get the path relative to the base path (Actix scope already strips it)
    let path = req.match_info().path().to_string();
    let path = if path.starts_with('/') { path } else { format!("/{}", path) };

    // Check if a plugin endpoint exists for this path+method
    if !endpoint_router::has_plugin_endpoint(&ctx.plugin_registry, plugin_method, &path) {
        return HttpResponse::NotFound()
            .json(serde_json::json!({"error": "Not found", "path": path}));
    }

    // Extract headers into a HashMap
    let mut header_map = HashMap::new();
    for (name, value) in req.headers().iter() {
        if let Ok(v) = value.to_str() {
            header_map.insert(name.as_str().to_lowercase(), v.to_string());
        }
    }

    // Extract session token
    let session_token = extract_session_token(&req, ctx.get_ref());

    // If endpoint requires auth, validate the session
    let session = if endpoint_router::endpoint_requires_auth(&ctx.plugin_registry, plugin_method, &path) {
        match &session_token {
            Some(token) => {
                match routes::session::handle_get_session(
                    (**ctx).clone(), token, GetSessionOptions::default(), None
                ).await {
                    Ok(result) => {
                        match result.response {
                            Some(session) => Some(serde_json::json!({
                                "user": session.user,
                                "session": session.session,
                            })),
                            None => {
                                return HttpResponse::Unauthorized()
                                    .json(serde_json::json!({"error": "Unauthorized", "code": "UNAUTHORIZED"}));
                            }
                        }
                    }
                    Err(_) => {
                        return HttpResponse::Unauthorized()
                            .json(serde_json::json!({"error": "Unauthorized", "code": "UNAUTHORIZED"}));
                    }
                }
            }
            None => {
                return HttpResponse::Unauthorized()
                    .json(serde_json::json!({"error": "Unauthorized", "code": "UNAUTHORIZED"}));
            }
        }
    } else {
        // Try to get session anyway (optional auth)
        if let Some(ref token) = session_token {
            routes::session::handle_get_session(
                (**ctx).clone(), token, GetSessionOptions::default(), None
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
    let query_json: serde_json::Value = if let Some(q) = req.uri().query() {
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
    let ctx_any: Arc<dyn std::any::Any + Send + Sync> = (**ctx).clone();
    match endpoint_router::dispatch_to_handler(
        &ctx.plugin_registry, ctx_any, plugin_method, &path, request
    ).await {
        Some(response) => plugin_response_to_actix(response),
        None => {
            HttpResponse::NotFound()
                .json(serde_json::json!({"error": "Not found", "path": path}))
        }
    }
}

/// Convert a `PluginHandlerResponse` into an Actix-web `HttpResponse`.
fn plugin_response_to_actix(resp: better_auth_core::plugin::PluginHandlerResponse) -> HttpResponse {
    // Handle redirects
    if let Some(ref url) = resp.redirect {
        return HttpResponse::Found()
            .insert_header(("Location", url.as_str()))
            .finish();
    }

    let status = actix_web::http::StatusCode::from_u16(resp.status)
        .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = HttpResponse::build(status);

    // Set additional headers
    for (key, value) in &resp.headers {
        builder.insert_header((key.as_str(), value.as_str()));
    }

    builder.json(resp.body)
}

// ─── Generic Handler ────────────────────────────────────────────

/// Handle any request through the framework-agnostic handler.
///
/// This converts an Actix-web request into a `GenericRequest`, runs it
/// through `handle_auth_request`, and converts the `GenericResponse` back.
async fn handle_generic_request(
    ctx: Data<Arc<AuthContext>>,
    req: HttpRequest,
    body: web::Bytes,
) -> HttpResponse {
    // Convert Actix request to GenericRequest
    let mut headers = HashMap::new();
    for (name, value) in req.headers().iter() {
        if let Ok(v) = value.to_str() {
            headers.insert(name.as_str().to_lowercase(), v.to_string());
        }
    }

    let generic_req = GenericRequest {
        method: req.method().as_str().to_string(),
        path: req.path().to_string(),
        query: req.uri().query().map(|s| s.to_string()),
        headers,
        body: if body.is_empty() {
            None
        } else {
            Some(body.to_vec())
        },
    };

    // Call the generic handler
    let generic_resp =
        better_auth::handler::handle_auth_request(ctx.get_ref().clone(), generic_req).await;

    // Convert GenericResponse to Actix HttpResponse
    generic_response_to_http(generic_resp)
}

/// Convert a `GenericResponse` to an Actix `HttpResponse`.
fn generic_response_to_http(resp: GenericResponse) -> HttpResponse {
    let status = actix_web::http::StatusCode::from_u16(resp.status)
        .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);

    let mut builder = HttpResponse::build(status);

    for (name, values) in &resp.headers {
        for value in values {
            builder.append_header((name.as_str(), value.as_str()));
        }
    }

    builder.body(resp.body)
}

// ─── Helpers ────────────────────────────────────────────────────

/// Require a session token, returning an error response if missing.
fn require_token(req: &HttpRequest, ctx: &AuthContext) -> Result<String, ApiError> {
    extract_session_token(req, ctx).ok_or_else(|| ApiError {
        status: actix_web::http::StatusCode::UNAUTHORIZED,
        code: "UNAUTHORIZED".to_string(),
        message: "Authentication required".to_string(),
    })
}

/// Require a valid session.
async fn require_session(
    ctx: &Arc<AuthContext>,
    token: &str,
) -> Result<SessionResponse, ApiError> {
    let result =
        routes::session::handle_get_session(ctx.clone(), token, GetSessionOptions::default(), None)
            .await?;
    result.response.ok_or_else(|| ApiError {
        status: actix_web::http::StatusCode::UNAUTHORIZED,
        code: "INVALID_SESSION".to_string(),
        message: "Invalid session".to_string(),
    })
}

/// Get user_id from session response.
fn user_id_from_session(session: &SessionResponse) -> Result<String, ApiError> {
    session.user["id"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| ApiError {
            status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            code: "INTERNAL_ERROR".to_string(),
            message: "No user id in session".to_string(),
        })
}

// ─── Middleware ─────────────────────────────────────────────────

/// Convert a MiddlewareError to an HttpResponse.
fn middleware_error_response(err: MiddlewareError) -> HttpResponse {
    match err {
        MiddlewareError::Forbidden { code, message } => {
            let body = serde_json::json!({
                "code": code,
                "message": message,
            });
            HttpResponse::Forbidden().json(body)
        }
        MiddlewareError::TooManyRequests {
            retry_after,
            message,
        } => {
            let body = serde_json::json!({ "message": message });
            HttpResponse::TooManyRequests()
                .append_header(("X-Retry-After", retry_after.to_string()))
                .json(body)
        }
    }
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

/// Run origin check and rate limiting middleware.
///
/// Must be called at the start of every Actix route handler in
/// the `configure()` path to match the protection provided by
/// the Axum middleware layers and the core handler pipeline.
fn run_middleware_checks(
    ctx: &AuthContext,
    req: &HttpRequest,
) -> Result<(), HttpResponse> {
    let route_path = normalize_path(req.path(), &ctx.base_path);

    // Origin check
    let origin_headers: HashMap<String, better_auth::middleware::origin_check::HeaderValue> = req
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str().ok().map(|v_str| {
                (
                    k.as_str().to_lowercase(),
                    better_auth::middleware::origin_check::HeaderValue::new(v_str),
                )
            })
        })
        .collect();

    if let Err(e) = better_auth::middleware::origin_check::validate_origin(
        req.method().as_str(),
        &origin_headers,
        &route_path,
        &ctx.trusted_origins,
        &ctx.origin_check_config,
    ) {
        return Err(middleware_error_response(e));
    }

    // Rate limiting
    let ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("127.0.0.1")
        .to_string();
    if let Err(e) = ctx.rate_limiter.check(&ip, &route_path) {
        return Err(middleware_error_response(e));
    }

    Ok(())
}

// ─── Route Handlers ─────────────────────────────────────────────

async fn handle_ok() -> HttpResponse {
    HttpResponse::Ok().json(routes::ok::handle_ok())
}

async fn handle_sign_up(
    ctx: Data<Arc<AuthContext>>,
    req: HttpRequest,
    body: Json<routes::sign_up::SignUpRequest>,
) -> Result<HttpResponse, ApiError> {
    if let Err(resp) = run_middleware_checks(ctx.get_ref(), &req) {
        return Ok(resp);
    }
    let result = routes::sign_up::handle_sign_up(ctx.get_ref().clone(), body.into_inner()).await?;
    Ok(HttpResponse::Created().json(result))
}

async fn handle_sign_in(
    ctx: Data<Arc<AuthContext>>,
    req: HttpRequest,
    body: Json<routes::sign_in::SignInRequest>,
) -> Result<HttpResponse, ApiError> {
    if let Err(resp) = run_middleware_checks(ctx.get_ref(), &req) {
        return Ok(resp);
    }
    let result = routes::sign_in::handle_sign_in(ctx.get_ref().clone(), body.into_inner()).await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn handle_social_sign_in(
    ctx: Data<Arc<AuthContext>>,
    req: HttpRequest,
    body: Json<routes::sign_in::SocialSignInRequest>,
) -> Result<HttpResponse, ApiError> {
    if let Err(resp) = run_middleware_checks(ctx.get_ref(), &req) {
        return Ok(resp);
    }
    let result =
        routes::sign_in::handle_social_sign_in(ctx.get_ref().clone(), body.into_inner()).await?;

    // Always return JSON — the TS client SDK does the redirect client-side
    Ok(HttpResponse::Ok().json(result))
}

async fn handle_sign_out(
    ctx: Data<Arc<AuthContext>>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    if let Err(resp) = run_middleware_checks(ctx.get_ref(), &req) {
        return Ok(resp);
    }
    let token = extract_session_token(&req, ctx.get_ref());
    let result =
        routes::sign_out::handle_sign_out(ctx.get_ref().clone(), token.as_deref()).await?;

    // Build cookie deletion headers matching TS behavior
    let mut builder = HttpResponse::Ok();
    for cookie_name in &result.cookies_to_delete {
        let cookie_header = format!(
            "{}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax",
            cookie_name
        );
        builder.append_header(("Set-Cookie", cookie_header));
    }
    Ok(builder.json(result.response))
}

async fn handle_get_session(
    ctx: Data<Arc<AuthContext>>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    if let Err(resp) = run_middleware_checks(ctx.get_ref(), &req) {
        return Ok(resp);
    }
    let token = match extract_session_token(&req, ctx.get_ref()) {
        Some(t) => t,
        None => return Ok(HttpResponse::Ok().json(serde_json::Value::Null)),
    };

    let cookie_hdr = req.headers().get("cookie").and_then(|v| v.to_str().ok());
    let result = routes::session::handle_get_session(
        ctx.get_ref().clone(),
        &token,
        GetSessionOptions::default(),
        cookie_hdr,
    )
    .await?;

    match result.response {
        Some(session) => Ok(HttpResponse::Ok().json(session)),
        None => Ok(HttpResponse::Ok().json(serde_json::Value::Null)),
    }
}

/// Callback query parameters for Actix-web (deserialized from query string).
#[derive(serde::Deserialize)]
struct CallbackQueryParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
    device_id: Option<String>,
    user: Option<String>,
}

async fn handle_callback(
    ctx: Data<Arc<AuthContext>>,
    query: Query<CallbackQueryParams>,
) -> Result<HttpResponse, ApiError> {
    let q = query.into_inner();
    let callback_query = routes::callback::CallbackQuery {
        code: q.code,
        state: q.state,
        error: q.error,
        error_description: q.error_description,
        device_id: q.device_id,
        user: q.user,
    };
    let result = routes::callback::handle_callback(ctx.get_ref().clone(), callback_query).await?;
    Ok(HttpResponse::Found()
        .append_header(("Location", result.url()))
        .finish())
}

async fn handle_update_user(
    ctx: Data<Arc<AuthContext>>,
    req: HttpRequest,
    body: Json<routes::update_user::UpdateUserRequest>,
) -> Result<HttpResponse, ApiError> {
    let token = require_token(&req, ctx.get_ref())?;
    let session = require_session(ctx.get_ref(), &token).await?;
    let user_id = user_id_from_session(&session)?;
    let result =
        routes::update_user::handle_update_user(ctx.get_ref().clone(), &user_id, body.into_inner())
            .await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn handle_delete_user(
    ctx: Data<Arc<AuthContext>>,
    req: HttpRequest,
    body: Json<routes::update_user::DeleteUserRequest>,
) -> Result<HttpResponse, ApiError> {
    let token = require_token(&req, ctx.get_ref())?;
    let session = require_session(ctx.get_ref(), &token).await?;
    let user_id = user_id_from_session(&session)?;
    let result =
        routes::update_user::handle_delete_user(ctx.get_ref().clone(), &user_id, body.into_inner())
            .await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn handle_change_password(
    ctx: Data<Arc<AuthContext>>,
    req: HttpRequest,
    body: Json<routes::password::ChangePasswordRequest>,
) -> Result<HttpResponse, ApiError> {
    let token = require_token(&req, ctx.get_ref())?;
    let session = require_session(ctx.get_ref(), &token).await?;
    let user_id = user_id_from_session(&session)?;
    routes::password::handle_change_password(ctx.get_ref().clone(), &user_id, body.into_inner())
        .await?;
    Ok(HttpResponse::Ok().finish())
}

async fn handle_forgot_password(
    ctx: Data<Arc<AuthContext>>,
    body: Json<routes::password::ForgotPasswordRequest>,
) -> Result<HttpResponse, ApiError> {
    let result =
        routes::password::handle_forgot_password(ctx.get_ref().clone(), body.into_inner()).await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn handle_reset_password(
    ctx: Data<Arc<AuthContext>>,
    body: Json<routes::password::ResetPasswordRequest>,
) -> Result<HttpResponse, ApiError> {
    let result =
        routes::password::handle_reset_password(ctx.get_ref().clone(), body.into_inner()).await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn handle_reset_password_callback(
    ctx: Data<Arc<AuthContext>>,
    path: web::Path<String>,
    query: Query<routes::password::PasswordResetCallbackQuery>,
) -> Result<HttpResponse, ApiError> {
    let token = path.into_inner();
    let result = routes::password::handle_password_reset_callback(
        ctx.get_ref().clone(), &token, query.into_inner()
    ).await;
    let url = match result {
        routes::password::PasswordResetCallbackResult::Redirect(u) |
        routes::password::PasswordResetCallbackResult::ErrorRedirect(u) => u,
    };
    Ok(HttpResponse::Found()
        .append_header(("Location", url))
        .finish())
}

async fn handle_verify_password(
    ctx: Data<Arc<AuthContext>>,
    req: HttpRequest,
    body: Json<routes::password::VerifyPasswordRequest>,
) -> Result<HttpResponse, ApiError> {
    let token = require_token(&req, ctx.get_ref())?;
    let session = require_session(ctx.get_ref(), &token).await?;
    let user_id = user_id_from_session(&session)?;
    let result = routes::password::handle_verify_password(
        ctx.get_ref().clone(),
        &user_id,
        body.into_inner(),
    )
    .await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn handle_list_accounts(
    ctx: Data<Arc<AuthContext>>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let token = require_token(&req, ctx.get_ref())?;
    let session = require_session(ctx.get_ref(), &token).await?;
    let user_id = user_id_from_session(&session)?;
    let result = routes::account::handle_list_accounts(ctx.get_ref().clone(), &user_id).await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn handle_unlink_account(
    ctx: Data<Arc<AuthContext>>,
    req: HttpRequest,
    body: Json<routes::account::UnlinkAccountRequest>,
) -> Result<HttpResponse, ApiError> {
    let token = require_token(&req, ctx.get_ref())?;
    let session = require_session(ctx.get_ref(), &token).await?;
    let user_id = user_id_from_session(&session)?;
    let result = routes::account::handle_unlink_account(
        ctx.get_ref().clone(),
        &user_id,
        body.into_inner(),
    )
    .await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn handle_link_social(
    ctx: Data<Arc<AuthContext>>,
    req: HttpRequest,
    body: Json<routes::account::LinkSocialRequest>,
) -> Result<HttpResponse, ApiError> {
    let token = require_token(&req, ctx.get_ref())?;
    let session = require_session(ctx.get_ref(), &token).await?;
    let user_id = user_id_from_session(&session)?;
    let user_email = session.user["email"]
        .as_str()
        .ok_or_else(|| ApiError {
            status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            code: "INTERNAL_ERROR".to_string(),
            message: "No user email in session".to_string(),
        })?;
    let result = routes::account::handle_link_social(
        ctx.get_ref().clone(),
        &user_id,
        user_email,
        body.into_inner(),
    )
    .await?;
    Ok(HttpResponse::Ok().json(result))
}

#[derive(serde::Deserialize)]
struct VerifyEmailQueryParams {
    token: String,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
}

async fn handle_verify_email(
    ctx: Data<Arc<AuthContext>>,
    query: Query<VerifyEmailQueryParams>,
) -> Result<HttpResponse, ApiError> {
    let q = query.into_inner();
    let email_query = routes::email_verification::VerifyEmailQuery {
        token: q.token,
        callback_url: q.callback_url,
    };
    let result =
        routes::email_verification::handle_verify_email(ctx.get_ref().clone(), email_query).await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn handle_send_verification(
    ctx: Data<Arc<AuthContext>>,
    body: Json<routes::email_verification::SendVerificationRequest>,
) -> Result<HttpResponse, ApiError> {
    let result = routes::email_verification::handle_send_verification(
        ctx.get_ref().clone(),
        body.into_inner(),
    )
    .await?;
    Ok(HttpResponse::Ok().json(result))
}

#[derive(serde::Deserialize)]
struct ErrorPageQueryParams {
    error: Option<String>,
    error_description: Option<String>,
}

async fn handle_error_page(query: Query<ErrorPageQueryParams>) -> HttpResponse {
    let q = query.into_inner();
    let error_query = routes::error_page::ErrorPageQuery {
        error: q.error,
        error_description: q.error_description,
    };
    let html = routes::error_page::render_error_page(&error_query);
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

// ─── Callback POST Handler ─────────────────────────────────────

async fn handle_callback_post(
    ctx: Data<Arc<AuthContext>>,
    path: web::Path<String>,
    query: Query<CallbackQueryParams>,
    body: web::Bytes,
) -> HttpResponse {
    // Parse body as CallbackQuery (handles both JSON and form-encoded)
    let body_query: routes::callback::CallbackQuery = if body.is_empty() {
        routes::callback::CallbackQuery {
            code: None, state: None, error: None,
            error_description: None, device_id: None, user: None,
        }
    } else {
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

    let q = query.into_inner();
    let url_query = routes::callback::CallbackQuery {
        code: q.code,
        state: q.state,
        error: q.error,
        error_description: q.error_description,
        device_id: q.device_id,
        user: q.user,
    };

    let provider = path.into_inner();
    let base_url = ctx.base_url.as_deref().unwrap_or("");
    let full_base = format!("{}{}", base_url, ctx.base_path);

    let result = routes::callback::handle_callback_post(
        &full_base, &provider, &body_query, &url_query,
    );
    HttpResponse::Found()
        .append_header(("Location", result.url()))
        .finish()
}

// ─── Set Password Handler ──────────────────────────────────────

async fn handle_set_password(
    ctx: Data<Arc<AuthContext>>,
    req: HttpRequest,
    body: Json<routes::update_user::SetPasswordRequest>,
) -> Result<HttpResponse, ApiError> {
    let token = require_token(&req, ctx.get_ref())?;
    let session = require_session(ctx.get_ref(), &token).await?;
    let user_id = user_id_from_session(&session)?;
    let result = routes::update_user::handle_set_password(
        ctx.get_ref().clone(), &user_id, body.into_inner(),
    )
    .await
    .map_err(|e| ApiError {
        status: actix_web::http::StatusCode::BAD_REQUEST,
        code: "SET_PASSWORD_ERROR".to_string(),
        message: e.to_string(),
    })?;
    Ok(HttpResponse::Ok().json(result))
}

// ─── Get Access Token Handler ──────────────────────────────────

async fn handle_get_access_token(
    ctx: Data<Arc<AuthContext>>,
    req: HttpRequest,
    body: Json<routes::account::GetAccessTokenRequest>,
) -> Result<HttpResponse, ApiError> {
    let token = require_token(&req, ctx.get_ref())?;
    let session = require_session(ctx.get_ref(), &token).await?;
    let user_id = user_id_from_session(&session)?;
    let result = routes::account::handle_get_access_token(
        ctx.get_ref().clone(), &user_id, body.into_inner(),
    )
    .await?;
    Ok(HttpResponse::Ok().json(result))
}

// ─── Refresh Token Handler ─────────────────────────────────────

async fn handle_refresh_token(
    ctx: Data<Arc<AuthContext>>,
    req: HttpRequest,
    body: Json<routes::account::RefreshTokenRequest>,
) -> Result<HttpResponse, ApiError> {
    let token = require_token(&req, ctx.get_ref())?;
    let session = require_session(ctx.get_ref(), &token).await?;
    let user_id = user_id_from_session(&session)?;
    let result = routes::account::handle_refresh_token(
        ctx.get_ref().clone(), &user_id, body.into_inner(),
    )
    .await
    .map_err(|e: routes::account::RefreshTokenError| ApiError {
        status: actix_web::http::StatusCode::BAD_REQUEST,
        code: "REFRESH_TOKEN_ERROR".to_string(),
        message: e.to_string(),
    })?;
    Ok(HttpResponse::Ok().json(result))
}

// ─── Account Info Handler ──────────────────────────────────────

async fn handle_account_info(
    ctx: Data<Arc<AuthContext>>,
    req: HttpRequest,
    query: Query<routes::account::AccountInfoQuery>,
) -> Result<HttpResponse, ApiError> {
    let token = require_token(&req, ctx.get_ref())?;
    let session = require_session(ctx.get_ref(), &token).await?;
    let user_id = user_id_from_session(&session)?;
    let result = routes::account::handle_account_info(
        ctx.get_ref().clone(), &user_id, query.into_inner(),
    )
    .await
    .map_err(|e: routes::account::AccountInfoError| ApiError {
        status: actix_web::http::StatusCode::BAD_REQUEST,
        code: "ACCOUNT_INFO_ERROR".to_string(),
        message: e.to_string(),
    })?;
    Ok(HttpResponse::Ok().json(result))
}

// ─── Delete User Callback Handler ──────────────────────────────

async fn handle_delete_user_callback(
    ctx: Data<Arc<AuthContext>>,
    query: Query<routes::update_user::DeleteUserCallbackQuery>,
) -> Result<HttpResponse, ApiError> {
    // For delete-user/callback, the session is optional
    let result = routes::update_user::handle_delete_user_callback(
        ctx.get_ref().clone(), None, query.into_inner(),
    )
    .await
    .map_err(|e| ApiError {
        status: actix_web::http::StatusCode::BAD_REQUEST,
        code: "DELETE_USER_CALLBACK_ERROR".to_string(),
        message: e.to_string(),
    })?;
    Ok(HttpResponse::Ok().json(result))
}

// ─── Change Email Handler ──────────────────────────────────────

async fn handle_change_email(
    ctx: Data<Arc<AuthContext>>,
    req: HttpRequest,
    body: Json<routes::update_user::ChangeEmailRequest>,
) -> Result<HttpResponse, ApiError> {
    let token = require_token(&req, ctx.get_ref())?;
    let session = require_session(ctx.get_ref(), &token).await?;
    let user_id = user_id_from_session(&session)?;
    let result = routes::update_user::handle_change_email(
        ctx.get_ref().clone(), &user_id, body.into_inner(),
    )
    .await
    .map_err(|e| ApiError {
        status: actix_web::http::StatusCode::BAD_REQUEST,
        code: "CHANGE_EMAIL_ERROR".to_string(),
        message: e.to_string(),
    })?;
    Ok(HttpResponse::Ok().json(result))
}

// ─── Session Management Handlers ────────────────────────────────

async fn handle_list_sessions(
    ctx: Data<Arc<AuthContext>>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let token = require_token(&req, ctx.get_ref())?;
    let session = require_session(ctx.get_ref(), &token).await?;
    let user_id = user_id_from_session(&session)?;
    let result = routes::session::handle_list_sessions(ctx.get_ref().clone(), &user_id).await?;
    Ok(HttpResponse::Ok().json(result))
}

#[derive(serde::Deserialize)]
struct RevokeSessionRequest {
    token: String,
}

async fn handle_revoke_session(
    ctx: Data<Arc<AuthContext>>,
    req: HttpRequest,
    body: Json<RevokeSessionRequest>,
) -> Result<HttpResponse, ApiError> {
    let token = require_token(&req, ctx.get_ref())?;
    let session = require_session(ctx.get_ref(), &token).await?;
    let user_id = user_id_from_session(&session)?;
    let result =
        routes::session::handle_revoke_session(ctx.get_ref().clone(), &user_id, &body.token)
            .await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn handle_revoke_sessions(
    ctx: Data<Arc<AuthContext>>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let token = require_token(&req, ctx.get_ref())?;
    let session = require_session(ctx.get_ref(), &token).await?;
    let user_id = user_id_from_session(&session)?;
    let result = routes::session::handle_revoke_sessions(ctx.get_ref().clone(), &user_id).await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn handle_revoke_other_sessions(
    ctx: Data<Arc<AuthContext>>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let token = require_token(&req, ctx.get_ref())?;
    let session = require_session(ctx.get_ref(), &token).await?;
    let user_id = user_id_from_session(&session)?;
    let session_token = session.session["token"]
        .as_str()
        .ok_or_else(|| ApiError {
            status: actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            code: "INTERNAL_ERROR".to_string(),
            message: "No session token".to_string(),
        })?;
    let result = routes::session::handle_revoke_other_sessions(
        ctx.get_ref().clone(),
        &user_id,
        session_token,
    )
    .await?;
    Ok(HttpResponse::Ok().json(result))
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_error_display() {
        let err = ApiError {
            status: actix_web::http::StatusCode::NOT_FOUND,
            code: "NOT_FOUND".to_string(),
            message: "Resource not found".to_string(),
        };
        assert_eq!(format!("{}", err), "NOT_FOUND: Resource not found");
    }

    #[test]
    fn test_adapter_error_conversion() {
        let err = ApiError::from(AdapterError::NotFound);
        assert_eq!(err.status, actix_web::http::StatusCode::NOT_FOUND);
        assert_eq!(err.code, "NOT_FOUND");

        let err = ApiError::from(AdapterError::Duplicate("user exists".into()));
        assert_eq!(err.status, actix_web::http::StatusCode::CONFLICT);

        let err = ApiError::from(AdapterError::Database("Invalid email or password".into()));
        assert_eq!(err.status, actix_web::http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path("/api/auth/session", "/api/auth"), "/session");
        assert_eq!(
            normalize_path("/api/auth/sign-in/email", "/api/auth"),
            "/sign-in/email"
        );
        assert_eq!(normalize_path("/api/auth", "/api/auth"), "/");
        assert_eq!(
            normalize_path("/other/path", "/api/auth"),
            "/other/path"
        );
    }

    #[test]
    fn test_generic_response_to_http() {
        let resp = GenericResponse::json(200, &serde_json::json!({"ok": true}));
        let http_resp = generic_response_to_http(resp);
        assert_eq!(http_resp.status(), actix_web::http::StatusCode::OK);
    }

    #[test]
    fn test_generic_response_redirect_to_http() {
        let resp = GenericResponse::redirect(302, "https://example.com");
        let http_resp = generic_response_to_http(resp);
        assert_eq!(http_resp.status(), actix_web::http::StatusCode::FOUND);
        assert_eq!(
            http_resp.headers().get("location").unwrap().to_str().unwrap(),
            "https://example.com"
        );
    }

    #[test]
    fn test_middleware_error_forbidden() {
        let resp = middleware_error_response(MiddlewareError::Forbidden {
            code: "CSRF_FAILED",
            message: "CSRF check failed".to_string(),
        });
        assert_eq!(resp.status(), actix_web::http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_middleware_error_rate_limit() {
        let resp = middleware_error_response(MiddlewareError::TooManyRequests {
            retry_after: 60,
            message: "Rate limit exceeded".to_string(),
        });
        assert_eq!(
            resp.status(),
            actix_web::http::StatusCode::TOO_MANY_REQUESTS
        );
        assert!(resp.headers().get("X-Retry-After").is_some());
    }

    #[actix_rt::test]
    async fn test_better_auth_creation() {
        use better_auth::internal_adapter::InternalAdapter;

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

        // Verify context is created
        assert_eq!(auth.context().base_path, "/api/auth");

        // Verify configure creates the service config closure
        let _configure = auth.configure();

        // Verify generic handler creates the service config closure
        let _handler = auth.generic_handler();
    }
}
