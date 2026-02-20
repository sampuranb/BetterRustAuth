// Framework-agnostic HTTP handler layer for Better Auth.
//
// Maps to: packages/better-auth/src/api/index.ts (router function)
//        + packages/better-auth/src/integrations/node.ts (toNodeHandler)
//
// This module provides framework-agnostic request/response types and a
// `handle_auth_request` function that any web framework integration can call.
// It mirrors the TS `Auth.handler` — a single function that takes an HTTP
// request and returns an HTTP response with all auth routes handled.
//
// Usage by framework integrations:
//   1. Convert framework-specific request → GenericRequest
//   2. Call handle_auth_request(ctx, request)
//   3. Convert GenericResponse → framework-specific response

use std::collections::HashMap;
use std::sync::Arc;

use crate::context::AuthContext;
use crate::cookies::ResponseCookies;
use crate::internal_adapter::AdapterError;
use crate::middleware;
use crate::routes;

// ─── Generic Request ────────────────────────────────────────────

/// A framework-agnostic HTTP request.
///
/// Framework integrations convert their specific request types into this.
/// This mirrors the role of the JS `Request` object in the TS version.
#[derive(Debug, Clone)]
pub struct GenericRequest {
    /// HTTP method (GET, POST, etc.)
    pub method: String,
    /// Full request path (e.g., "/api/auth/sign-in/email")
    pub path: String,
    /// Query string (e.g., "token=abc&redirect=true")
    pub query: Option<String>,
    /// Request headers (lowercased keys)
    pub headers: HashMap<String, String>,
    /// Request body (JSON bytes)
    pub body: Option<Vec<u8>>,
}

impl GenericRequest {
    /// Parse the request body as JSON.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, String> {
        let body = self.body.as_ref().ok_or("Request body is empty")?;
        serde_json::from_slice(body).map_err(|e| format!("Failed to parse JSON: {}", e))
    }

    /// Get a header value by name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_lowercase()).map(|s| s.as_str())
    }

    /// Extract the session token from cookies or Authorization header.
    ///
    /// Uses a hardcoded default cookie name for framework-agnostic usage.
    /// For configurable cookie names, use `session_token_with_prefix`.
    pub fn session_token(&self) -> Option<String> {
        self.session_token_with_prefix("better-auth")
    }

    /// Extract the session token using a configurable cookie prefix.
    ///
    /// Matches TS behavior where the cookie name is `{prefix}.session_token`.
    /// Also checks for the `__Secure-` prefixed variant (used on HTTPS).
    pub fn session_token_with_prefix(&self, prefix: &str) -> Option<String> {
        // Try Authorization: Bearer <token>
        if let Some(auth) = self.header("authorization") {
            if let Some(token) = auth.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }

        // Try cookie with configurable prefix
        if let Some(cookies) = self.header("cookie") {
            let cookie_name = format!("{}.session_token", prefix);
            let secure_cookie_name = format!("__Secure-{}", cookie_name);

            for cookie in cookies.split(';') {
                let cookie = cookie.trim();
                // Check secure variant first
                if let Some((name, value)) = cookie.split_once('=') {
                    let name = name.trim();
                    if name == secure_cookie_name || name == cookie_name {
                        return Some(value.to_string());
                    }
                }
            }
        }

        None
    }

    /// Get the raw `Cookie` header value for cookie cache operations.
    pub fn cookie_header(&self) -> Option<&str> {
        self.header("cookie")
    }

    /// Parse query parameters into a map.
    pub fn query_params(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        if let Some(ref query) = self.query {
            for pair in query.split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    params.insert(
                        urlencoding::decode(key).unwrap_or_default().to_string(),
                        urlencoding::decode(value).unwrap_or_default().to_string(),
                    );
                }
            }
        }
        params
    }

    /// Get a query parameter value.
    pub fn query_param(&self, name: &str) -> Option<String> {
        self.query_params().get(name).cloned()
    }

    /// Get the client IP from X-Forwarded-For or X-Real-IP headers.
    pub fn client_ip(&self) -> String {
        self.header("x-forwarded-for")
            .map(|s| s.split(',').next().unwrap_or("unknown").trim().to_string())
            .or_else(|| self.header("x-real-ip").map(|s| s.to_string()))
            .unwrap_or_else(|| "unknown".to_string())
    }
}

// ─── Generic Response ───────────────────────────────────────────

/// A framework-agnostic HTTP response.
///
/// Framework integrations convert this into their specific response types.
#[derive(Debug, Clone)]
pub struct GenericResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers.
    pub headers: HashMap<String, Vec<String>>,
    /// Response body (JSON bytes).
    pub body: Vec<u8>,
}

impl GenericResponse {
    /// Create a JSON response.
    pub fn json<T: serde::Serialize>(status: u16, data: &T) -> Self {
        let body = serde_json::to_vec(data).unwrap_or_default();
        let mut headers = HashMap::new();
        headers.insert(
            "content-type".to_string(),
            vec!["application/json".to_string()],
        );
        Self { status, headers, body }
    }

    /// Create a JSON response with Set-Cookie headers.
    pub fn json_with_cookies<T: serde::Serialize>(
        status: u16,
        data: &T,
        cookies: ResponseCookies,
    ) -> Self {
        let mut resp = Self::json(status, data);
        let cookie_values: Vec<String> = cookies
            .into_headers()
            .into_iter()
            .map(|(_, v)| v)
            .collect();
        if !cookie_values.is_empty() {
            resp.headers.insert("set-cookie".to_string(), cookie_values);
        }
        resp
    }

    /// Create a redirect response.
    pub fn redirect(status: u16, url: &str) -> Self {
        let mut headers = HashMap::new();
        headers.insert("location".to_string(), vec![url.to_string()]);
        Self {
            status,
            headers,
            body: Vec::new(),
        }
    }

    /// Create an HTML response.
    pub fn html(status: u16, html: &str) -> Self {
        let mut headers = HashMap::new();
        headers.insert(
            "content-type".to_string(),
            vec!["text/html; charset=utf-8".to_string()],
        );
        Self {
            status,
            headers,
            body: html.as_bytes().to_vec(),
        }
    }

    /// Create an error response.
    pub fn error(status: u16, code: &str, message: &str) -> Self {
        let body = serde_json::json!({
            "error": {
                "message": message,
                "code": code,
                "status": status,
            }
        });
        Self::json(status, &body)
    }
}

// ─── Auth Handler ───────────────────────────────────────────────

/// Handle an auth request using the framework-agnostic types.
///
/// This is the Rust equivalent of the TS `Auth.handler` function.
/// It routes the request to the appropriate handler based on the path.
///
/// # Arguments
/// - `ctx`: The shared AuthContext.
/// - `request`: A framework-agnostic request.
///
/// # Returns
/// A framework-agnostic response.
pub async fn handle_auth_request(
    ctx: Arc<AuthContext>,
    request: GenericRequest,
) -> GenericResponse {
    // 1. Strip base_path to get the route path
    let mut route_path = strip_base_path(&request.path, &ctx.base_path);

    // 1b. Normalize trailing slashes if enabled (matches TS `skipTrailingSlashes`)
    if ctx.options.advanced.skip_trailing_slashes && route_path.len() > 1 {
        route_path = route_path.trim_end_matches('/').to_string();
        if route_path.is_empty() {
            route_path = "/".to_string();
        }
    }

    // 2. Run origin check middleware
    let origin_headers = request
        .headers
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                middleware::origin_check::HeaderValue::new(v),
            )
        })
        .collect::<HashMap<_, _>>();

    if let Err(e) = middleware::origin_check::validate_origin(
        &request.method,
        &origin_headers,
        &route_path,
        &ctx.trusted_origins,
        &ctx.origin_check_config,
    ) {
        return middleware_error_to_response(e);
    }

    // 3. Run rate limit middleware
    let ip = request.client_ip();
    if let Err(e) = ctx.rate_limiter.check(&ip, &route_path) {
        return middleware_error_to_response(e);
    }

    // 4. Plugin onRequest hooks — iterate all plugins and call on_request
    // Matches TS: for (const plugin of ctx.options.plugins || []) { if (plugin.onRequest) { ... } }
    {
        let plugin_request = better_auth_core::plugin::PluginRequest {
            method: match request.method.as_str() {
                "GET" => better_auth_core::plugin::HttpMethod::Get,
                "POST" => better_auth_core::plugin::HttpMethod::Post,
                "PUT" => better_auth_core::plugin::HttpMethod::Put,
                "DELETE" => better_auth_core::plugin::HttpMethod::Delete,
                "PATCH" => better_auth_core::plugin::HttpMethod::Patch,
                _ => better_auth_core::plugin::HttpMethod::Get,
            },
            path: route_path.clone(),
            headers: request.headers.clone(),
        };

        for plugin_id in ctx.plugin_registry.plugin_ids() {
            if let Some(plugin) = ctx.plugin_registry.get_plugin(plugin_id) {
                if let Err(e) = plugin.on_request(&plugin_request).await {
                    // Plugin signaled an error — return it as a response
                    return GenericResponse::error(
                        400,
                        "PLUGIN_REQUEST_ERROR",
                        &e.to_string(),
                    );
                }
            }
        }
    }

    // 5. Route to handler
    let mut response = route_request(ctx.clone(), &route_path, &request).await;

    // 6. Plugin onResponse hooks — iterate all plugins and call on_response
    // Matches TS: for (const plugin of ctx.options.plugins || []) { if (plugin.onResponse) { ... } }
    {
        let body_value: Option<serde_json::Value> = if response.body.is_empty() {
            None
        } else {
            serde_json::from_slice(&response.body).ok()
        };

        let mut plugin_response = better_auth_core::plugin::PluginResponse {
            status: response.status,
            headers: response
                .headers
                .iter()
                .map(|(k, v)| (k.clone(), v.join(", ")))
                .collect(),
            body: body_value,
        };

        for plugin_id in ctx.plugin_registry.plugin_ids() {
            if let Some(plugin) = ctx.plugin_registry.get_plugin(plugin_id) {
                let _ = plugin.on_response(&mut plugin_response).await;
            }
        }

        // Apply any modifications back to the response
        response.status = plugin_response.status;
        if let Some(body) = plugin_response.body {
            if let Ok(serialized) = serde_json::to_vec(&body) {
                response.body = serialized;
            }
        }
    }

    response
}

/// Strip the base path prefix from a request path.
fn strip_base_path(path: &str, base_path: &str) -> String {
    let stripped = path.strip_prefix(base_path).unwrap_or(path);
    if stripped.is_empty() {
        "/".to_string()
    } else if stripped.starts_with('/') {
        stripped.to_string()
    } else {
        format!("/{}", stripped)
    }
}

/// Convert a middleware error into a GenericResponse.
fn middleware_error_to_response(err: middleware::MiddlewareError) -> GenericResponse {
    match err {
        middleware::MiddlewareError::Forbidden { code, message } => {
            GenericResponse::error(403, &code, &message)
        }
        middleware::MiddlewareError::TooManyRequests {
            retry_after,
            message,
        } => {
            let mut resp = GenericResponse::error(429, "TOO_MANY_REQUESTS", &message);
            resp.headers.insert(
                "x-retry-after".to_string(),
                vec![retry_after.to_string()],
            );
            resp
        }
    }
}

/// Convert an AdapterError into a GenericResponse.
fn adapter_error_to_response(e: AdapterError) -> GenericResponse {
    let (status, code, message) = match &e {
        AdapterError::NotFound => (404, "NOT_FOUND", "Not found".to_string()),
        AdapterError::Duplicate(msg) => (409, "DUPLICATE", msg.clone()),
        AdapterError::Serialization(msg) => (500, "SERIALIZATION_ERROR", msg.clone()),
        AdapterError::Database(msg) => {
            if msg.contains("Invalid email or password") {
                (401, "INVALID_CREDENTIALS", msg.clone())
            } else if msg.contains("already exists") {
                (409, "DUPLICATE", msg.clone())
            } else if msg.contains("expired") || msg.contains("Invalid") {
                (400, "BAD_REQUEST", msg.clone())
            } else {
                (500, "INTERNAL_SERVER_ERROR", msg.clone())
            }
        }
    };
    GenericResponse::error(status, code, &message)
}

/// Helper: require a session token from the request.
fn require_token(request: &GenericRequest) -> Result<String, GenericResponse> {
    request
        .session_token()
        .ok_or_else(|| GenericResponse::error(401, "UNAUTHORIZED", "Authentication required"))
}

/// Helper: require a session from a token.
async fn require_session(
    ctx: Arc<AuthContext>,
    token: &str,
) -> Result<routes::session::SessionResponse, GenericResponse> {
    let result = routes::session::handle_get_session(
        ctx,
        token,
        routes::session::GetSessionOptions::default(),
        None,
    )
    .await
    .map_err(|e| adapter_error_to_response(e))?;

    result
        .response
        .ok_or_else(|| GenericResponse::error(401, "INVALID_SESSION", "Invalid session"))
}

/// Helper: get user_id from session response.
fn user_id_from_session(
    session: &routes::session::SessionResponse,
) -> Result<String, GenericResponse> {
    session.user["id"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| GenericResponse::error(500, "INTERNAL_ERROR", "No user id in session"))
}

/// Route an incoming request to the appropriate handler.
async fn route_request(
    ctx: Arc<AuthContext>,
    route_path: &str,
    request: &GenericRequest,
) -> GenericResponse {
    // Check disabled paths — TS: `ctx.options.disabledPaths`
    if !ctx.options.advanced.disabled_paths.is_empty()
        && ctx.options.advanced.disabled_paths.iter().any(|p| p == route_path)
    {
        return GenericResponse::error(404, "NOT_FOUND", "Not Found");
    }

    match (request.method.as_str(), route_path) {
        // Health
        ("GET", "/ok") => GenericResponse::json(200, &routes::ok::handle_ok()),

        // Sign up
        ("POST", "/sign-up/email") => {
            match request.json::<routes::sign_up::SignUpRequest>() {
                Ok(body) => match routes::sign_up::handle_sign_up(ctx, body).await {
                    Ok(result) => GenericResponse::json(201, &result),
                    Err(e) => sign_up_error_to_response(e),
                },
                Err(msg) => GenericResponse::error(400, "BAD_REQUEST", &msg),
            }
        }

        // Sign in
        ("POST", "/sign-in/email") => {
            match request.json::<routes::sign_in::SignInRequest>() {
                Ok(body) => match routes::sign_in::handle_sign_in(ctx, body).await {
                    Ok(result) => GenericResponse::json(200, &result),
                    Err(e) => sign_in_error_to_response(e),
                },
                Err(msg) => GenericResponse::error(400, "BAD_REQUEST", &msg),
            }
        }

        // Social sign in
        ("POST", "/sign-in/social") => {
            match request.json::<routes::sign_in::SocialSignInRequest>() {
                Ok(body) => match routes::sign_in::handle_social_sign_in(ctx, body).await {
                    Ok(result) => {
                        if result.redirect == Some(true) {
                            if let Some(ref url) = result.url {
                                return GenericResponse::redirect(302, url);
                            }
                        }
                        GenericResponse::json(200, &result)
                    }
                    Err(e) => adapter_error_to_response(e),
                },
                Err(msg) => GenericResponse::error(400, "BAD_REQUEST", &msg),
            }
        }

        // Sign out — delete session and return cookie deletion headers
        ("POST", "/sign-out") => {
            let cookie_prefix = ctx.options.advanced.cookie_prefix.as_deref().unwrap_or("better-auth");
            let token = request.session_token_with_prefix(cookie_prefix);
            match routes::sign_out::handle_sign_out(ctx.clone(), token.as_deref()).await {
                Ok(result) => {
                    // Build cookie deletion headers matching TS behavior
                    let mut cookies = crate::cookies::ResponseCookies::new();
                    for cookie_name in &result.cookies_to_delete {
                        let attrs = crate::cookies::CookieAttributes {
                            value: String::new(),
                            max_age: Some(0),
                            expires: None,
                            domain: None,
                            path: Some("/".to_string()),
                            secure: false,
                            http_only: true,
                            same_site: Some(crate::cookies::SameSite::Lax),
                        };
                        cookies.set_cookie(cookie_name, &attrs);
                    }
                    GenericResponse::json_with_cookies(200, &result.response, cookies)
                }
                Err(e) => adapter_error_to_response(e),
            }
        }

        // Get session (both /session and /get-session for TS client compat)
        // TS uses method: ["GET", "POST"] — POST is used for session refresh
        ("GET" | "POST", "/session") | ("GET" | "POST", "/get-session") => {
            let cookie_prefix = ctx.options.advanced.cookie_prefix.as_deref().unwrap_or("better-auth");
            let token = match request.session_token_with_prefix(cookie_prefix) {
                Some(t) => t,
                None => return GenericResponse::json(200, &serde_json::Value::Null),
            };
            match routes::session::handle_get_session(
                ctx,
                &token,
                routes::session::GetSessionOptions::default(),
                request.cookie_header(),
            )
            .await
            {
                Ok(result) => match result.response {
                    Some(session) => GenericResponse::json(200, &session),
                    None => GenericResponse::json(200, &serde_json::Value::Null),
                },
                Err(e) => adapter_error_to_response(e),
            }
        }

        // List sessions
        ("GET", "/list-sessions") => {
            let token = match require_token(request) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let session = match require_session(ctx.clone(), &token).await {
                Ok(s) => s,
                Err(e) => return e,
            };
            let user_id = match user_id_from_session(&session) {
                Ok(id) => id,
                Err(e) => return e,
            };
            match routes::session::handle_list_sessions(ctx, &user_id).await {
                Ok(result) => GenericResponse::json(200, &result),
                Err(e) => adapter_error_to_response(e),
            }
        }

        // Revoke session
        ("POST", "/revoke-session") => {
            let token = match require_token(request) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let session = match require_session(ctx.clone(), &token).await {
                Ok(s) => s,
                Err(e) => return e,
            };
            let user_id = match user_id_from_session(&session) {
                Ok(id) => id,
                Err(e) => return e,
            };
            #[derive(serde::Deserialize)]
            struct Body { token: String }
            match request.json::<Body>() {
                Ok(body) => {
                    match routes::session::handle_revoke_session(ctx, &user_id, &body.token).await {
                        Ok(result) => GenericResponse::json(200, &result),
                        Err(e) => adapter_error_to_response(e),
                    }
                }
                Err(msg) => GenericResponse::error(400, "BAD_REQUEST", &msg),
            }
        }

        // Revoke all sessions
        ("POST", "/revoke-sessions") => {
            let token = match require_token(request) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let session = match require_session(ctx.clone(), &token).await {
                Ok(s) => s,
                Err(e) => return e,
            };
            let user_id = match user_id_from_session(&session) {
                Ok(id) => id,
                Err(e) => return e,
            };
            match routes::session::handle_revoke_sessions(ctx, &user_id).await {
                Ok(result) => GenericResponse::json(200, &result),
                Err(e) => adapter_error_to_response(e),
            }
        }

        // Revoke other sessions
        ("POST", "/revoke-other-sessions") => {
            let token = match require_token(request) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let session = match require_session(ctx.clone(), &token).await {
                Ok(s) => s,
                Err(e) => return e,
            };
            let user_id = match user_id_from_session(&session) {
                Ok(id) => id,
                Err(e) => return e,
            };
            let session_token = session.session["token"]
                .as_str()
                .unwrap_or_default();
            match routes::session::handle_revoke_other_sessions(ctx, &user_id, session_token).await
            {
                Ok(result) => GenericResponse::json(200, &result),
                Err(e) => adapter_error_to_response(e),
            }
        }

        // OAuth callback (GET /callback/:provider)
        ("GET", path) if path.starts_with("/callback/") => {
            let _provider = path.strip_prefix("/callback/").unwrap_or("");
            let params = request.query_params();
            let query = routes::callback::CallbackQuery {
                code: params.get("code").cloned(),
                state: params.get("state").cloned(),
                error: params.get("error").cloned(),
                error_description: params.get("error_description").cloned(),
                device_id: params.get("device_id").cloned(),
                user: params.get("user").cloned(),
            };
            match routes::callback::handle_callback(ctx, query).await {
                Ok(result) => GenericResponse::redirect(302, result.url()),
                Err(e) => adapter_error_to_response(e),
            }
        }

        // OAuth callback (POST /callback/:provider) — redirect to GET
        // TS behavior: POST merges body+query and redirects to GET to ensure
        // cookies are properly set on the response.
        ("POST", path) if path.starts_with("/callback/") => {
            let provider = path.strip_prefix("/callback/").unwrap_or("");
            let base_url = ctx.base_url.as_deref().unwrap_or("");
            let full_base = format!("{}{}", base_url, ctx.base_path);

            // Parse body as CallbackQuery
            let body_query: routes::callback::CallbackQuery = request
                .json()
                .unwrap_or(routes::callback::CallbackQuery {
                    code: None, state: None, error: None,
                    error_description: None, device_id: None, user: None,
                });

            // Parse query params
            let params = request.query_params();
            let url_query = routes::callback::CallbackQuery {
                code: params.get("code").cloned(),
                state: params.get("state").cloned(),
                error: params.get("error").cloned(),
                error_description: params.get("error_description").cloned(),
                device_id: params.get("device_id").cloned(),
                user: params.get("user").cloned(),
            };

            let result = routes::callback::handle_callback_post(
                &full_base, provider, &body_query, &url_query,
            );
            GenericResponse::redirect(302, result.url())
        }

        // Update user
        ("POST", "/update-user") => {
            let token = match require_token(request) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let session = match require_session(ctx.clone(), &token).await {
                Ok(s) => s,
                Err(e) => return e,
            };
            let user_id = match user_id_from_session(&session) {
                Ok(id) => id,
                Err(e) => return e,
            };
            match request.json::<routes::update_user::UpdateUserRequest>() {
                Ok(body) => {
                    match routes::update_user::handle_update_user(ctx, &user_id, body).await {
                        Ok(result) => GenericResponse::json(200, &result),
                        Err(e) => update_user_error_to_response(e),
                    }
                }
                Err(msg) => GenericResponse::error(400, "BAD_REQUEST", &msg),
            }
        }

        // Delete user
        ("POST", "/delete-user") => {
            let token = match require_token(request) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let session = match require_session(ctx.clone(), &token).await {
                Ok(s) => s,
                Err(e) => return e,
            };
            let user_id = match user_id_from_session(&session) {
                Ok(id) => id,
                Err(e) => return e,
            };
            match request.json::<routes::update_user::DeleteUserRequest>() {
                Ok(body) => {
                    match routes::update_user::handle_delete_user(ctx, &user_id, body).await {
                        Ok(result) => GenericResponse::json(200, &result),
                        Err(e) => update_user_error_to_response(e),
                    }
                }
                Err(msg) => GenericResponse::error(400, "BAD_REQUEST", &msg),
            }
        }

        // Change password
        ("POST", "/change-password") => {
            let token = match require_token(request) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let session = match require_session(ctx.clone(), &token).await {
                Ok(s) => s,
                Err(e) => return e,
            };
            let user_id = match user_id_from_session(&session) {
                Ok(id) => id,
                Err(e) => return e,
            };
            match request.json::<routes::update_user::ChangePasswordRequest>() {
                Ok(body) => {
                    // Pass the user value from the session for the response
                    let user_value = session.user.clone();
                    match routes::update_user::handle_change_password(ctx, &user_id, user_value, body).await {
                        Ok(result) => GenericResponse::json(200, &result),
                        Err(routes::update_user::UpdateUserError::Api(e)) => {
                            GenericResponse::error(e.status, &e.code, &e.message)
                        }
                        Err(routes::update_user::UpdateUserError::Database(e)) => adapter_error_to_response(e),
                    }
                }
                Err(msg) => GenericResponse::error(400, "BAD_REQUEST", &msg),
            }
        }

        // Set password (for OAuth-only users)
        ("POST", "/set-password") => {
            let token = match require_token(request) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let session = match require_session(ctx.clone(), &token).await {
                Ok(s) => s,
                Err(e) => return e,
            };
            let user_id = match user_id_from_session(&session) {
                Ok(id) => id,
                Err(e) => return e,
            };
            match request.json::<routes::update_user::SetPasswordRequest>() {
                Ok(body) => {
                    match routes::update_user::handle_set_password(ctx, &user_id, body).await {
                        Ok(result) => GenericResponse::json(200, &result),
                        Err(e) => update_user_error_to_response(e),
                    }
                }
                Err(msg) => GenericResponse::error(400, "BAD_REQUEST", &msg),
            }
        }

        // Request password reset (matches TS path /request-password-reset)
        ("POST", "/request-password-reset") => {
            match request.json::<routes::password::ForgotPasswordRequest>() {
                Ok(body) => match routes::password::handle_forgot_password(ctx, body).await {
                    Ok(result) => GenericResponse::json(200, &result),
                    Err(e) => adapter_error_to_response(e),
                },
                Err(msg) => GenericResponse::error(400, "BAD_REQUEST", &msg),
            }
        }

        // Password reset callback — GET /reset-password/:token
        // Maps to TS `requestPasswordResetCallback`
        ("GET", path) if path.starts_with("/reset-password/") => {
            let token = &path["/reset-password/".len()..];
            if token.is_empty() {
                return GenericResponse::error(400, "BAD_REQUEST", "Missing reset token");
            }
            let params = request.query_params();
            let query = routes::password::PasswordResetCallbackQuery {
                callback_url: params.get("callbackURL").cloned().unwrap_or_default(),
            };
            match routes::password::handle_password_reset_callback(ctx, token, query).await {
                routes::password::PasswordResetCallbackResult::Redirect(url) => {
                    GenericResponse::redirect(302, &url)
                }
                routes::password::PasswordResetCallbackResult::ErrorRedirect(url) => {
                    GenericResponse::redirect(302, &url)
                }
            }
        }

        // Reset password
        ("POST", "/reset-password") => {
            match request.json::<routes::password::ResetPasswordRequest>() {
                Ok(body) => match routes::password::handle_reset_password(ctx, body).await {
                    Ok(result) => GenericResponse::json(200, &result),
                    Err(e) => adapter_error_to_response(e),
                },
                Err(msg) => GenericResponse::error(400, "BAD_REQUEST", &msg),
            }
        }

        // Verify password
        ("POST", "/verify-password") => {
            let token = match require_token(request) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let session = match require_session(ctx.clone(), &token).await {
                Ok(s) => s,
                Err(e) => return e,
            };
            let user_id = match user_id_from_session(&session) {
                Ok(id) => id,
                Err(e) => return e,
            };
            match request.json::<routes::password::VerifyPasswordRequest>() {
                Ok(body) => {
                    match routes::password::handle_verify_password(ctx, &user_id, body).await {
                        Ok(result) => GenericResponse::json(200, &result),
                        Err(e) => adapter_error_to_response(e),
                    }
                }
                Err(msg) => GenericResponse::error(400, "BAD_REQUEST", &msg),
            }
        }

        // List accounts
        ("GET", "/list-accounts") => {
            let token = match require_token(request) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let session = match require_session(ctx.clone(), &token).await {
                Ok(s) => s,
                Err(e) => return e,
            };
            let user_id = match user_id_from_session(&session) {
                Ok(id) => id,
                Err(e) => return e,
            };
            match routes::account::handle_list_accounts(ctx, &user_id).await {
                Ok(result) => GenericResponse::json(200, &result),
                Err(e) => adapter_error_to_response(e),
            }
        }

        // Unlink account
        ("POST", "/unlink-account") => {
            let token = match require_token(request) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let session = match require_session(ctx.clone(), &token).await {
                Ok(s) => s,
                Err(e) => return e,
            };
            let user_id = match user_id_from_session(&session) {
                Ok(id) => id,
                Err(e) => return e,
            };
            match request.json::<routes::account::UnlinkAccountRequest>() {
                Ok(body) => {
                    match routes::account::handle_unlink_account(ctx, &user_id, body).await {
                        Ok(result) => GenericResponse::json(200, &result),
                        Err(e) => unlink_error_to_response(e),
                    }
                }
                Err(msg) => GenericResponse::error(400, "BAD_REQUEST", &msg),
            }
        }

        // Link social
        ("POST", "/link-social") => {
            let token = match require_token(request) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let session = match require_session(ctx.clone(), &token).await {
                Ok(s) => s,
                Err(e) => return e,
            };
            let user_id = match user_id_from_session(&session) {
                Ok(id) => id,
                Err(e) => return e,
            };
            let user_email = session.user["email"]
                .as_str()
                .unwrap_or_default();
            match request.json::<routes::account::LinkSocialRequest>() {
                Ok(body) => {
                    match routes::account::handle_link_social(ctx, &user_id, user_email, body).await
                    {
                        Ok(result) => GenericResponse::json(200, &result),
                        Err(e) => adapter_error_to_response(e),
                    }
                }
                Err(msg) => GenericResponse::error(400, "BAD_REQUEST", &msg),
            }
        }

        // Verify email
        ("GET", "/verify-email") => {
            let params = request.query_params();
            let query = routes::email_verification::VerifyEmailQuery {
                token: params.get("token").cloned().unwrap_or_default(),
                callback_url: params.get("callbackURL").cloned(),
            };
            match routes::email_verification::handle_verify_email(ctx, query).await {
                Ok(result) => GenericResponse::json(200, &result),
                Err(e) => adapter_error_to_response(e),
            }
        }

        // Send verification email
        ("POST", "/send-verification-email") => {
            match request.json::<routes::email_verification::SendVerificationRequest>() {
                Ok(body) => {
                    match routes::email_verification::handle_send_verification(ctx, body).await {
                        Ok(result) => GenericResponse::json(200, &result),
                        Err(e) => adapter_error_to_response(e),
                    }
                }
                Err(msg) => GenericResponse::error(400, "BAD_REQUEST", &msg),
            }
        }

        // Error page
        ("GET", "/error") => {
            let params = request.query_params();
            let query = routes::error_page::ErrorPageQuery {
                error: params.get("error").cloned(),
                error_description: params.get("error_description").cloned(),
            };
            let html = routes::error_page::render_error_page(&query);
            GenericResponse::html(200, &html)
        }

        // Change email
        ("POST", "/change-email") => {
            let token = match require_token(request) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let session = match require_session(ctx.clone(), &token).await {
                Ok(s) => s,
                Err(e) => return e,
            };
            let user_id = match user_id_from_session(&session) {
                Ok(id) => id,
                Err(e) => return e,
            };
            match request.json::<routes::update_user::ChangeEmailRequest>() {
                Ok(body) => {
                    match routes::update_user::handle_change_email(ctx, &user_id, body).await {
                        Ok(result) => GenericResponse::json(200, &result),
                        Err(e) => update_user_error_to_response(e),
                    }
                }
                Err(msg) => GenericResponse::error(400, "BAD_REQUEST", &msg),
            }
        }

        // Get access token for linked OAuth account
        ("POST", "/get-access-token") => {
            let token = match require_token(request) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let session = match require_session(ctx.clone(), &token).await {
                Ok(s) => s,
                Err(e) => return e,
            };
            let user_id = match user_id_from_session(&session) {
                Ok(id) => id,
                Err(e) => return e,
            };
            match request.json::<routes::account::GetAccessTokenRequest>() {
                Ok(body) => {
                    match routes::account::handle_get_access_token(ctx, &user_id, body).await {
                        Ok(result) => GenericResponse::json(200, &result),
                        Err(e) => adapter_error_to_response(e),
                    }
                }
                Err(msg) => GenericResponse::error(400, "BAD_REQUEST", &msg),
            }
        }

        // Force-refresh OAuth tokens for linked account
        ("POST", "/refresh-token") => {
            let token = match require_token(request) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let session = match require_session(ctx.clone(), &token).await {
                Ok(s) => s,
                Err(e) => return e,
            };
            let user_id = match user_id_from_session(&session) {
                Ok(id) => id,
                Err(e) => return e,
            };
            match request.json::<routes::account::RefreshTokenRequest>() {
                Ok(body) => {
                    match routes::account::handle_refresh_token(ctx, &user_id, body).await {
                        Ok(result) => GenericResponse::json(200, &result),
                        Err(e) => refresh_token_error_to_response(e),
                    }
                }
                Err(msg) => GenericResponse::error(400, "BAD_REQUEST", &msg),
            }
        }

        // Get provider-side account info
        ("GET", "/account-info") => {
            let token = match require_token(request) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let session = match require_session(ctx.clone(), &token).await {
                Ok(s) => s,
                Err(e) => return e,
            };
            let user_id = match user_id_from_session(&session) {
                Ok(id) => id,
                Err(e) => return e,
            };
            let params = request.query_params();
            let query = routes::account::AccountInfoQuery {
                account_id: params.get("accountId").cloned(),
            };
            match routes::account::handle_account_info(ctx, &user_id, query).await {
                Ok(result) => GenericResponse::json(200, &result),
                Err(e) => account_info_error_to_response(e),
            }
        }

        // Delete user callback (verified deletion via email token)
        ("GET", "/delete-user/callback") => {
            let params = request.query_params();
            let callback_token = params.get("token").cloned().unwrap_or_default();
            let callback_url = params.get("callbackURL").cloned();

            // Optionally get user_id from session (may not be present)
            let cookie_prefix = ctx.options.advanced.cookie_prefix.as_deref().unwrap_or("better-auth");
            let session_token = request.session_token_with_prefix(cookie_prefix);
            let user_id_opt = if let Some(ref st) = session_token {
                if let Ok(sess) = routes::session::handle_get_session(
                    ctx.clone(), st, routes::session::GetSessionOptions::default(), None,
                ).await {
                    sess.response.as_ref().and_then(|s| {
                        s.user["id"].as_str().map(|id: &str| id.to_string())
                    })
                } else {
                    None
                }
            } else {
                None
            };

            let query = routes::update_user::DeleteUserCallbackQuery {
                token: callback_token,
                callback_url: callback_url.clone(),
            };
            match routes::update_user::handle_delete_user_callback(
                ctx, user_id_opt.as_deref(), query,
            ).await {
                Ok(result) => {
                    if let Some(url) = callback_url {
                        GenericResponse::redirect(302, &url)
                    } else {
                        GenericResponse::json(200, &result)
                    }
                }
                Err(e) => update_user_error_to_response(e),
            }
        }

        // Plugin endpoint dispatch — try plugin handlers before returning 404
        _ => {
            use better_auth_core::plugin::HttpMethod as PluginMethod;
            use crate::plugin_runtime::endpoint_router;

            let plugin_method = match request.method.as_str() {
                "GET" => PluginMethod::Get,
                "POST" => PluginMethod::Post,
                "PUT" => PluginMethod::Put,
                "DELETE" => PluginMethod::Delete,
                "PATCH" => PluginMethod::Patch,
                _ => return GenericResponse::error(405, "METHOD_NOT_ALLOWED", "Method not allowed"),
            };

            // Check full path (with base_path) since plugin endpoints are registered without it
            let full_path = format!("{}{}", ctx.base_path, route_path);
            let dispatch_path = if endpoint_router::has_plugin_endpoint(&ctx.plugin_registry, plugin_method, route_path) {
                route_path.to_string()
            } else if endpoint_router::has_plugin_endpoint(&ctx.plugin_registry, plugin_method, &full_path) {
                full_path
            } else {
                return GenericResponse::error(404, "NOT_FOUND", &format!("Route not found: {} {}", request.method, route_path));
            };

            // Build plugin handler request
            let cookie_prefix = ctx.options.advanced.cookie_prefix.as_deref().unwrap_or("better-auth");
            let session_token = request.session_token_with_prefix(cookie_prefix);

            // Try to resolve session for plugin
            let session = if let Some(ref token) = session_token {
                match routes::session::handle_get_session(
                    ctx.clone(), token, routes::session::GetSessionOptions::default(), request.cookie_header()
                ).await {
                    Ok(result) => result.response.map(|s| serde_json::json!({
                        "user": s.user,
                        "session": s.session,
                    })),
                    Err(_) => None,
                }
            } else {
                None
            };

            let body_json: serde_json::Value = request.body.as_ref()
                .and_then(|b| serde_json::from_slice(b).ok())
                .unwrap_or(serde_json::json!({}));

            let query_json: serde_json::Value = request.query.as_ref()
                .map(|q| {
                    let mut map = serde_json::Map::new();
                    for pair in q.split('&') {
                        if let Some((key, value)) = pair.split_once('=') {
                            map.insert(key.to_string(), serde_json::Value::String(value.to_string()));
                        }
                    }
                    serde_json::Value::Object(map)
                })
                .unwrap_or(serde_json::json!({}));

            let plugin_req = better_auth_core::plugin::PluginHandlerRequest {
                body: body_json,
                query: query_json,
                headers: request.headers.clone(),
                session_token,
                session,
            };

            let ctx_any: Arc<dyn std::any::Any + Send + Sync> = ctx.clone();
            match endpoint_router::dispatch_to_handler(
                &ctx.plugin_registry, ctx_any, plugin_method, &dispatch_path, plugin_req
            ).await {
                Some(response) => {
                    let mut resp = GenericResponse {
                        status: response.status,
                        headers: response.headers.iter().map(|(k, v)| (k.clone(), vec![v.clone()])).collect(),
                        body: serde_json::to_vec(&response.body).unwrap_or_default(),
                    };
                    // Handle redirects
                    if response.status == 302 {
                        if let Some(location) = response.headers.get("Location") {
                            resp = GenericResponse::redirect(302, location);
                        }
                    }
                    resp
                }
                None => GenericResponse::error(404, "NOT_FOUND", &format!("Route not found: {} {}", request.method, route_path)),
            }
        }
    }
}

// ─── Error Converters ───────────────────────────────────────────

fn sign_up_error_to_response(e: routes::sign_up::SignUpHandlerError) -> GenericResponse {
    use routes::sign_up::SignUpHandlerError;
    match e {
        SignUpHandlerError::BadRequest(err) => {
            GenericResponse::error(400, &format!("{err:?}"), &err.to_string())
        }
        SignUpHandlerError::UnprocessableEntity(err) => {
            GenericResponse::error(422, &format!("{err:?}"), &err.to_string())
        }
        SignUpHandlerError::Internal(msg) => {
            GenericResponse::error(500, "INTERNAL_SERVER_ERROR", &msg)
        }
        SignUpHandlerError::Adapter(adapter_err) => adapter_error_to_response(adapter_err),
    }
}

fn sign_in_error_to_response(e: routes::sign_in::SignInHandlerError) -> GenericResponse {
    use routes::sign_in::SignInHandlerError;
    match e {
        SignInHandlerError::BadRequest(err) => {
            GenericResponse::error(400, &format!("{err:?}"), &err.to_string())
        }
        SignInHandlerError::Unauthorized(err) => {
            GenericResponse::error(401, &format!("{err:?}"), &err.to_string())
        }
        SignInHandlerError::Forbidden(err) => {
            GenericResponse::error(403, &format!("{err:?}"), &err.to_string())
        }
        SignInHandlerError::Internal(msg) => {
            GenericResponse::error(500, "INTERNAL_SERVER_ERROR", &msg)
        }
        SignInHandlerError::Adapter(adapter_err) => adapter_error_to_response(adapter_err),
    }
}

fn update_user_error_to_response(e: routes::update_user::UpdateUserError) -> GenericResponse {
    use routes::update_user::UpdateUserError;
    match e {
        UpdateUserError::Api(api_err) => {
            GenericResponse::error(400, "UPDATE_USER_ERROR", &api_err.to_string())
        }
        UpdateUserError::Database(adapter_err) => adapter_error_to_response(adapter_err),
    }
}

fn unlink_error_to_response(e: routes::account::UnlinkError) -> GenericResponse {
    use routes::account::UnlinkError;
    match e {
        UnlinkError::LastAccount => {
            GenericResponse::error(400, "LAST_ACCOUNT", &e.to_string())
        }
        UnlinkError::AccountNotFound => {
            GenericResponse::error(404, "ACCOUNT_NOT_FOUND", &e.to_string())
        }
        UnlinkError::Database(adapter_err) => adapter_error_to_response(adapter_err),
    }
}

fn refresh_token_error_to_response(e: routes::account::RefreshTokenError) -> GenericResponse {
    use routes::account::RefreshTokenError;
    match e {
        RefreshTokenError::AccountNotFound => {
            GenericResponse::error(404, "ACCOUNT_NOT_FOUND", &e.to_string())
        }
        RefreshTokenError::RefreshTokenNotFound => {
            GenericResponse::error(400, "REFRESH_TOKEN_NOT_FOUND", &e.to_string())
        }
        RefreshTokenError::ProviderNotSupported(ref _p) => {
            GenericResponse::error(400, "PROVIDER_NOT_SUPPORTED", &e.to_string())
        }
        RefreshTokenError::RefreshNotSupported(ref _p) => {
            GenericResponse::error(400, "REFRESH_NOT_SUPPORTED", &e.to_string())
        }
        RefreshTokenError::RefreshFailed => {
            GenericResponse::error(500, "REFRESH_FAILED", &e.to_string())
        }
        RefreshTokenError::UserIdOrSessionRequired => {
            GenericResponse::error(401, "UNAUTHORIZED", &e.to_string())
        }
        RefreshTokenError::Database(adapter_err) => adapter_error_to_response(adapter_err),
    }
}

fn account_info_error_to_response(e: routes::account::AccountInfoError) -> GenericResponse {
    use routes::account::AccountInfoError;
    match e {
        AccountInfoError::AccountNotFound => {
            GenericResponse::error(404, "ACCOUNT_NOT_FOUND", &e.to_string())
        }
        AccountInfoError::ProviderNotConfigured => {
            GenericResponse::error(400, "PROVIDER_NOT_CONFIGURED", &e.to_string())
        }
        AccountInfoError::AccessTokenNotFound => {
            GenericResponse::error(400, "ACCESS_TOKEN_NOT_FOUND", &e.to_string())
        }
        AccountInfoError::Database(adapter_err) => adapter_error_to_response(adapter_err),
    }
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generic_request_session_token_bearer() {
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "Bearer my-token".to_string());

        let req = GenericRequest {
            method: "GET".into(),
            path: "/api/auth/session".into(),
            query: None,
            headers,
            body: None,
        };

        assert_eq!(req.session_token(), Some("my-token".to_string()));
    }

    #[test]
    fn test_generic_request_session_token_cookie() {
        let mut headers = HashMap::new();
        headers.insert(
            "cookie".to_string(),
            "other=val; better-auth.session_token=abc123; foo=bar".to_string(),
        );

        let req = GenericRequest {
            method: "GET".into(),
            path: "/api/auth/session".into(),
            query: None,
            headers,
            body: None,
        };

        assert_eq!(req.session_token(), Some("abc123".to_string()));
    }

    #[test]
    fn test_generic_request_session_token_none() {
        let req = GenericRequest {
            method: "GET".into(),
            path: "/api/auth/session".into(),
            query: None,
            headers: HashMap::new(),
            body: None,
        };

        assert_eq!(req.session_token(), None);
    }

    #[test]
    fn test_generic_request_json_parse() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct LoginReq { email: String, password: String }

        let body = serde_json::to_vec(&serde_json::json!({
            "email": "test@example.com",
            "password": "password123"
        })).unwrap();

        let req = GenericRequest {
            method: "POST".into(),
            path: "/api/auth/sign-in/email".into(),
            query: None,
            headers: HashMap::new(),
            body: Some(body),
        };

        let parsed: LoginReq = req.json().unwrap();
        assert_eq!(parsed.email, "test@example.com");
        assert_eq!(parsed.password, "password123");
    }

    #[test]
    fn test_generic_request_query_params() {
        let req = GenericRequest {
            method: "GET".into(),
            path: "/api/auth/verify-email".into(),
            query: Some("token=abc123&callbackURL=https%3A%2F%2Fexample.com".into()),
            headers: HashMap::new(),
            body: None,
        };

        let params = req.query_params();
        assert_eq!(params.get("token"), Some(&"abc123".to_string()));
        assert_eq!(
            params.get("callbackURL"),
            Some(&"https://example.com".to_string())
        );
    }

    #[test]
    fn test_generic_request_client_ip() {
        let mut headers = HashMap::new();
        headers.insert(
            "x-forwarded-for".to_string(),
            "1.2.3.4, 5.6.7.8".to_string(),
        );

        let req = GenericRequest {
            method: "GET".into(),
            path: "/".into(),
            query: None,
            headers,
            body: None,
        };

        assert_eq!(req.client_ip(), "1.2.3.4");
    }

    #[test]
    fn test_generic_response_json() {
        let resp = GenericResponse::json(200, &serde_json::json!({"ok": true}));
        assert_eq!(resp.status, 200);
        assert!(resp.headers.contains_key("content-type"));
        let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(body["ok"], true);
    }

    #[test]
    fn test_generic_response_redirect() {
        let resp = GenericResponse::redirect(302, "https://example.com/callback");
        assert_eq!(resp.status, 302);
        assert_eq!(
            resp.headers.get("location"),
            Some(&vec!["https://example.com/callback".to_string()])
        );
    }

    #[test]
    fn test_generic_response_error() {
        let resp = GenericResponse::error(401, "UNAUTHORIZED", "Not authenticated");
        assert_eq!(resp.status, 401);
        let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(body["error"]["code"], "UNAUTHORIZED");
        assert_eq!(body["error"]["message"], "Not authenticated");
    }

    #[test]
    fn test_generic_response_html() {
        let resp = GenericResponse::html(200, "<h1>Hello</h1>");
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.headers.get("content-type"),
            Some(&vec!["text/html; charset=utf-8".to_string()])
        );
        assert_eq!(String::from_utf8_lossy(&resp.body), "<h1>Hello</h1>");
    }

    #[test]
    fn test_strip_base_path() {
        assert_eq!(strip_base_path("/api/auth/sign-in/email", "/api/auth"), "/sign-in/email");
        assert_eq!(strip_base_path("/api/auth/session", "/api/auth"), "/session");
        assert_eq!(strip_base_path("/api/auth/callback/google", "/api/auth"), "/callback/google");
        assert_eq!(strip_base_path("/api/auth", "/api/auth"), "/");
        assert_eq!(strip_base_path("/other/path", "/api/auth"), "/other/path");
    }

    #[test]
    fn test_middleware_error_to_response() {
        let resp = middleware_error_to_response(middleware::MiddlewareError::Forbidden {
            code: "CSRF_FAILED",
            message: "CSRF check failed".to_string(),
        });
        assert_eq!(resp.status, 403);

        let resp = middleware_error_to_response(middleware::MiddlewareError::TooManyRequests {
            retry_after: 60,
            message: "Rate limit exceeded".to_string(),
        });
        assert_eq!(resp.status, 429);
        assert!(resp.headers.contains_key("x-retry-after"));
    }
}
