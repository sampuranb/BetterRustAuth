// Plugin trait — defines the interface that all Better Auth plugins implement.
//
// Maps to: packages/core/src/types/plugin.ts + better-auth/src/types/plugin.ts
// Each plugin can add endpoints, middleware, schema fields, hooks, and error codes.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use crate::db::schema::AuthTable;
use crate::error::ErrorCode;

// ─── Plugin Handler Types ───────────────────────────────────────

/// The request context passed to a plugin handler.
#[derive(Debug, Clone)]
pub struct PluginHandlerRequest {
    /// The request body (JSON). Empty object `{}` for GET requests.
    pub body: Value,
    /// Query parameters as a JSON object.
    pub query: Value,
    /// HTTP headers.
    pub headers: HashMap<String, String>,
    /// The session token extracted from cookies/Authorization header, if any.
    pub session_token: Option<String>,
    /// The authenticated user session, if `require_auth` is true and auth succeeded.
    /// Contains `{ "user": {...}, "session": {...} }`.
    pub session: Option<Value>,
}

/// The response returned by a plugin handler.
#[derive(Debug, Clone)]
pub struct PluginHandlerResponse {
    /// HTTP status code (200, 201, 400, 404, etc.).
    pub status: u16,
    /// Response body (JSON).
    pub body: Value,
    /// Additional response headers to set.
    pub headers: HashMap<String, String>,
    /// Optional redirect URL (for OAuth flows etc.).
    pub redirect: Option<String>,
}

impl PluginHandlerResponse {
    /// Create a 200 OK response with a JSON body.
    pub fn ok(body: Value) -> Self {
        Self {
            status: 200,
            body,
            headers: HashMap::new(),
            redirect: None,
        }
    }

    /// Create a 201 Created response.
    pub fn created(body: Value) -> Self {
        Self {
            status: 201,
            body,
            headers: HashMap::new(),
            redirect: None,
        }
    }

    /// Create an error response.
    pub fn error(status: u16, code: &str, message: &str) -> Self {
        Self {
            status,
            body: serde_json::json!({
                "code": code,
                "message": message,
            }),
            headers: HashMap::new(),
            redirect: None,
        }
    }

    /// Create a redirect response.
    pub fn redirect_to(url: String) -> Self {
        Self {
            status: 302,
            body: Value::Null,
            headers: HashMap::new(),
            redirect: Some(url),
        }
    }
}

/// Type-erased async plugin handler function.
///
/// Takes an opaque auth context (`Arc<dyn Any + Send + Sync>` — actually `Arc<AuthContext>`)
/// and a `PluginHandlerRequest`, returns a `PluginHandlerResponse`.
///
/// We use `dyn Any` for the context to avoid a circular dependency between
/// `better-auth-core` (which defines PluginEndpoint) and `better-auth`
/// (which defines AuthContext).
pub type PluginHandlerFn = Arc<
    dyn Fn(
            Arc<dyn std::any::Any + Send + Sync>,
            PluginHandlerRequest,
        ) -> Pin<Box<dyn Future<Output = PluginHandlerResponse> + Send>>
        + Send
        + Sync,
>;

/// The core plugin trait. Every plugin must implement this.
///
/// Maps to the TypeScript `BetterAuthPlugin` interface which provides:
/// - `id`: Unique plugin identifier
/// - `endpoints`: Additional API routes
/// - `middlewares`: Route-level middleware
/// - `schema`: Additional tables or fields on existing tables
/// - `hooks`: Before/after hooks on model operations
/// - `init`: Plugin initialization
/// - `$ERROR_CODES`: Plugin-specific error codes
#[async_trait]
pub trait BetterAuthPlugin: Send + Sync + fmt::Debug {
    /// Unique identifier for this plugin (e.g., "two-factor", "admin", "organization").
    fn id(&self) -> &str;

    /// Human-readable plugin name.
    fn name(&self) -> &str {
        self.id()
    }

    /// Called during auth context initialization.
    /// Allows the plugin to perform setup, validate options, etc.
    async fn init(&self, _ctx: &PluginInitContext<'_>) -> Result<(), crate::error::BetterAuthError> {
        Ok(())
    }

    /// Additional database tables introduced by this plugin.
    /// Returns table definitions that will be merged into the auth schema.
    fn schema(&self) -> Vec<AuthTable> {
        Vec::new()
    }

    /// Additional fields to add to existing tables.
    /// Key is the table name (e.g., "user", "session"), value is the fields to add.
    fn additional_fields(&self) -> HashMap<String, HashMap<String, crate::db::schema::SchemaField>> {
        HashMap::new()
    }

    /// Additional API endpoints provided by this plugin.
    /// Each endpoint includes a handler function for processing requests.
    fn endpoints(&self) -> Vec<PluginEndpoint> {
        Vec::new()
    }

    /// Plugin-specific middleware applied to routes.
    fn middlewares(&self) -> Vec<PluginMiddleware> {
        Vec::new()
    }

    /// Model-level hooks (before/after create, update, delete).
    fn hooks(&self) -> Vec<PluginHook> {
        Vec::new()
    }

    /// Custom error codes introduced by this plugin.
    fn error_codes(&self) -> Vec<ErrorCode> {
        Vec::new()
    }

    /// Rate limit rules for plugin endpoints.
    fn rate_limit(&self) -> Vec<PluginRateLimit> {
        Vec::new()
    }

    /// Field name overrides for DB column mapping.
    fn field_mapping(&self) -> HashMap<String, HashMap<String, String>> {
        HashMap::new()
    }

    /// Hook called on every incoming request.
    async fn on_request(&self, _request: &PluginRequest) -> Result<(), crate::error::BetterAuthError> {
        Ok(())
    }

    /// Hook called before sending every response.
    async fn on_response(&self, _response: &mut PluginResponse) -> Result<(), crate::error::BetterAuthError> {
        Ok(())
    }
}

/// Context available during plugin initialization.
#[derive(Debug)]
pub struct PluginInitContext<'a> {
    /// The auth options (read-only).
    pub options: &'a crate::options::BetterAuthOptions,
}

/// An API endpoint provided by a plugin.
///
/// Contains both the route metadata (path, method, auth requirement) and
/// the actual handler function for processing requests.
pub struct PluginEndpoint {
    /// The route path (e.g., "/two-factor/verify").
    pub path: String,
    /// HTTP method (GET, POST, etc.).
    pub method: HttpMethod,
    /// Whether the endpoint requires authentication.
    pub require_auth: bool,
    /// Plugin-specific metadata.
    pub metadata: HashMap<String, Value>,
    /// The handler function. If `None`, the endpoint is metadata-only (for documentation).
    pub handler: Option<PluginHandlerFn>,
}

impl Clone for PluginEndpoint {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            method: self.method,
            require_auth: self.require_auth,
            metadata: self.metadata.clone(),
            handler: self.handler.clone(),
        }
    }
}

impl fmt::Debug for PluginEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PluginEndpoint")
            .field("path", &self.path)
            .field("method", &self.method)
            .field("require_auth", &self.require_auth)
            .field("handler", &self.handler.as_ref().map(|_| "<fn>"))
            .finish()
    }
}

impl PluginEndpoint {
    /// Create a new endpoint with metadata only (no handler).
    pub fn metadata_only(path: impl Into<String>, method: HttpMethod, require_auth: bool) -> Self {
        Self {
            path: path.into(),
            method,
            require_auth,
            metadata: HashMap::new(),
            handler: None,
        }
    }

    /// Create a new endpoint with a handler.
    pub fn with_handler(
        path: impl Into<String>,
        method: HttpMethod,
        require_auth: bool,
        handler: PluginHandlerFn,
    ) -> Self {
        Self {
            path: path.into(),
            method,
            require_auth,
            metadata: HashMap::new(),
            handler: Some(handler),
        }
    }
}

/// HTTP methods for plugin endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
}

/// A middleware provided by a plugin.
#[derive(Debug, Clone)]
pub struct PluginMiddleware {
    /// Which paths this middleware applies to (empty = all).
    pub paths: Vec<String>,
    /// Plugin-specific middleware identifier.
    pub id: String,
}

/// Model-level hook definition.
#[derive(Debug, Clone)]
pub struct PluginHook {
    /// The model this hook applies to (e.g., "user", "session").
    pub model: String,
    /// When the hook fires.
    pub timing: HookTiming,
    /// What operation triggers the hook.
    pub operation: HookOperation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookTiming {
    Before,
    After,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookOperation {
    Create,
    Update,
    Delete,
}

/// Rate limit configuration for a plugin endpoint.
#[derive(Debug, Clone)]
pub struct PluginRateLimit {
    pub path: String,
    pub window: u64,
    pub max: u64,
}

/// Simplified request object passed to plugin hooks.
#[derive(Debug)]
pub struct PluginRequest {
    pub method: HttpMethod,
    pub path: String,
    pub headers: HashMap<String, String>,
}

/// Simplified response object for plugin response hooks.
#[derive(Debug)]
pub struct PluginResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Option<Value>,
}
