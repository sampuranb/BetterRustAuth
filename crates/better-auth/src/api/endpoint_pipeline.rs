// Endpoint pipeline — maps to packages/better-auth/src/api/to-auth-endpoints.ts
//
// Provides the before/after hook execution pipeline for endpoints.
// In TS, `toAuthEndpoints` wraps each endpoint handler with hooks from plugins.
// In Rust, we provide the same pipeline as composable functions that the
// Axum integration layer calls during request processing.

use std::collections::HashMap;
use std::sync::Arc;

use crate::context::AuthContext;
use crate::api::request_state::RequestStateStore;

/// Internal context passed through the endpoint pipeline.
///
/// Maps to the TS `InternalContext` type in to-auth-endpoints.ts.
/// Carries the auth context, request metadata, and mutable response state.
#[derive(Debug, Clone)]
pub struct InternalContext {
    /// The shared auth context.
    pub auth_context: Arc<AuthContext>,

    /// The path being handled (e.g., "/sign-in/email").
    pub path: String,

    /// Request headers.
    pub headers: HashMap<String, String>,

    /// Request body (JSON value, if any).
    pub body: Option<serde_json::Value>,

    /// Query parameters.
    pub query: Option<serde_json::Value>,

    /// Response headers accumulated by hooks and handlers.
    pub response_headers: HashMap<String, String>,

    /// The value returned by the endpoint handler (available to after hooks).
    pub returned: Option<serde_json::Value>,

    /// Per-request state store.
    pub request_state: RequestStateStore,

    /// Current session data (if authenticated).
    pub session: Option<serde_json::Value>,
}

impl InternalContext {
    /// Create a new internal context for a request.
    pub fn new(
        auth_context: Arc<AuthContext>,
        path: String,
        headers: HashMap<String, String>,
    ) -> Self {
        Self {
            auth_context,
            path,
            headers,
            body: None,
            query: None,
            response_headers: HashMap::new(),
            returned: None,
            request_state: RequestStateStore::new(),
            session: None,
        }
    }

    /// Set the request body.
    pub fn with_body(mut self, body: serde_json::Value) -> Self {
        self.body = Some(body);
        self
    }

    /// Set the query parameters.
    pub fn with_query(mut self, query: serde_json::Value) -> Self {
        self.query = Some(query);
        self
    }

    /// Add a response header.
    pub fn add_response_header(&mut self, key: String, value: String) {
        self.response_headers.insert(key, value);
    }
}

/// A hook entry for before/after processing.
///
/// Maps to the TS hooks structure with `matcher` and `handler`.
pub struct HookEntry {
    /// The originating plugin ID.
    pub plugin_id: String,

    /// Matcher function — determines if this hook applies to the given context.
    pub matcher: Box<dyn Fn(&InternalContext) -> bool + Send + Sync>,

    /// Handler function — executes the hook logic.
    /// Returns `Ok(HookResult)` on success, or `Err` to abort.
    pub handler: Box<dyn Fn(&mut InternalContext) -> HookHandlerFuture + Send + Sync>,
}

/// The future type returned by hook handlers.
pub type HookHandlerFuture = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<HookResult, HookError>> + Send>,
>;

/// Result from a before hook.
#[derive(Debug, Clone)]
pub enum HookResult {
    /// Continue processing with potentially modified context.
    Continue,

    /// Continue with context modifications merged.
    ContinueWithContext(ContextModification),

    /// Short-circuit: return this response immediately.
    Response(serde_json::Value),
}

/// Context modifications from a before hook.
#[derive(Debug, Clone, Default)]
pub struct ContextModification {
    /// Additional headers to merge.
    pub headers: Option<HashMap<String, String>>,

    /// Body overrides.
    pub body: Option<serde_json::Value>,

    /// Extra response headers.
    pub response_headers: Option<HashMap<String, String>>,
}

/// Error from a hook.
#[derive(Debug, Clone)]
pub struct HookError {
    pub message: String,
    pub code: Option<String>,
    pub status: Option<u16>,
}

impl std::fmt::Display for HookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HookError: {}", self.message)
    }
}

impl std::error::Error for HookError {}

impl std::fmt::Debug for HookEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookEntry")
            .field("plugin_id", &self.plugin_id)
            .finish()
    }
}

/// The endpoint pipeline manages before/after hooks for endpoint execution.
///
/// Maps to the TS `toAuthEndpoints` wrapper logic.
pub struct EndpointPipeline {
    /// Before hooks: run before the endpoint handler.
    pub before_hooks: Vec<HookEntry>,

    /// After hooks: run after the endpoint handler.
    pub after_hooks: Vec<HookEntry>,
}

impl EndpointPipeline {
    /// Create a new empty pipeline.
    pub fn new() -> Self {
        Self {
            before_hooks: Vec::new(),
            after_hooks: Vec::new(),
        }
    }

    /// Add a before hook.
    pub fn add_before_hook(&mut self, hook: HookEntry) {
        self.before_hooks.push(hook);
    }

    /// Add an after hook.
    pub fn add_after_hook(&mut self, hook: HookEntry) {
        self.after_hooks.push(hook);
    }
}

impl Default for EndpointPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for EndpointPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointPipeline")
            .field("before_hooks", &self.before_hooks.len())
            .field("after_hooks", &self.after_hooks.len())
            .finish()
    }
}

/// Run all matching before hooks for the given context.
///
/// Maps to TS `runBeforeHooks`.
///
/// Returns:
/// - `Ok(None)` — continue to the handler with the (potentially modified) context
/// - `Ok(Some(value))` — short-circuit with this response
/// - `Err(HookError)` — abort with this error
pub async fn run_before_hooks(
    context: &mut InternalContext,
    hooks: &[HookEntry],
) -> Result<Option<serde_json::Value>, HookError> {
    for hook in hooks {
        let matched = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            (hook.matcher)(context)
        })) {
            Ok(m) => m,
            Err(_) => {
                // Matcher panicked — skip this hook (matches TS behavior)
                continue;
            }
        };

        if !matched {
            continue;
        }

        let result = (hook.handler)(context).await?;

        match result {
            HookResult::Continue => {}
            HookResult::ContinueWithContext(mods) => {
                // Merge context modifications
                if let Some(headers) = mods.headers {
                    context.headers.extend(headers);
                }
                if let Some(body) = mods.body {
                    context.body = Some(body);
                }
                if let Some(resp_headers) = mods.response_headers {
                    context.response_headers.extend(resp_headers);
                }
            }
            HookResult::Response(value) => {
                return Ok(Some(value));
            }
        }
    }

    Ok(None)
}

/// Run all matching after hooks for the given context.
///
/// Maps to TS `runAfterHooks`.
///
/// After hooks can modify the response and headers.
///
/// Returns the final (potentially modified) response and headers.
pub async fn run_after_hooks(
    context: &mut InternalContext,
    hooks: &[HookEntry],
) -> Result<AfterHookResult, HookError> {
    for hook in hooks {
        let matched = (hook.matcher)(context);
        if !matched {
            continue;
        }

        let result = (hook.handler)(context).await;
        match result {
            Ok(HookResult::Response(value)) => {
                context.returned = Some(value);
            }
            Ok(HookResult::ContinueWithContext(mods)) => {
                if let Some(resp_headers) = mods.response_headers {
                    context.response_headers.extend(resp_headers);
                }
            }
            Ok(HookResult::Continue) => {}
            Err(e) => {
                // After hook errors are logged but don't abort (matches TS)
                tracing::warn!(
                    "After hook error from plugin '{}': {}",
                    hook.plugin_id, e.message
                );
            }
        }
    }

    Ok(AfterHookResult {
        response: context.returned.clone(),
        headers: context.response_headers.clone(),
    })
}

/// Result from after hook processing.
#[derive(Debug, Clone)]
pub struct AfterHookResult {
    /// The final response value.
    pub response: Option<serde_json::Value>,

    /// Accumulated response headers.
    pub headers: HashMap<String, String>,
}

/// Build hooks from the plugin registry's middleware/hooks.
///
/// Maps to the TS `getHooks` in `to-auth-endpoints.ts`.
///
/// Collects middleware descriptors from all registered plugins and converts
/// them into before/after hook entries that the endpoint pipeline executes
/// on matching requests. In the TS version, plugins declare `hooks.before`
/// and `hooks.after` arrays with `{ matcher, handler }` entries. Here we
/// use the `PluginMiddleware` descriptors (which carry path patterns) and
/// also the `on_request` / `on_response` plugin trait methods.
pub fn get_hooks(
    registry: &crate::plugin_runtime::PluginRegistry,
) -> (Vec<HookEntry>, Vec<HookEntry>) {
    let mut before_hooks: Vec<HookEntry> = Vec::new();
    let mut after_hooks: Vec<HookEntry> = Vec::new();

    // 1. Collect middleware descriptors as before hooks.
    //    Each PluginMiddleware has a list of paths it applies to.
    //    An empty `paths` list means "match all requests" (global middleware).
    for mw in registry.middlewares() {
        let paths = mw.paths.clone();
        let plugin_id = mw.id.clone();

        before_hooks.push(HookEntry {
            plugin_id: plugin_id.clone(),
            matcher: Box::new(move |ctx: &InternalContext| {
                if paths.is_empty() {
                    // Global middleware — matches everything
                    return true;
                }
                // Path-based matching: check if the request path starts with
                // any of the middleware's declared paths.
                paths.iter().any(|p| ctx.path.starts_with(p) || ctx.path == *p)
            }),
            handler: Box::new(move |_ctx: &mut InternalContext| {
                // Middleware descriptors act as markers — their actual logic
                // is dispatched via the plugin's `on_request` trait method.
                // The handler here is a no-op pass-through; the plugin's
                // on_request is called separately in the request pipeline.
                Box::pin(async { Ok(HookResult::Continue) })
            }),
        });
    }

    // 2. Wire up plugin on_request hooks as before hooks.
    //    Each plugin's `on_request` method is called for every request.
    //    This matches the TS pattern where plugin hooks run on all endpoints.
    for plugin in registry.plugins() {
        let plugin_arc = plugin.clone();
        let plugin_id = plugin.id().to_string();

        before_hooks.push(HookEntry {
            plugin_id: plugin_id.clone(),
            matcher: Box::new(|_ctx: &InternalContext| {
                // Plugin on_request hooks run on all requests (global)
                true
            }),
            handler: Box::new(move |ctx: &mut InternalContext| {
                let plugin = plugin_arc.clone();
                let method_str = ctx.headers.get("x-method")
                    .cloned()
                    .unwrap_or_else(|| "GET".to_string());
                let method = match method_str.as_str() {
                    "POST" => better_auth_core::plugin::HttpMethod::Post,
                    "PUT" => better_auth_core::plugin::HttpMethod::Put,
                    "DELETE" => better_auth_core::plugin::HttpMethod::Delete,
                    "PATCH" => better_auth_core::plugin::HttpMethod::Patch,
                    _ => better_auth_core::plugin::HttpMethod::Get,
                };
                let request = better_auth_core::plugin::PluginRequest {
                    method,
                    path: ctx.path.clone(),
                    headers: ctx.headers.clone(),
                };
                Box::pin(async move {
                    match plugin.on_request(&request).await {
                        Ok(()) => Ok(HookResult::Continue),
                        Err(e) => Err(HookError {
                            message: e.to_string(),
                            code: Some("PLUGIN_HOOK_ERROR".into()),
                            status: Some(500),
                        }),
                    }
                })
            }),
        });

        // 3. Wire up plugin on_response hooks as after hooks.
        let plugin_arc2 = plugin.clone();
        let plugin_id2 = plugin.id().to_string();

        after_hooks.push(HookEntry {
            plugin_id: plugin_id2,
            matcher: Box::new(|_ctx: &InternalContext| true),
            handler: Box::new(move |ctx: &mut InternalContext| {
                let plugin = plugin_arc2.clone();
                let response_headers = ctx.response_headers.clone();
                let returned = ctx.returned.clone();
                Box::pin(async move {
                    let mut plugin_response = better_auth_core::plugin::PluginResponse {
                        status: 200,
                        headers: response_headers,
                        body: returned,
                    };
                    match plugin.on_response(&mut plugin_response).await {
                        Ok(()) => {
                            // If the plugin modified the response, propagate changes
                            if let Some(ref body) = plugin_response.body {
                                Ok(HookResult::Response(body.clone()))
                            } else {
                                Ok(HookResult::Continue)
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Plugin on_response error: {}", e);
                            Ok(HookResult::Continue)
                        }
                    }
                })
            }),
        });
    }

    (before_hooks, after_hooks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal_adapter::tests::MockInternalAdapter;

    fn make_test_context() -> InternalContext {
        let options = better_auth_core::options::BetterAuthOptions::new(
            "test-secret-that-is-long-enough-32",
        );
        let adapter = Arc::new(MockInternalAdapter);
        let auth_ctx = AuthContext::new(options, adapter);

        InternalContext::new(
            auth_ctx,
            "/test".into(),
            HashMap::new(),
        )
    }

    #[tokio::test]
    async fn test_run_before_hooks_empty() {
        let mut ctx = make_test_context();
        let result = run_before_hooks(&mut ctx, &[]).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_run_before_hooks_continue() {
        let mut ctx = make_test_context();
        let hooks = vec![HookEntry {
            plugin_id: "test".into(),
            matcher: Box::new(|_| true),
            handler: Box::new(|_ctx| {
                Box::pin(async { Ok(HookResult::Continue) })
            }),
        }];

        let result = run_before_hooks(&mut ctx, &hooks).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_run_before_hooks_short_circuit() {
        let mut ctx = make_test_context();
        let hooks = vec![HookEntry {
            plugin_id: "test".into(),
            matcher: Box::new(|_| true),
            handler: Box::new(|_ctx| {
                Box::pin(async {
                    Ok(HookResult::Response(serde_json::json!({"blocked": true})))
                })
            }),
        }];

        let result = run_before_hooks(&mut ctx, &hooks).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap()["blocked"], true);
    }

    #[tokio::test]
    async fn test_run_before_hooks_context_modification() {
        let mut ctx = make_test_context();
        let hooks = vec![HookEntry {
            plugin_id: "test".into(),
            matcher: Box::new(|_| true),
            handler: Box::new(|_ctx| {
                Box::pin(async {
                    let mut headers = HashMap::new();
                    headers.insert("X-Custom".into(), "value".into());
                    Ok(HookResult::ContinueWithContext(ContextModification {
                        headers: Some(headers),
                        body: None,
                        response_headers: None,
                    }))
                })
            }),
        }];

        let result = run_before_hooks(&mut ctx, &hooks).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        assert_eq!(ctx.headers.get("X-Custom").unwrap(), "value");
    }

    #[tokio::test]
    async fn test_run_before_hooks_unmatched() {
        let mut ctx = make_test_context();
        let hooks = vec![HookEntry {
            plugin_id: "test".into(),
            matcher: Box::new(|ctx| ctx.path.starts_with("/admin")),
            handler: Box::new(|_ctx| {
                Box::pin(async { Ok(HookResult::Response(serde_json::json!({"admin": true}))) })
            }),
        }];

        let result = run_before_hooks(&mut ctx, &hooks).await.unwrap();
        // Should not match since path is "/test"
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_run_before_hooks_error() {
        let mut ctx = make_test_context();
        let hooks = vec![HookEntry {
            plugin_id: "test".into(),
            matcher: Box::new(|_| true),
            handler: Box::new(|_ctx| {
                Box::pin(async {
                    Err(HookError {
                        message: "forbidden".into(),
                        code: Some("FORBIDDEN".into()),
                        status: Some(403),
                    })
                })
            }),
        }];

        let result = run_before_hooks(&mut ctx, &hooks).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.message, "forbidden");
        assert_eq!(err.status, Some(403));
    }

    #[tokio::test]
    async fn test_run_after_hooks_modify_response() {
        let mut ctx = make_test_context();
        ctx.returned = Some(serde_json::json!({"original": true}));

        let hooks = vec![HookEntry {
            plugin_id: "test".into(),
            matcher: Box::new(|_| true),
            handler: Box::new(|_ctx| {
                Box::pin(async {
                    Ok(HookResult::Response(serde_json::json!({"modified": true})))
                })
            }),
        }];

        let result = run_after_hooks(&mut ctx, &hooks).await.unwrap();
        assert_eq!(result.response.unwrap()["modified"], true);
    }

    #[tokio::test]
    async fn test_run_after_hooks_add_headers() {
        let mut ctx = make_test_context();

        let hooks = vec![HookEntry {
            plugin_id: "test".into(),
            matcher: Box::new(|_| true),
            handler: Box::new(|_ctx| {
                Box::pin(async {
                    let mut headers = HashMap::new();
                    headers.insert("X-After".into(), "hook-value".into());
                    Ok(HookResult::ContinueWithContext(ContextModification {
                        headers: None,
                        body: None,
                        response_headers: Some(headers),
                    }))
                })
            }),
        }];

        let result = run_after_hooks(&mut ctx, &hooks).await.unwrap();
        assert_eq!(result.headers.get("X-After").unwrap(), "hook-value");
    }

    #[test]
    fn test_pipeline_creation() {
        let mut pipeline = EndpointPipeline::new();
        pipeline.add_before_hook(HookEntry {
            plugin_id: "test".into(),
            matcher: Box::new(|_| true),
            handler: Box::new(|_| Box::pin(async { Ok(HookResult::Continue) })),
        });
        pipeline.add_after_hook(HookEntry {
            plugin_id: "test".into(),
            matcher: Box::new(|_| true),
            handler: Box::new(|_| Box::pin(async { Ok(HookResult::Continue) })),
        });

        assert_eq!(pipeline.before_hooks.len(), 1);
        assert_eq!(pipeline.after_hooks.len(), 1);
    }
}
