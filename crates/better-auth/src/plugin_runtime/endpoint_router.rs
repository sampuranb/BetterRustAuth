// Plugin endpoint router — dynamically registers plugin endpoints in Axum.
//
// Maps to: packages/core/src/api/index.ts endpoint registration
//
// Since plugins declare endpoints as descriptors (path + method), this module
// provides the glue to register them as Axum routes with a generic handler
// that dispatches to the appropriate plugin.

use std::collections::HashMap;
use std::sync::Arc;

use better_auth_core::plugin::{
    BetterAuthPlugin, HttpMethod, PluginEndpoint, PluginRequest,
};

use super::registry::PluginRegistry;

/// Collect all plugin endpoint paths grouped by HTTP method.
///
/// This is used by the Axum router builder to know which routes to register.
/// Returns a map keyed by (method, path) for deduplication.
pub fn collect_endpoint_routes(
    registry: &PluginRegistry,
) -> HashMap<(HttpMethod, String), EndpointInfo> {
    let mut routes = HashMap::new();

    for plugin in registry.plugins() {
        for endpoint in plugin.endpoints() {
            let key = (endpoint.method, endpoint.path.clone());
            routes.entry(key).or_insert(EndpointInfo {
                plugin_id: plugin.id().to_string(),
                endpoint: endpoint.clone(),
            });
        }
    }

    routes
}

/// Info about a registered endpoint for routing.
#[derive(Debug, Clone)]
pub struct EndpointInfo {
    pub plugin_id: String,
    pub endpoint: PluginEndpoint,
}

/// Dispatch a request to the appropriate plugin's `on_request` hook.
///
/// This is a generic request handler that can be used as the body of
/// a catch-all Axum handler for plugin endpoints.
pub async fn dispatch_plugin_request(
    registry: &PluginRegistry,
    plugin_id: &str,
    method: HttpMethod,
    path: &str,
    headers: HashMap<String, String>,
) -> Result<(), better_auth_core::error::BetterAuthError> {
    let plugin = registry
        .get_plugin(plugin_id)
        .ok_or_else(|| {
            better_auth_core::error::BetterAuthError::Plugin(
                format!("Plugin '{}' not found", plugin_id),
            )
        })?;

    let request = PluginRequest {
        method,
        path: path.to_string(),
        headers,
    };

    plugin.on_request(&request).await
}

/// Get the set of paths that require authentication from plugin endpoints.
///
/// Returns the set of paths where the Axum middleware should enforce
/// session validation before passing to the handler.
pub fn auth_required_paths(registry: &PluginRegistry) -> Vec<String> {
    registry
        .auth_endpoints()
        .iter()
        .map(|e| e.path.clone())
        .collect()
}

/// Merge plugin rate limit rules into the rate limiter configuration.
///
/// This should be called during AuthContext initialization to inject
/// plugin-specific rate limits into the global rate limiter.
pub fn merge_plugin_rate_limits(
    registry: &PluginRegistry,
) -> HashMap<String, crate::middleware::rate_limiter::RateLimitRule> {
    let mut rules = HashMap::new();

    for rl in registry.rate_limits() {
        rules.insert(
            rl.path.clone(),
            crate::middleware::rate_limiter::RateLimitRule {
                window: rl.window,
                max: rl.max,
            },
        );
    }

    rules
}

/// Dispatch an incoming request to the matching plugin handler.
///
/// Looks up the endpoint by (path, method) in the registry's collected endpoints,
/// then calls the handler function if present. Returns `None` if no handler is
/// registered for this path+method combination.
pub async fn dispatch_to_handler(
    registry: &PluginRegistry,
    ctx: Arc<dyn std::any::Any + Send + Sync>,
    method: HttpMethod,
    path: &str,
    request: better_auth_core::plugin::PluginHandlerRequest,
) -> Option<better_auth_core::plugin::PluginHandlerResponse> {
    // Find the matching endpoint
    for endpoint in registry.endpoints() {
        if endpoint.path == path && endpoint.method == method {
            if let Some(ref handler) = endpoint.handler {
                let response = handler(ctx, request).await;
                return Some(response);
            }
            // Endpoint found but no handler registered
            return None;
        }
    }
    None
}

/// Check if a plugin endpoint exists for the given path and method.
pub fn has_plugin_endpoint(
    registry: &PluginRegistry,
    method: HttpMethod,
    path: &str,
) -> bool {
    registry.endpoints().iter().any(|e| e.path == path && e.method == method)
}

/// Check if a plugin endpoint requires authentication.
pub fn endpoint_requires_auth(
    registry: &PluginRegistry,
    method: HttpMethod,
    path: &str,
) -> bool {
    registry.endpoints().iter()
        .find(|e| e.path == path && e.method == method)
        .map(|e| e.require_auth)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::db::schema::SchemaField;

    #[derive(Debug)]
    struct RouterTestPlugin;

    #[async_trait::async_trait]
    impl BetterAuthPlugin for RouterTestPlugin {
        fn id(&self) -> &str {
            "test-router"
        }

        fn endpoints(&self) -> Vec<PluginEndpoint> {
            vec![
                PluginEndpoint {
                    path: "/test/action".into(),
                    method: HttpMethod::Post,
                    require_auth: true,
                    metadata: HashMap::new(),
                    handler: None,
                },
                PluginEndpoint {
                    path: "/test/public".into(),
                    method: HttpMethod::Get,
                    require_auth: false,
                    metadata: HashMap::new(),
                    handler: None,
                },
            ]
        }

        fn rate_limit(&self) -> Vec<better_auth_core::plugin::PluginRateLimit> {
            vec![better_auth_core::plugin::PluginRateLimit {
                path: "/test".into(),
                window: 30,
                max: 5,
            }]
        }
    }

    #[test]
    fn test_collect_endpoint_routes() {
        let plugins: Vec<Arc<dyn BetterAuthPlugin>> = vec![Arc::new(RouterTestPlugin)];
        let reg = PluginRegistry::from_plugins(plugins);
        let routes = collect_endpoint_routes(&reg);

        assert_eq!(routes.len(), 2);
        assert!(routes.contains_key(&(HttpMethod::Post, "/test/action".into())));
        assert!(routes.contains_key(&(HttpMethod::Get, "/test/public".into())));
    }

    #[test]
    fn test_auth_required_paths() {
        let plugins: Vec<Arc<dyn BetterAuthPlugin>> = vec![Arc::new(RouterTestPlugin)];
        let reg = PluginRegistry::from_plugins(plugins);
        let paths = auth_required_paths(&reg);

        assert_eq!(paths.len(), 1);
        assert!(paths.contains(&"/test/action".to_string()));
    }

    #[test]
    fn test_merge_plugin_rate_limits() {
        let plugins: Vec<Arc<dyn BetterAuthPlugin>> = vec![Arc::new(RouterTestPlugin)];
        let reg = PluginRegistry::from_plugins(plugins);
        let rules = merge_plugin_rate_limits(&reg);

        assert_eq!(rules.len(), 1);
        let rule = rules.get("/test").unwrap();
        assert_eq!(rule.window, 30);
        assert_eq!(rule.max, 5);
    }
}
