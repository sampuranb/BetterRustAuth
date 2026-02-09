//! Client-side plugin system.
//!
//! Maps to the TS `BetterAuthClientPlugin` interface from `@better-auth/core`.
//! Each plugin declares an `id`, optional `path_methods` overrides, and
//! provides typed accessor methods that call the underlying HTTP endpoints.
//!
//! ## TS Parity
//! - `BetterAuthClientPlugin.id` → `ClientPlugin::id()`
//! - `BetterAuthClientPlugin.pathMethods` → `ClientPlugin::path_methods()`
//! - `BetterAuthClientPlugin.atomListeners` → `ClientPlugin::session_signals()` (Rust equivalent)
//! - `BetterAuthClientPlugin.getActions` → typed methods on each plugin struct

use std::collections::HashMap;

/// HTTP method override for a specific path.
///
/// Maps to TS `pathMethods` in `BetterAuthClientPlugin`.
/// Some plugin endpoints need explicit method declarations because the
/// proxy-based TS client can't always infer them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Patch => write!(f, "PATCH"),
            HttpMethod::Delete => write!(f, "DELETE"),
        }
    }
}

/// Paths that should trigger a session signal refresh.
///
/// Maps to TS `atomListeners` in `BetterAuthClientPlugin`.
/// When a request is made to a path that matches, the session cache is
/// invalidated so the next `get_session()` call re-fetches.
#[derive(Debug, Clone)]
pub struct SessionSignal {
    /// Paths or path prefixes that trigger this signal.
    pub paths: Vec<String>,
    /// If true, matches any path that starts with the given prefix.
    pub prefix_match: bool,
}

/// Trait for client-side plugins.
///
/// Each plugin provides:
/// - A unique `id` for identification
/// - Optional `path_methods` for HTTP method overrides
/// - Optional `session_signals` for cache invalidation triggers
///
/// Plugin-specific typed methods are implemented directly on the plugin
/// struct and accept a reference to `BetterAuthClient` for making requests.
pub trait ClientPlugin: Send + Sync {
    /// Unique plugin identifier.
    /// Maps to TS `BetterAuthClientPlugin.id`.
    fn id(&self) -> &str;

    /// HTTP method overrides for specific paths.
    /// Maps to TS `BetterAuthClientPlugin.pathMethods`.
    fn path_methods(&self) -> HashMap<String, HttpMethod> {
        HashMap::new()
    }

    /// Paths that should trigger session cache invalidation when called.
    /// Maps to TS `BetterAuthClientPlugin.atomListeners`.
    fn session_signals(&self) -> Vec<SessionSignal> {
        Vec::new()
    }
}

/// Registry of installed client plugins.
///
/// Aggregates path method overrides and session signals from all plugins.
#[derive(Debug, Default)]
pub struct PluginRegistry {
    /// Combined path → method overrides from all plugins.
    pub path_methods: HashMap<String, HttpMethod>,
    /// Combined session signals from all plugins.
    pub session_signals: Vec<SessionSignal>,
    /// Plugin IDs (for diagnostics).
    pub plugin_ids: Vec<String>,
}

impl PluginRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a plugin, merging its path methods and session signals.
    pub fn register(&mut self, plugin: &dyn ClientPlugin) {
        self.plugin_ids.push(plugin.id().to_string());
        self.path_methods.extend(plugin.path_methods());
        self.session_signals.extend(plugin.session_signals());
    }

    /// Check if a path should trigger a session cache invalidation.
    pub fn should_invalidate_session(&self, path: &str) -> bool {
        self.session_signals.iter().any(|signal| {
            signal.paths.iter().any(|p| {
                if signal.prefix_match {
                    path.starts_with(p)
                } else {
                    path == p
                }
            })
        })
    }

    /// Get the HTTP method for a path, if overridden by a plugin.
    pub fn get_method(&self, path: &str) -> Option<HttpMethod> {
        self.path_methods.get(path).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestPlugin;

    impl ClientPlugin for TestPlugin {
        fn id(&self) -> &str {
            "test-plugin"
        }

        fn path_methods(&self) -> HashMap<String, HttpMethod> {
            let mut m = HashMap::new();
            m.insert("/test/action".to_string(), HttpMethod::Post);
            m
        }

        fn session_signals(&self) -> Vec<SessionSignal> {
            vec![SessionSignal {
                paths: vec!["/test/".to_string()],
                prefix_match: true,
            }]
        }
    }

    #[test]
    fn test_plugin_registry() {
        let mut registry = PluginRegistry::new();
        let plugin = TestPlugin;
        registry.register(&plugin);

        assert_eq!(registry.plugin_ids, vec!["test-plugin"]);
        assert_eq!(
            registry.get_method("/test/action"),
            Some(HttpMethod::Post)
        );
        assert!(registry.should_invalidate_session("/test/foo"));
        assert!(!registry.should_invalidate_session("/other/foo"));
    }

    #[test]
    fn test_http_method_display() {
        assert_eq!(format!("{}", HttpMethod::Get), "GET");
        assert_eq!(format!("{}", HttpMethod::Post), "POST");
        assert_eq!(format!("{}", HttpMethod::Put), "PUT");
        assert_eq!(format!("{}", HttpMethod::Patch), "PATCH");
        assert_eq!(format!("{}", HttpMethod::Delete), "DELETE");
    }
}
