// Endpoint conflict detection — maps to packages/better-auth/src/api/index.ts checkEndpointConflicts
//
// Detects when multiple plugins attempt to register endpoints on the same
// path with overlapping HTTP methods. Reports conflicts as warnings.

use std::collections::HashMap;

use crate::plugin_runtime::PluginRegistry;
use better_auth_core::plugin::HttpMethod;

/// A detected endpoint conflict between plugins.
#[derive(Debug, Clone)]
pub struct EndpointConflict {
    /// The path where the conflict occurs.
    pub path: String,
    /// The HTTP methods that overlap.
    pub methods: Vec<HttpMethod>,
    /// The plugin IDs that conflict.
    pub plugin_ids: Vec<String>,
    /// The endpoint keys from each plugin.
    pub endpoint_keys: Vec<String>,
}

/// Check for endpoint conflicts across all plugins.
///
/// Maps to TS `checkEndpointConflicts(options, logger)`.
///
/// This detects when multiple plugins register endpoints on the same
/// path with overlapping HTTP methods. Returns a list of conflicts
/// for the caller to log or handle.
pub fn check_endpoint_conflicts(
    registry: &PluginRegistry,
) -> Vec<EndpointConflict> {
    // Build a registry: path -> Vec<{ plugin_id, method }>
    let mut path_registry: HashMap<String, Vec<(String, HttpMethod, String)>> = HashMap::new();

    for plugin in registry.plugins() {
        let plugin_id = plugin.id().to_string();
        for endpoint in plugin.endpoints() {
            let entry = (
                plugin_id.clone(),
                endpoint.method,
                format!("{}:{}", plugin_id, endpoint.path),
            );
            path_registry
                .entry(endpoint.path.clone())
                .or_default()
                .push(entry);
        }
    }

    let mut conflicts = Vec::new();

    for (path, registrations) in &path_registry {
        if registrations.len() <= 1 {
            continue;
        }

        // Check for method overlaps
        let mut method_to_plugins: HashMap<HttpMethod, Vec<(String, String)>> = HashMap::new();
        for (plugin_id, method, key) in registrations {
            method_to_plugins
                .entry(*method)
                .or_default()
                .push((plugin_id.clone(), key.clone()));
        }

        for (method, plugins) in &method_to_plugins {
            if plugins.len() > 1 {
                conflicts.push(EndpointConflict {
                    path: path.clone(),
                    methods: vec![*method],
                    plugin_ids: plugins.iter().map(|(id, _)| id.clone()).collect(),
                    endpoint_keys: plugins.iter().map(|(_, key)| key.clone()).collect(),
                });
            }
        }
    }

    conflicts
}

/// Format conflict warnings for logging.
///
/// Returns a Vec of human-readable warning messages.
pub fn format_conflict_warnings(conflicts: &[EndpointConflict]) -> Vec<String> {
    conflicts
        .iter()
        .map(|c| {
            let method_str: Vec<String> = c.methods.iter().map(|m| format!("{:?}", m)).collect();
            format!(
                "Endpoint conflict at '{}' [{methods}]: plugins {plugins} both register this endpoint. \
                 This may cause unexpected behavior.",
                c.path,
                methods = method_str.join(", "),
                plugins = c.plugin_ids.join(", "),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::plugin::{BetterAuthPlugin, PluginEndpoint};
    use std::collections::HashMap;
    use std::sync::Arc;

    #[derive(Debug)]
    struct ConflictPluginA;

    #[async_trait::async_trait]
    impl BetterAuthPlugin for ConflictPluginA {
        fn id(&self) -> &str {
            "plugin-a"
        }

        fn endpoints(&self) -> Vec<PluginEndpoint> {
            vec![
                PluginEndpoint {
                    path: "/shared-path".into(),
                    method: HttpMethod::Post,
                    require_auth: false,
                    metadata: HashMap::new(),
                    handler: None,
                },
            ]
        }
    }

    #[derive(Debug)]
    struct ConflictPluginB;

    #[async_trait::async_trait]
    impl BetterAuthPlugin for ConflictPluginB {
        fn id(&self) -> &str {
            "plugin-b"
        }

        fn endpoints(&self) -> Vec<PluginEndpoint> {
            vec![
                PluginEndpoint {
                    path: "/shared-path".into(),
                    method: HttpMethod::Post,
                    require_auth: false,
                    metadata: HashMap::new(),
                    handler: None,
                },
            ]
        }
    }

    #[derive(Debug)]
    struct NoConflictPlugin;

    #[async_trait::async_trait]
    impl BetterAuthPlugin for NoConflictPlugin {
        fn id(&self) -> &str {
            "no-conflict"
        }

        fn endpoints(&self) -> Vec<PluginEndpoint> {
            vec![
                PluginEndpoint {
                    path: "/unique-path".into(),
                    method: HttpMethod::Get,
                    require_auth: false,
                    metadata: HashMap::new(),
                    handler: None,
                },
            ]
        }
    }

    #[test]
    fn test_detects_conflicts() {
        let plugins: Vec<Arc<dyn BetterAuthPlugin>> = vec![
            Arc::new(ConflictPluginA),
            Arc::new(ConflictPluginB),
        ];
        let reg = PluginRegistry::from_plugins(plugins);
        let conflicts = check_endpoint_conflicts(&reg);

        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].path, "/shared-path");
        assert!(conflicts[0].plugin_ids.contains(&"plugin-a".to_string()));
        assert!(conflicts[0].plugin_ids.contains(&"plugin-b".to_string()));
    }

    #[test]
    fn test_no_conflicts() {
        let plugins: Vec<Arc<dyn BetterAuthPlugin>> = vec![
            Arc::new(ConflictPluginA),
            Arc::new(NoConflictPlugin),
        ];
        let reg = PluginRegistry::from_plugins(plugins);
        let conflicts = check_endpoint_conflicts(&reg);

        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_different_methods_no_conflict() {
        #[derive(Debug)]
        struct GetPlugin;

        #[async_trait::async_trait]
        impl BetterAuthPlugin for GetPlugin {
            fn id(&self) -> &str { "get-plugin" }
            fn endpoints(&self) -> Vec<PluginEndpoint> {
                vec![PluginEndpoint {
                    path: "/shared".into(),
                    method: HttpMethod::Get,
                    require_auth: false,
                    metadata: HashMap::new(),
                    handler: None,
                }]
            }
        }

        #[derive(Debug)]
        struct PostPlugin;

        #[async_trait::async_trait]
        impl BetterAuthPlugin for PostPlugin {
            fn id(&self) -> &str { "post-plugin" }
            fn endpoints(&self) -> Vec<PluginEndpoint> {
                vec![PluginEndpoint {
                    path: "/shared".into(),
                    method: HttpMethod::Post,
                    require_auth: false,
                    metadata: HashMap::new(),
                    handler: None,
                }]
            }
        }

        let plugins: Vec<Arc<dyn BetterAuthPlugin>> = vec![
            Arc::new(GetPlugin),
            Arc::new(PostPlugin),
        ];
        let reg = PluginRegistry::from_plugins(plugins);
        let conflicts = check_endpoint_conflicts(&reg);

        // Same path but different methods should NOT conflict
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_format_warnings() {
        let conflicts = vec![EndpointConflict {
            path: "/test".into(),
            methods: vec![HttpMethod::Post],
            plugin_ids: vec!["a".into(), "b".into()],
            endpoint_keys: vec!["a:/test".into(), "b:/test".into()],
        }];
        let warnings = format_conflict_warnings(&conflicts);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("/test"));
        assert!(warnings[0].contains("a, b"));
    }

    #[test]
    fn test_empty_registry() {
        let reg = PluginRegistry::new();
        let conflicts = check_endpoint_conflicts(&reg);
        assert!(conflicts.is_empty());
    }
}
