// Plugin runtime — collects, initializes, and wires plugins.
//
// Maps to: packages/better-auth/src/context/helpers.ts runPluginInit +
//          packages/core/src/types/plugin.ts plugin integration
//
// The PluginRegistry is the runtime counterpart to the BetterAuthPlugin trait.
// It collects all enabled plugins, merges their schemas, endpoints, hooks,
// middleware rules, and rate limits into a unified runtime configuration.

use std::collections::HashMap;
use std::sync::Arc;

use better_auth_core::db::schema::{AuthTable, SchemaField};
use better_auth_core::plugin::{
    BetterAuthPlugin, PluginEndpoint, PluginHook, PluginMiddleware, PluginRateLimit,
};

/// The plugin registry holds all enabled plugins and their merged configuration.
///
/// Constructed once during `AuthContext` initialization. Shared immutably
/// across all request handlers via `Arc<AuthContext>`.
#[derive(Debug)]
pub struct PluginRegistry {
    /// All registered plugin instances (trait objects).
    plugins: Vec<Arc<dyn BetterAuthPlugin>>,

    /// Merged endpoint descriptors from all plugins.
    /// Key: path → endpoint descriptor.
    all_endpoints: Vec<PluginEndpoint>,

    /// Merged schema tables from all plugins.
    all_tables: Vec<AuthTable>,

    /// Merged additional fields from all plugins.
    /// Outer key: table name, inner key: field name.
    all_additional_fields: HashMap<String, HashMap<String, SchemaField>>,

    /// Merged hooks from all plugins.
    all_hooks: Vec<PluginHookEntry>,

    /// Merged middleware from all plugins.
    all_middlewares: Vec<PluginMiddleware>,

    /// Merged rate limit rules from all plugins.
    all_rate_limits: Vec<PluginRateLimit>,
}

/// A hook entry with the originating plugin ID for tracing.
#[derive(Debug, Clone)]
pub struct PluginHookEntry {
    pub plugin_id: String,
    pub hook: PluginHook,
}

impl PluginRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
            all_endpoints: Vec::new(),
            all_tables: Vec::new(),
            all_additional_fields: HashMap::new(),
            all_hooks: Vec::new(),
            all_middlewares: Vec::new(),
            all_rate_limits: Vec::new(),
        }
    }

    /// Create a registry from a list of plugins.
    ///
    /// This is the main constructor. It collects endpoints, schema, hooks,
    /// middleware, and rate limits from each plugin.
    pub fn from_plugins(plugins: Vec<Arc<dyn BetterAuthPlugin>>) -> Self {
        let mut registry = Self::new();

        for plugin in &plugins {
            // Collect endpoints
            registry.all_endpoints.extend(plugin.endpoints());

            // Collect schema tables
            registry.all_tables.extend(plugin.schema());

            // Merge additional fields
            for (table, fields) in plugin.additional_fields() {
                registry
                    .all_additional_fields
                    .entry(table)
                    .or_default()
                    .extend(fields);
            }

            // Collect hooks with plugin ID
            for hook in plugin.hooks() {
                registry.all_hooks.push(PluginHookEntry {
                    plugin_id: plugin.id().to_string(),
                    hook,
                });
            }

            // Collect middleware
            registry.all_middlewares.extend(plugin.middlewares());

            // Collect rate limits
            registry.all_rate_limits.extend(plugin.rate_limit());
        }

        registry.plugins = plugins;
        registry
    }

    /// Initialize all plugins.
    ///
    /// Matches TS `runPluginInit`: calls `plugin.init()` on each registered plugin.
    pub async fn init_all(
        &self,
        init_ctx: &better_auth_core::plugin::PluginInitContext,
    ) -> Result<(), better_auth_core::error::BetterAuthError> {
        for plugin in &self.plugins {
            plugin.init(init_ctx).await?;
        }
        Ok(())
    }

    // ─── Accessors ──────────────────────────────────────────────

    /// All registered plugins.
    pub fn plugins(&self) -> &[Arc<dyn BetterAuthPlugin>] {
        &self.plugins
    }

    /// Number of registered plugins.
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Check if a plugin is enabled by ID.
    ///
    /// Mirrors TS `ctx.hasPlugin(id)`.
    pub fn has_plugin(&self, id: &str) -> bool {
        self.plugins.iter().any(|p| p.id() == id)
    }

    /// Get a plugin by ID.
    pub fn get_plugin(&self, id: &str) -> Option<&Arc<dyn BetterAuthPlugin>> {
        self.plugins.iter().find(|p| p.id() == id)
    }

    /// All merged endpoint descriptors.
    pub fn endpoints(&self) -> &[PluginEndpoint] {
        &self.all_endpoints
    }

    /// All merged schema tables.
    pub fn tables(&self) -> &[AuthTable] {
        &self.all_tables
    }

    /// All merged additional fields for existing tables.
    pub fn additional_fields(&self) -> &HashMap<String, HashMap<String, SchemaField>> {
        &self.all_additional_fields
    }

    /// All merged hooks.
    pub fn hooks(&self) -> &[PluginHookEntry] {
        &self.all_hooks
    }

    /// All merged middleware descriptors.
    pub fn middlewares(&self) -> &[PluginMiddleware] {
        &self.all_middlewares
    }

    /// All merged rate limit rules.
    pub fn rate_limits(&self) -> &[PluginRateLimit] {
        &self.all_rate_limits
    }

    /// Hooks matching a specific model, timing, and operation.
    pub fn hooks_for(
        &self,
        model: &str,
        timing: better_auth_core::plugin::HookTiming,
        operation: better_auth_core::plugin::HookOperation,
    ) -> Vec<&PluginHookEntry> {
        self.all_hooks
            .iter()
            .filter(|e| {
                e.hook.model == model
                    && e.hook.timing == timing
                    && e.hook.operation == operation
            })
            .collect()
    }

    /// Endpoints requiring authentication.
    pub fn auth_endpoints(&self) -> Vec<&PluginEndpoint> {
        self.all_endpoints.iter().filter(|e| e.require_auth).collect()
    }

    /// Plugin IDs as a list.
    pub fn plugin_ids(&self) -> Vec<&str> {
        self.plugins.iter().map(|p| p.id()).collect()
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal test plugin for unit tests
    #[derive(Debug)]
    struct TestPlugin {
        id: String,
    }

    #[async_trait::async_trait]
    impl BetterAuthPlugin for TestPlugin {
        fn id(&self) -> &str {
            &self.id
        }

        fn endpoints(&self) -> Vec<PluginEndpoint> {
            vec![PluginEndpoint {
                path: format!("/{}/action", self.id),
                method: better_auth_core::plugin::HttpMethod::Post,
                require_auth: true,
                metadata: HashMap::new(),
                    handler: None,
            }]
        }

        fn additional_fields(
            &self,
        ) -> HashMap<String, HashMap<String, SchemaField>> {
            let mut user_fields = HashMap::new();
            user_fields.insert(
                format!("{}_field", self.id),
                SchemaField::optional_string(),
            );
            let mut fields = HashMap::new();
            fields.insert("user".to_string(), user_fields);
            fields
        }

        fn hooks(&self) -> Vec<PluginHook> {
            vec![PluginHook {
                model: "user".to_string(),
                timing: better_auth_core::plugin::HookTiming::Before,
                operation: better_auth_core::plugin::HookOperation::Create,
            }]
        }
    }

    #[test]
    fn test_empty_registry() {
        let reg = PluginRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        assert!(reg.endpoints().is_empty());
        assert!(reg.hooks().is_empty());
    }

    #[test]
    fn test_from_plugins() {
        let plugins: Vec<Arc<dyn BetterAuthPlugin>> = vec![
            Arc::new(TestPlugin { id: "alpha".into() }),
            Arc::new(TestPlugin { id: "beta".into() }),
        ];
        let reg = PluginRegistry::from_plugins(plugins);

        assert_eq!(reg.len(), 2);
        assert_eq!(reg.endpoints().len(), 2);
        assert_eq!(reg.hooks().len(), 2);
        assert!(reg
            .additional_fields()
            .get("user")
            .unwrap()
            .contains_key("alpha_field"));
        assert!(reg
            .additional_fields()
            .get("user")
            .unwrap()
            .contains_key("beta_field"));
    }

    #[test]
    fn test_get_plugin() {
        let plugins: Vec<Arc<dyn BetterAuthPlugin>> = vec![
            Arc::new(TestPlugin { id: "test".into() }),
        ];
        let reg = PluginRegistry::from_plugins(plugins);

        assert!(reg.get_plugin("test").is_some());
        assert!(reg.get_plugin("unknown").is_none());
    }

    #[test]
    fn test_hooks_for() {
        let plugins: Vec<Arc<dyn BetterAuthPlugin>> = vec![
            Arc::new(TestPlugin { id: "a".into() }),
            Arc::new(TestPlugin { id: "b".into() }),
        ];
        let reg = PluginRegistry::from_plugins(plugins);

        let hooks = reg.hooks_for(
            "user",
            better_auth_core::plugin::HookTiming::Before,
            better_auth_core::plugin::HookOperation::Create,
        );
        assert_eq!(hooks.len(), 2);

        let hooks = reg.hooks_for(
            "session",
            better_auth_core::plugin::HookTiming::Before,
            better_auth_core::plugin::HookOperation::Create,
        );
        assert_eq!(hooks.len(), 0);
    }

    #[test]
    fn test_plugin_ids() {
        let plugins: Vec<Arc<dyn BetterAuthPlugin>> = vec![
            Arc::new(TestPlugin { id: "x".into() }),
            Arc::new(TestPlugin { id: "y".into() }),
            Arc::new(TestPlugin { id: "z".into() }),
        ];
        let reg = PluginRegistry::from_plugins(plugins);
        assert_eq!(reg.plugin_ids(), vec!["x", "y", "z"]);
    }

    #[test]
    fn test_auth_endpoints() {
        let plugins: Vec<Arc<dyn BetterAuthPlugin>> = vec![
            Arc::new(TestPlugin { id: "t".into() }),
        ];
        let reg = PluginRegistry::from_plugins(plugins);
        assert_eq!(reg.auth_endpoints().len(), 1);
    }
}
