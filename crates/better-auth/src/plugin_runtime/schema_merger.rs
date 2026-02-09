// Schema merger — merges plugin schemas into the base auth schema.
//
// Maps to: packages/better-auth/src/db/schema.ts mergeSchema
//
// When plugins add tables or fields, they need to be merged into the
// base Better Auth schema (user, session, account, verification) before
// database initialization / migrations.

use std::collections::HashMap;

use better_auth_core::db::schema::{AuthSchema, AuthTable, SchemaField};

use super::registry::PluginRegistry;

/// Merge plugin schema contributions into the base auth schema.
///
/// This:
/// 1. Adds any new tables from plugins
/// 2. Merges additional fields into existing tables (user, session, etc.)
/// 3. Returns the unified schema
pub fn merge_plugin_schema(
    mut base_schema: AuthSchema,
    registry: &PluginRegistry,
) -> AuthSchema {
    // 1. Add new tables from plugins
    for table in registry.tables() {
        // Only add if not already present
        if !base_schema.tables.contains_key(&table.name) {
            base_schema.tables.insert(table.name.clone(), table.clone());
        }
    }

    // 2. Merge additional fields into existing tables
    for (table_name, fields) in registry.additional_fields() {
        if let Some(table) = base_schema.tables.get_mut(table_name) {
            for (field_name, field) in fields {
                // Only add if not already present (don't override base fields)
                if !table.fields.contains_key(field_name) {
                    table.fields.insert(field_name.clone(), field.clone());
                }
            }
        }
    }

    base_schema
}

/// Count the total number of fields added by plugins.
pub fn count_plugin_fields(registry: &PluginRegistry) -> usize {
    registry
        .additional_fields()
        .values()
        .map(|fields| fields.len())
        .sum()
}

/// Count the total number of tables added by plugins.
pub fn count_plugin_tables(registry: &PluginRegistry) -> usize {
    registry.tables().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_schema() -> AuthSchema {
        AuthSchema::new()
            .table(
                AuthTable::new("user")
                    .field("name", SchemaField::required_string())
                    .field("email", SchemaField::required_string()),
            )
            .table(AuthTable::new("session"))
    }

    #[derive(Debug)]
    struct SchemaTestPlugin;

    #[async_trait::async_trait]
    impl better_auth_core::plugin::BetterAuthPlugin for SchemaTestPlugin {
        fn id(&self) -> &str {
            "schema-test"
        }

        fn schema(&self) -> Vec<AuthTable> {
            vec![AuthTable::new("twofactor")
                .field("secret", SchemaField::required_string())]
        }

        fn additional_fields(
            &self,
        ) -> HashMap<String, HashMap<String, SchemaField>> {
            let mut user_fields = HashMap::new();
            user_fields.insert("twoFactorEnabled".into(), SchemaField::boolean(false));
            let mut fields = HashMap::new();
            fields.insert("user".into(), user_fields);
            fields
        }
    }

    #[test]
    fn test_merge_adds_new_table() {
        let plugins: Vec<std::sync::Arc<dyn better_auth_core::plugin::BetterAuthPlugin>> =
            vec![std::sync::Arc::new(SchemaTestPlugin)];
        let reg = PluginRegistry::from_plugins(plugins);
        let merged = merge_plugin_schema(base_schema(), &reg);

        assert_eq!(merged.tables.len(), 3); // user, session, twofactor
        assert!(merged.tables.contains_key("twofactor"));
    }

    #[test]
    fn test_merge_adds_fields_to_existing_table() {
        let plugins: Vec<std::sync::Arc<dyn better_auth_core::plugin::BetterAuthPlugin>> =
            vec![std::sync::Arc::new(SchemaTestPlugin)];
        let reg = PluginRegistry::from_plugins(plugins);
        let merged = merge_plugin_schema(base_schema(), &reg);

        let user_table = merged.tables.get("user").unwrap();
        assert!(user_table.fields.contains_key("twoFactorEnabled"));
        // Base fields preserved
        assert!(user_table.fields.contains_key("name"));
        assert!(user_table.fields.contains_key("email"));
    }

    #[test]
    fn test_no_duplicate_tables() {
        #[derive(Debug)]
        struct DuplicatePlugin;

        #[async_trait::async_trait]
        impl better_auth_core::plugin::BetterAuthPlugin for DuplicatePlugin {
            fn id(&self) -> &str { "dup" }
            fn schema(&self) -> Vec<AuthTable> {
                vec![AuthTable::new("user")] // already exists
            }
        }

        let plugins: Vec<std::sync::Arc<dyn better_auth_core::plugin::BetterAuthPlugin>> =
            vec![std::sync::Arc::new(DuplicatePlugin)];
        let reg = PluginRegistry::from_plugins(plugins);
        let merged = merge_plugin_schema(base_schema(), &reg);

        assert_eq!(merged.tables.len(), 2);
    }

    #[test]
    fn test_count_plugin_fields() {
        let plugins: Vec<std::sync::Arc<dyn better_auth_core::plugin::BetterAuthPlugin>> =
            vec![std::sync::Arc::new(SchemaTestPlugin)];
        let reg = PluginRegistry::from_plugins(plugins);
        assert_eq!(count_plugin_fields(&reg), 1);
    }
}
