// Additional Fields plugin — schema extension for user/session tables.
//
// Maps to: packages/better-auth/src/plugins/additional-fields/client.ts
//
// In the TypeScript version, this is a client-side type inference helper that
// adds type-level knowledge of additional user/session fields. In Rust,
// this is a config struct + plugin that can extend the user and session schemas
// at runtime with arbitrary additional columns.

use std::collections::HashMap;

use async_trait::async_trait;
use better_auth_core::db::schema::{AuthTable, FieldType, SchemaField};
use better_auth_core::plugin::BetterAuthPlugin;

// ─── Configuration ─────────────────────────────────────────────────────

/// Configuration for additional fields on user and session tables.
///
/// Allows adding custom columns to the `user` and `session` tables
/// without creating a full plugin. This is the Rust equivalent of the
/// TS `user.additionalFields` / `session.additionalFields` config.
///
/// # Example
/// ```rust
/// use better_auth::plugins::additional_fields::{AdditionalFieldsOptions, FieldDefinition};
///
/// let options = AdditionalFieldsOptions {
///     user: vec![
///         FieldDefinition::optional_string("bio"),
///         FieldDefinition::optional_string("avatar_url"),
///         FieldDefinition::required_string("display_name"),
///     ],
///     session: vec![
///         FieldDefinition::optional_string("device_name"),
///     ],
/// };
/// ```
#[derive(Debug, Clone, Default)]
pub struct AdditionalFieldsOptions {
    /// Additional fields to add to the `user` table.
    pub user: Vec<FieldDefinition>,
    /// Additional fields to add to the `session` table.
    pub session: Vec<FieldDefinition>,
}

/// A single additional field definition.
#[derive(Debug, Clone)]
pub struct FieldDefinition {
    /// Column name.
    pub name: String,
    /// The schema field type and constraints.
    pub field: SchemaField,
}

impl FieldDefinition {
    /// Create a required string field.
    pub fn required_string(name: &str) -> Self {
        Self {
            name: name.to_string(),
            field: SchemaField::required_string(),
        }
    }

    /// Create an optional string field.
    pub fn optional_string(name: &str) -> Self {
        Self {
            name: name.to_string(),
            field: SchemaField::optional_string(),
        }
    }

    /// Create a required boolean field.
    pub fn required_boolean(name: &str) -> Self {
        Self {
            name: name.to_string(),
            field: SchemaField {
                field_type: FieldType::Boolean,
                required: true,
                ..SchemaField::required_string()
            },
        }
    }

    /// Create an optional boolean field.
    pub fn optional_boolean(name: &str) -> Self {
        Self {
            name: name.to_string(),
            field: SchemaField {
                field_type: FieldType::Boolean,
                required: false,
                ..SchemaField::required_string()
            },
        }
    }

    /// Create a required integer field.
    pub fn required_number(name: &str) -> Self {
        Self {
            name: name.to_string(),
            field: SchemaField {
                field_type: FieldType::Number,
                required: true,
                ..SchemaField::required_string()
            },
        }
    }

    /// Create an optional integer field.
    pub fn optional_number(name: &str) -> Self {
        Self {
            name: name.to_string(),
            field: SchemaField {
                field_type: FieldType::Number,
                required: false,
                ..SchemaField::required_string()
            },
        }
    }

    /// Create a custom field with an explicit SchemaField.
    pub fn custom(name: &str, field: SchemaField) -> Self {
        Self {
            name: name.to_string(),
            field,
        }
    }
}

// ─── Plugin ────────────────────────────────────────────────────────────

/// Additional Fields plugin.
///
/// Extends the `user` and/or `session` schemas with custom columns
/// defined in `AdditionalFieldsOptions`.
#[derive(Debug)]
pub struct AdditionalFieldsPlugin {
    options: AdditionalFieldsOptions,
}

impl AdditionalFieldsPlugin {
    /// Create a new plugin with the given field definitions.
    pub fn new(options: AdditionalFieldsOptions) -> Self {
        Self { options }
    }

    /// Get the configured options.
    pub fn options(&self) -> &AdditionalFieldsOptions {
        &self.options
    }
}

impl Default for AdditionalFieldsPlugin {
    fn default() -> Self {
        Self::new(AdditionalFieldsOptions::default())
    }
}

#[async_trait]
impl BetterAuthPlugin for AdditionalFieldsPlugin {
    fn id(&self) -> &str {
        "additional-fields"
    }

    fn name(&self) -> &str {
        "Additional Fields"
    }

    fn schema(&self) -> Vec<AuthTable> {
        let mut tables = Vec::new();

        // Extend user table
        if !self.options.user.is_empty() {
            let mut user_table = AuthTable::new("user");
            for field_def in &self.options.user {
                user_table = user_table.field(&field_def.name, field_def.field.clone());
            }
            tables.push(user_table);
        }

        // Extend session table
        if !self.options.session.is_empty() {
            let mut session_table = AuthTable::new("session");
            for field_def in &self.options.session {
                session_table = session_table.field(&field_def.name, field_def.field.clone());
            }
            tables.push(session_table);
        }

        tables
    }

    fn endpoints(&self) -> Vec<better_auth_core::plugin::PluginEndpoint> {
        // No endpoints — this is a schema-only plugin.
        Vec::new()
    }

    fn error_codes(&self) -> Vec<better_auth_core::error::ErrorCode> {
        Vec::new()
    }

    fn field_mapping(&self) -> HashMap<String, HashMap<String, String>> {
        HashMap::new()
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_id() {
        let plugin = AdditionalFieldsPlugin::default();
        assert_eq!(plugin.id(), "additional-fields");
        assert_eq!(plugin.name(), "Additional Fields");
    }

    #[test]
    fn test_no_fields_no_schema() {
        let plugin = AdditionalFieldsPlugin::default();
        assert!(plugin.schema().is_empty());
    }

    #[test]
    fn test_user_fields_schema() {
        let options = AdditionalFieldsOptions {
            user: vec![
                FieldDefinition::optional_string("bio"),
                FieldDefinition::required_string("display_name"),
                FieldDefinition::optional_boolean("email_verified_custom"),
            ],
            session: vec![],
        };
        let plugin = AdditionalFieldsPlugin::new(options);
        let schema = plugin.schema();
        assert_eq!(schema.len(), 1);
        assert_eq!(schema[0].name, "user");
        assert_eq!(schema[0].fields.len(), 3);
    }

    #[test]
    fn test_session_fields_schema() {
        let options = AdditionalFieldsOptions {
            user: vec![],
            session: vec![FieldDefinition::optional_string("device_name")],
        };
        let plugin = AdditionalFieldsPlugin::new(options);
        let schema = plugin.schema();
        assert_eq!(schema.len(), 1);
        assert_eq!(schema[0].name, "session");
    }

    #[test]
    fn test_both_tables_extended() {
        let options = AdditionalFieldsOptions {
            user: vec![FieldDefinition::optional_string("bio")],
            session: vec![FieldDefinition::optional_string("device_name")],
        };
        let plugin = AdditionalFieldsPlugin::new(options);
        let schema = plugin.schema();
        assert_eq!(schema.len(), 2);
    }

    #[test]
    fn test_no_endpoints() {
        let plugin = AdditionalFieldsPlugin::default();
        assert!(plugin.endpoints().is_empty());
    }

    #[test]
    fn test_field_factories() {
        let f1 = FieldDefinition::required_string("name");
        assert_eq!(f1.name, "name");
        assert!(f1.field.required);

        let f2 = FieldDefinition::optional_string("bio");
        assert!(!f2.field.required);

        let f3 = FieldDefinition::required_boolean("active");
        assert!(f3.field.required);

        let f4 = FieldDefinition::optional_number("age");
        assert!(!f4.field.required);
    }
}
