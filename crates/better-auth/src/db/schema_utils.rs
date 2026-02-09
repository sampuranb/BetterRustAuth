// Schema utilities — resolve tables and fields from options + plugins.
//
// Maps to: packages/better-auth/src/db/get-schema.ts
//          packages/better-auth/src/db/schema.ts (mergeSchema)

use std::collections::HashMap;

use better_auth_core::db::schema::{AuthSchema, AuthTable, SchemaField};

// ---------------------------------------------------------------------------
// Schema table info — matches TS getSchema() return type
// ---------------------------------------------------------------------------

/// Info about a resolved table in the auth schema.
#[derive(Debug, Clone)]
pub struct SchemaTableInfo {
    pub fields: HashMap<String, SchemaField>,
    pub order: usize,
}

/// Resolve all tables from an AuthSchema into a `HashMap<String, SchemaTableInfo>`.
///
/// Matches the TS `getSchema(config)`: iterates all tables, resolves field names
/// using each field's `fieldName` override, resolves reference model names,
/// and merges duplicates (same modelName from different plugin registrations).
pub fn get_schema(schema: &AuthSchema) -> HashMap<String, SchemaTableInfo> {
    let mut result: HashMap<String, SchemaTableInfo> = HashMap::new();

    for (_key, table) in &schema.tables {
        let model_name = &table.name;
        let mut actual_fields = HashMap::new();

        for (key, field) in &table.fields {
            // Use the field's fieldName override if set, otherwise the key itself
            let resolved_name = field.field_name.clone().unwrap_or_else(|| key.clone());
            let mut resolved_field = field.clone();

            // Resolve reference model names to their actual model names
            if let Some(ref fk) = field.references {
                if let Some(ref_table) = schema.tables.get(&fk.model) {
                    resolved_field.references = Some(better_auth_core::db::schema::FieldReference {
                        model: fk.model.clone(),
                        table: ref_table.name.clone(),
                        field: fk.field.clone(),
                        on_delete: fk.on_delete.clone(),
                    });
                    resolved_field.reference = resolved_field.references.clone();
                }
            }

            actual_fields.insert(resolved_name, resolved_field);
        }

        if let Some(existing) = result.get_mut(model_name) {
            // Merge fields from multiple registrations (e.g., plugin adding fields to user)
            existing.fields.extend(actual_fields);
        } else {
            result.insert(
                model_name.clone(),
                SchemaTableInfo {
                    fields: actual_fields,
                    order: table.order.unwrap_or(i32::MAX) as usize,
                },
            );
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Get fields — matches TS getFields() with mode
// ---------------------------------------------------------------------------

/// Field retrieval mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldMode {
    /// Include core fields + plugin fields (for output filtering).
    Output,
    /// Only additional fields (for input validation).
    Input,
}

/// Get the merged field definitions for a model.
///
/// Matches the TS `getFields(options, modelName, mode)`.
/// For output mode: returns core table fields + additional fields from options/plugins.
/// For input mode: returns only additional fields (caller validates core fields separately).
pub fn get_fields(
    schema: &AuthSchema,
    model_name: &str,
    mode: FieldMode,
) -> HashMap<String, SchemaField> {
    let mut fields = HashMap::new();

    // In output mode, include the core table fields
    if mode == FieldMode::Output {
        if let Some(table) = schema.tables.get(model_name) {
            fields.extend(table.fields.clone());
        }
    }

    // Additional fields from plugins are already merged into the schema
    // by the plugin registry / schema merger, so we just look at the table.
    if mode == FieldMode::Input {
        if let Some(table) = schema.tables.get(model_name) {
            // For input mode, only add fields that aren't core (have custom fieldName or returned=false)
            for (name, field) in &table.fields {
                if !field.returned || field.field_name.is_some() {
                    fields.insert(name.clone(), field.clone());
                }
            }
        }
    }

    fields
}

// ---------------------------------------------------------------------------
// Merge schema — matches TS mergeSchema()
// ---------------------------------------------------------------------------

/// Schema override specification — allows renaming models and fields.
#[derive(Debug, Clone, Default)]
pub struct SchemaOverride {
    /// New model (table) name.
    pub model_name: Option<String>,
    /// Map of field key → new physical field name.
    pub fields: HashMap<String, String>,
}

/// Merge user-provided schema overrides into the auth schema.
///
/// Matches the TS `mergeSchema(schema, newSchema)`: allows users to rename
/// tables and fields without changing the internal model structure.
pub fn merge_schema(
    schema: &mut AuthSchema,
    overrides: &HashMap<String, SchemaOverride>,
) {
    for (table_key, override_spec) in overrides {
        if let Some(table) = schema.tables.get_mut(table_key) {
            // Rename the model
            if let Some(ref new_model_name) = override_spec.model_name {
                table.name = new_model_name.clone();
            }

            // Rename fields
            for (field_key, new_field_name) in &override_spec.fields {
                if let Some(field) = table.fields.get_mut(field_key) {
                    field.field_name = Some(new_field_name.clone());
                }
            }
        }
    }
}

/// Build an AuthSchema from a base schema + plugin tables.
///
/// Merges plugin tables into the base schema, handling duplicate table names
/// by merging their fields.
pub fn merge_plugin_tables(
    base: &mut AuthSchema,
    plugin_tables: &[AuthTable],
) {
    for table in plugin_tables {
        if let Some(existing) = base.tables.get_mut(&table.name) {
            // Merge new fields into existing table
            for (field_name, field) in &table.fields {
                existing
                    .fields
                    .entry(field_name.clone())
                    .or_insert_with(|| field.clone());
            }
        } else {
            base.tables
                .insert(table.name.clone(), table.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::db::schema::{AuthSchema, SchemaField};

    #[test]
    fn test_get_schema() {
        let schema = AuthSchema::core_schema();
        let resolved = get_schema(&schema);
        assert!(resolved.contains_key("user"), "Should have user table");
        assert!(resolved.contains_key("session"), "Should have session table");
        assert!(resolved.contains_key("account"), "Should have account table");
    }

    #[test]
    fn test_get_fields_output() {
        let schema = AuthSchema::core_schema();
        let fields = get_fields(&schema, "user", FieldMode::Output);
        assert!(fields.contains_key("email"), "user should have email field");
        assert!(fields.contains_key("name"), "user should have name field");
    }

    #[test]
    fn test_merge_schema() {
        let mut schema = AuthSchema::core_schema();
        let mut overrides = HashMap::new();
        overrides.insert(
            "user".into(),
            SchemaOverride {
                model_name: Some("users".into()),
                fields: {
                    let mut f = HashMap::new();
                    f.insert("emailVerified".into(), "email_verified".into());
                    f
                },
            },
        );
        merge_schema(&mut schema, &overrides);
        let user_table = schema.tables.get("user").unwrap();
        assert_eq!(user_table.name, "users");
        if let Some(ev) = user_table.fields.get("emailVerified") {
            assert_eq!(ev.field_name, Some("email_verified".to_string()));
        }
    }

    #[test]
    fn test_merge_plugin_tables() {
        let mut schema = AuthSchema::core_schema();
        let plugin_table = AuthTable::new("twoFactor")
            .field("id", SchemaField::required_string())
            .field("userId", SchemaField::required_string());
        merge_plugin_tables(&mut schema, &[plugin_table]);
        assert!(schema.tables.contains_key("twoFactor"));
    }

    #[test]
    fn test_merge_plugin_tables_extends_existing() {
        let mut schema = AuthSchema::core_schema();
        let ext = AuthTable::new("user")
            .field("twoFactorEnabled", SchemaField::boolean(false));
        merge_plugin_tables(&mut schema, &[ext]);
        let user = schema.tables.get("user").unwrap();
        assert!(user.fields.contains_key("twoFactorEnabled"));
        // Original fields should still be present
        assert!(user.fields.contains_key("email"));
    }
}
