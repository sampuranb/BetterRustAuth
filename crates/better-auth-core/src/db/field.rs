// Field name mapping for DB adapters — handles camelCase ↔ snake_case
// and custom field name overrides from plugins/options.
//
// Maps to: packages/core/src/db/adapter/factory.ts field mapping logic.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Configuration describing how to map between logical field names
/// (as used in code/API) and physical column names (in the database).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FieldMapping {
    /// Map of `logicalName → physicalColumnName` per table.
    /// Key is the table name, value is a map of field name conversions.
    tables: HashMap<String, HashMap<String, String>>,
}

impl FieldMapping {
    pub fn new() -> Self {
        Self {
            tables: HashMap::new(),
        }
    }

    /// Add a field mapping for a specific table.
    pub fn add(
        &mut self,
        table: &str,
        logical_name: &str,
        physical_name: &str,
    ) {
        self.tables
            .entry(table.to_string())
            .or_default()
            .insert(logical_name.to_string(), physical_name.to_string());
    }

    /// Convert a logical field name to its physical column name.
    /// Falls back to the logical name if no mapping exists.
    pub fn to_physical(&self, table: &str, logical: &str) -> String {
        self.tables
            .get(table)
            .and_then(|fields| fields.get(logical))
            .cloned()
            .unwrap_or_else(|| logical.to_string())
    }

    /// Convert a physical column name back to its logical field name.
    pub fn to_logical(&self, table: &str, physical: &str) -> String {
        if let Some(fields) = self.tables.get(table) {
            for (logical, phys) in fields {
                if phys == physical {
                    return logical.clone();
                }
            }
        }
        physical.to_string()
    }

    /// Convert a logical table name to its physical name.
    /// (Tables can also be renamed.)
    pub fn table_to_physical(&self, logical: &str) -> String {
        self.tables
            .get("__tables__")
            .and_then(|t| t.get(logical))
            .cloned()
            .unwrap_or_else(|| logical.to_string())
    }

    /// Add a table name mapping.
    pub fn add_table_mapping(&mut self, logical: &str, physical: &str) {
        self.tables
            .entry("__tables__".to_string())
            .or_default()
            .insert(logical.to_string(), physical.to_string());
    }
}

/// Utility to convert a camelCase string to snake_case.
pub fn camel_to_snake(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 4);
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            result.push('_');
        }
        result.push(c.to_lowercase().next().unwrap_or(c));
    }
    result
}

/// Utility to convert a snake_case string to camelCase.
pub fn snake_to_camel(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut capitalize_next = false;
    for c in s.chars() {
        if c == '_' {
            capitalize_next = true;
        } else if capitalize_next {
            result.extend(c.to_uppercase());
            capitalize_next = false;
        } else {
            result.push(c);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_camel_to_snake() {
        assert_eq!(camel_to_snake("emailVerified"), "email_verified");
        assert_eq!(camel_to_snake("accessTokenExpiresAt"), "access_token_expires_at");
        assert_eq!(camel_to_snake("id"), "id");
        assert_eq!(camel_to_snake("userId"), "user_id");
    }

    #[test]
    fn test_snake_to_camel() {
        assert_eq!(snake_to_camel("email_verified"), "emailVerified");
        assert_eq!(snake_to_camel("access_token_expires_at"), "accessTokenExpiresAt");
        assert_eq!(snake_to_camel("id"), "id");
    }

    #[test]
    fn test_field_mapping() {
        let mut mapping = FieldMapping::new();
        mapping.add("user", "emailVerified", "email_verified");
        assert_eq!(mapping.to_physical("user", "emailVerified"), "email_verified");
        assert_eq!(mapping.to_logical("user", "email_verified"), "emailVerified");
        assert_eq!(mapping.to_physical("user", "name"), "name"); // unmapped falls through
    }
}
