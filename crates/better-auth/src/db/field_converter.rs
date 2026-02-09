// Field converter — maps logical field names to/from physical DB column names.
//
// Maps to: packages/better-auth/src/db/field-converter.ts
// Uses FieldMapping from better-auth-core to convert between in-code
// camelCase field names and physical database column names.

use std::collections::HashMap;
use better_auth_core::db::field::FieldMapping;
use better_auth_core::db::schema::SchemaField;
use serde_json::Value;

/// Convert data from logical (code-facing) field names to physical DB column names.
///
/// Matches TS `convertToDB`: given a record with logical field names (e.g. `emailVerified`),
/// produces a record with the physical column names (e.g. `email_verified`),
/// using the schema's `fieldName` overrides and the FieldMapping.
pub fn convert_to_db(
    fields: &HashMap<String, SchemaField>,
    values: &Value,
    mapping: &FieldMapping,
    table: &str,
) -> Value {
    let obj = match values.as_object() {
        Some(o) => o,
        None => return values.clone(),
    };

    let mut result = serde_json::Map::new();

    // Preserve "id" if present
    if let Some(id) = obj.get("id") {
        result.insert("id".to_string(), id.clone());
    }

    for (key, field) in fields {
        if let Some(value) = obj.get(key.as_str()) {
            // Use the field's custom fieldName if set, otherwise use FieldMapping
            let physical_name = if let Some(ref custom) = field.field_name {
                custom.clone()
            } else {
                mapping.to_physical(table, key)
            };
            result.insert(physical_name, value.clone());
        }
    }

    Value::Object(result)
}

/// Convert data from physical DB column names back to logical (code-facing) names.
///
/// Matches TS `convertFromDB`: given a row from the database with physical names,
/// produces a record with the logical field names used in the API.
pub fn convert_from_db(
    fields: &HashMap<String, SchemaField>,
    values: &Value,
    mapping: &FieldMapping,
    table: &str,
) -> Option<Value> {
    let obj = match values.as_object() {
        Some(o) => o,
        None => return None,
    };

    let mut result = serde_json::Map::new();

    // Preserve "id" if present
    if let Some(id) = obj.get("id") {
        result.insert("id".to_string(), id.clone());
    }

    for (logical_key, field) in fields {
        let physical_name = if let Some(ref custom) = field.field_name {
            custom.clone()
        } else {
            mapping.to_physical(table, logical_key)
        };
        if let Some(value) = obj.get(&physical_name) {
            result.insert(logical_key.clone(), value.clone());
        }
    }

    Some(Value::Object(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::db::schema::SchemaField;
    use serde_json::json;

    fn make_fields() -> HashMap<String, SchemaField> {
        let mut fields = HashMap::new();
        fields.insert("name".into(), SchemaField::required_string());
        fields.insert("emailVerified".into(), SchemaField::boolean(false));
        fields
    }

    #[test]
    fn test_convert_to_db_with_mapping() {
        let fields = make_fields();
        let mut mapping = FieldMapping::new();
        mapping.add("user", "emailVerified", "email_verified");

        let data = json!({"id": "u1", "name": "Alice", "emailVerified": true});
        let result = convert_to_db(&fields, &data, &mapping, "user");

        assert_eq!(result["id"], "u1");
        assert_eq!(result["name"], "Alice");
        assert_eq!(result["email_verified"], true);
    }

    #[test]
    fn test_convert_from_db_with_mapping() {
        let fields = make_fields();
        let mut mapping = FieldMapping::new();
        mapping.add("user", "emailVerified", "email_verified");

        let db_row = json!({"id": "u1", "name": "Alice", "email_verified": true});
        let result = convert_from_db(&fields, &db_row, &mapping, "user").unwrap();

        assert_eq!(result["id"], "u1");
        assert_eq!(result["name"], "Alice");
        assert_eq!(result["emailVerified"], true);
    }

    #[test]
    fn test_convert_roundtrip() {
        let fields = make_fields();
        let mapping = FieldMapping::new(); // No custom mapping, names stay same

        let data = json!({"id": "u2", "name": "Bob", "emailVerified": false});
        let to_db = convert_to_db(&fields, &data, &mapping, "user");
        let from_db = convert_from_db(&fields, &to_db, &mapping, "user").unwrap();

        assert_eq!(from_db["id"], "u2");
        assert_eq!(from_db["name"], "Bob");
        assert_eq!(from_db["emailVerified"], false);
    }

    #[test]
    fn test_convert_from_db_null_returns_none() {
        let fields = make_fields();
        let mapping = FieldMapping::new();
        let result = convert_from_db(&fields, &Value::Null, &mapping, "user");
        assert!(result.is_none());
    }
}
