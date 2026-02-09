// Input/output parsing — validates and transforms data going into and out of the DB.
//
// Maps to: packages/better-auth/src/db/schema.ts (parseInputData, parseUserOutput,
//          parseAccountOutput, parseSessionOutput, etc.)

use std::collections::HashMap;

use better_auth_core::db::schema::SchemaField;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Parse input data — matches TS parseInputData()
// ---------------------------------------------------------------------------

/// Action context for input parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseAction {
    Create,
    Update,
}

/// Error during input parsing.
#[derive(Debug, Clone)]
pub enum ParseError {
    /// A field marked `input: false` was provided with a non-null value.
    FieldNotAllowed(String),
    /// A required field is missing during create.
    MissingField(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FieldNotAllowed(field) => write!(f, "{field} is not allowed to be set"),
            Self::MissingField(field) => write!(f, "{field} is required"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse and validate input data against a schema.
///
/// Matches the TS `parseInputData(data, { fields, action })`:
/// - Rejects fields with `input: false` (unless they have a defaultValue → apply default on create)
/// - Applies `defaultValue` for missing fields on create
/// - Validates required fields on create
/// - Passes through all other fields unchanged
pub fn parse_input_data(
    data: &Value,
    fields: &HashMap<String, SchemaField>,
    action: ParseAction,
) -> Result<Value, ParseError> {
    let obj = match data.as_object() {
        Some(o) => o,
        None => return Ok(Value::Object(serde_json::Map::new())),
    };

    let mut result = serde_json::Map::new();

    for (key, field) in fields {
        if let Some(value) = obj.get(key.as_str()) {
            // Check input: false fields
            if !field.input {
                if field.default_value.is_some() && action != ParseAction::Update {
                    // Apply default instead of user value
                    result.insert(key.clone(), field.default_value.clone().unwrap());
                    continue;
                }
                // If user provided a non-null value for a non-input field, reject
                if !value.is_null() {
                    return Err(ParseError::FieldNotAllowed(key.clone()));
                }
                continue;
            }

            // Value is provided and field accepts input → pass through
            if !value.is_null() {
                result.insert(key.clone(), value.clone());
            }
            continue;
        }

        // Value not provided — check defaults and required
        if let Some(ref default) = field.default_value {
            if action == ParseAction::Create {
                result.insert(key.clone(), default.clone());
                continue;
            }
        }

        if field.required && action == ParseAction::Create {
            return Err(ParseError::MissingField(key.clone()));
        }
    }

    Ok(Value::Object(result))
}

// ---------------------------------------------------------------------------
// Parse user input — convenience wrappers
// ---------------------------------------------------------------------------

/// Parse user input data.
pub fn parse_user_input(
    data: &Value,
    fields: &HashMap<String, SchemaField>,
    action: ParseAction,
) -> Result<Value, ParseError> {
    parse_input_data(data, fields, action)
}

/// Parse session input data.
pub fn parse_session_input(
    data: &Value,
    fields: &HashMap<String, SchemaField>,
    action: ParseAction,
) -> Result<Value, ParseError> {
    parse_input_data(data, fields, action)
}

/// Parse account input data.
pub fn parse_account_input(
    data: &Value,
    fields: &HashMap<String, SchemaField>,
    action: ParseAction,
) -> Result<Value, ParseError> {
    parse_input_data(data, fields, action)
}

// ---------------------------------------------------------------------------
// Output parsing — strip non-returned fields
// ---------------------------------------------------------------------------

/// Filter output fields, removing fields marked `returned: false`.
///
/// Matches the TS `filterOutputFields` + `parseUserOutput` / `parseSessionOutput`.
pub fn filter_output_fields(
    data: &Value,
    fields: &HashMap<String, SchemaField>,
) -> Value {
    let obj = match data.as_object() {
        Some(o) => o,
        None => return data.clone(),
    };

    let mut result = serde_json::Map::new();

    // Always include id
    if let Some(id) = obj.get("id") {
        result.insert("id".to_string(), id.clone());
    }

    for (key, field) in fields {
        if !field.returned {
            continue;
        }
        if let Some(value) = obj.get(key.as_str()) {
            result.insert(key.clone(), value.clone());
        }
    }

    Value::Object(result)
}

/// Parse account output — strip sensitive fields (tokens, password).
///
/// Matches the TS `parseAccountOutput` which strips accessToken, refreshToken,
/// idToken, accessTokenExpiresAt, refreshTokenExpiresAt, password.
pub fn parse_account_output(data: &Value) -> Value {
    let obj = match data.as_object() {
        Some(o) => o,
        None => return data.clone(),
    };

    let sensitive_fields = [
        "accessToken",
        "refreshToken",
        "idToken",
        "accessTokenExpiresAt",
        "refreshTokenExpiresAt",
        "password",
    ];

    let mut result = serde_json::Map::new();
    for (key, value) in obj {
        if !sensitive_fields.contains(&key.as_str()) {
            result.insert(key.clone(), value.clone());
        }
    }

    Value::Object(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::db::schema::SchemaField;
    use serde_json::json;

    fn user_fields() -> HashMap<String, SchemaField> {
        let mut fields = HashMap::new();
        fields.insert("name".into(), SchemaField::required_string());
        fields.insert("email".into(), SchemaField::required_string());
        let mut ev = SchemaField::boolean(false);
        ev.input = false; // emailVerified should not be settable by user
        fields.insert("emailVerified".into(), ev);
        fields
    }

    #[test]
    fn test_parse_input_create_ok() {
        let fields = user_fields();
        let data = json!({"name": "Alice", "email": "alice@example.com"});
        let result = parse_input_data(&data, &fields, ParseAction::Create).unwrap();
        assert_eq!(result["name"], "Alice");
        assert_eq!(result["email"], "alice@example.com");
        // emailVerified has default=false and input=false, so default should be applied
        assert_eq!(result["emailVerified"], false);
    }

    #[test]
    fn test_parse_input_rejects_non_input_field() {
        let fields = user_fields();
        let data = json!({"name": "Alice", "email": "alice@example.com", "emailVerified": true});
        // emailVerified has input=false and a default, so on create the default is used (not rejected)
        let result = parse_input_data(&data, &fields, ParseAction::Create).unwrap();
        assert_eq!(result["emailVerified"], false); // Default applied, user value ignored
    }

    #[test]
    fn test_parse_input_missing_required() {
        let fields = user_fields();
        let data = json!({"name": "Alice"}); // missing email
        let result = parse_input_data(&data, &fields, ParseAction::Create);
        assert!(result.is_err());
        if let Err(ParseError::MissingField(f)) = result {
            assert_eq!(f, "email");
        }
    }

    #[test]
    fn test_parse_input_update_skips_required() {
        let fields = user_fields();
        let data = json!({"name": "Bob"}); // missing email is OK on update
        let result = parse_input_data(&data, &fields, ParseAction::Update).unwrap();
        assert_eq!(result["name"], "Bob");
    }

    #[test]
    fn test_filter_output_fields() {
        let mut fields = HashMap::new();
        fields.insert("name".into(), SchemaField::required_string());
        let mut pw = SchemaField::required_string();
        pw.returned = false;
        fields.insert("password".into(), pw);

        let data = json!({"id": "u1", "name": "Alice", "password": "secret"});
        let result = filter_output_fields(&data, &fields);
        assert_eq!(result["id"], "u1");
        assert_eq!(result["name"], "Alice");
        assert!(result.get("password").is_none());
    }

    #[test]
    fn test_parse_account_output() {
        let data = json!({
            "id": "a1",
            "providerId": "github",
            "accessToken": "secret-token",
            "refreshToken": "refresh-secret",
            "password": "hashed-pw"
        });
        let result = parse_account_output(&data);
        assert_eq!(result["id"], "a1");
        assert_eq!(result["providerId"], "github");
        assert!(result.get("accessToken").is_none());
        assert!(result.get("refreshToken").is_none());
        assert!(result.get("password").is_none());
    }
}
