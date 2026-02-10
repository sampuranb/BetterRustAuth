// Naming convention utilities for Kysely compatibility.
//
// Kysely uses the table/column names as-is from the database. The TypeScript
// adapter supports various database types (postgres, mysql, sqlite, mssql)
// and translates better-auth's camelCase field names to the database column names.
//
// By default, Kysely does NOT transform names — it uses whatever the database has.
// The `better-auth` CLI generates snake_case names for Kysely by default.

use regex::Regex;
use std::sync::LazyLock;

/// Convert a camelCase string to snake_case.
pub fn to_snake_case(s: &str) -> String {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"([a-z0-9])([A-Z])").unwrap()
    });
    RE.replace_all(s, "${1}_${2}").to_lowercase()
}

/// Convert a snake_case string to camelCase.
pub fn to_camel_case(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut capitalize_next = false;

    for ch in s.chars() {
        if ch == '_' {
            capitalize_next = true;
        } else if capitalize_next {
            result.push(ch.to_ascii_uppercase());
            capitalize_next = false;
        } else {
            result.push(ch);
        }
    }
    result
}

/// Pluralize a model name.
pub fn pluralize(name: &str) -> String {
    if name.ends_with('s') || name.ends_with("sh") || name.ends_with("ch") {
        format!("{name}es")
    } else if name.ends_with('y') && !name.ends_with("ay") && !name.ends_with("ey")
        && !name.ends_with("oy") && !name.ends_with("uy")
    {
        format!("{}ies", &name[..name.len() - 1])
    } else {
        format!("{name}s")
    }
}

/// Convert a better-auth model name to a Kysely table name.
pub fn model_to_table_name(model: &str, use_plural: bool) -> String {
    let name = to_snake_case(model);
    if use_plural { pluralize(&name) } else { name }
}

/// Convert a better-auth field name to a Kysely column name (always snake_case).
pub fn field_to_column_name(field: &str) -> String {
    to_snake_case(field)
}

/// Convert a database column name back to better-auth field name (camelCase).
pub fn column_to_field_name(column: &str) -> String {
    to_camel_case(column)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_snake_case() {
        assert_eq!(to_snake_case("createdAt"), "created_at");
        assert_eq!(to_snake_case("userId"), "user_id");
        assert_eq!(to_snake_case("id"), "id");
    }

    #[test]
    fn test_to_camel_case() {
        assert_eq!(to_camel_case("created_at"), "createdAt");
        assert_eq!(to_camel_case("user_id"), "userId");
        assert_eq!(to_camel_case("id"), "id");
    }

    #[test]
    fn test_model_to_table_name() {
        assert_eq!(model_to_table_name("user", false), "user");
        assert_eq!(model_to_table_name("user", true), "users");
        assert_eq!(model_to_table_name("session", false), "session");
        assert_eq!(model_to_table_name("session", true), "sessions");
    }
}
