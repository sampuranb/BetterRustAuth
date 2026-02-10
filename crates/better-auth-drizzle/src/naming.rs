// Naming convention utilities for Drizzle ORM compatibility.
//
// Drizzle ORM uses snake_case for table/column names by default when the CLI
// generates the schema. Users can opt into camelCase with the `camelCase` config.
// Table names are singular by default (e.g., "user", "session"), with an option
// for plural names (e.g., "users", "sessions") via `usePlural`.

use regex::Regex;
use std::sync::LazyLock;

/// Convert a camelCase string to snake_case.
///
/// Examples: "createdAt" -> "created_at", "userId" -> "user_id"
pub fn to_snake_case(s: &str) -> String {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"([a-z0-9])([A-Z])").unwrap()
    });
    RE.replace_all(s, "${1}_${2}").to_lowercase()
}

/// Convert a snake_case string to camelCase.
///
/// Examples: "created_at" -> "createdAt", "user_id" -> "userId"
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

/// Pluralize a model name by appending "s" (simple English pluralization).
///
/// Matches the Drizzle `usePlural` behavior.
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

/// Convert a better-auth model name to a Drizzle table name.
///
/// Applies the naming conventions based on the Drizzle config:
/// - snake_case (default) or camelCase
/// - singular (default) or plural
pub fn model_to_table_name(model: &str, use_plural: bool, camel_case: bool) -> String {
    let name = if camel_case {
        to_camel_case(model)
    } else {
        to_snake_case(model)
    };

    if use_plural {
        pluralize(&name)
    } else {
        name
    }
}

/// Convert a better-auth field name to a Drizzle column name.
///
/// By default, Drizzle uses snake_case for column names.
/// With `camelCase: true`, it uses camelCase.
pub fn field_to_column_name(field: &str, camel_case: bool) -> String {
    if camel_case {
        to_camel_case(field)
    } else {
        to_snake_case(field)
    }
}

/// Convert a Drizzle column name back to the better-auth field name (camelCase).
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
        assert_eq!(to_snake_case("emailVerified"), "email_verified");
        assert_eq!(to_snake_case("id"), "id");
        assert_eq!(to_snake_case("twoFactorEnabled"), "two_factor_enabled");
    }

    #[test]
    fn test_to_camel_case() {
        assert_eq!(to_camel_case("created_at"), "createdAt");
        assert_eq!(to_camel_case("user_id"), "userId");
        assert_eq!(to_camel_case("email_verified"), "emailVerified");
        assert_eq!(to_camel_case("id"), "id");
    }

    #[test]
    fn test_pluralize() {
        assert_eq!(pluralize("user"), "users");
        assert_eq!(pluralize("session"), "sessions");
        assert_eq!(pluralize("account"), "accounts");
        assert_eq!(pluralize("verification"), "verifications");
    }

    #[test]
    fn test_model_to_table_name() {
        // Default: snake_case, singular
        assert_eq!(model_to_table_name("user", false, false), "user");
        assert_eq!(model_to_table_name("session", false, false), "session");

        // Plural
        assert_eq!(model_to_table_name("user", true, false), "users");
        assert_eq!(model_to_table_name("session", true, false), "sessions");

        // CamelCase
        assert_eq!(model_to_table_name("user", false, true), "user");
        assert_eq!(model_to_table_name("twoFactor", false, true), "twoFactor");

        // CamelCase + plural
        assert_eq!(model_to_table_name("user", true, true), "users");
    }

    #[test]
    fn test_field_to_column_name() {
        // Default: snake_case
        assert_eq!(field_to_column_name("createdAt", false), "created_at");
        assert_eq!(field_to_column_name("userId", false), "user_id");
        assert_eq!(field_to_column_name("id", false), "id");

        // CamelCase
        assert_eq!(field_to_column_name("created_at", true), "createdAt");
        assert_eq!(field_to_column_name("user_id", true), "userId");
    }
}
