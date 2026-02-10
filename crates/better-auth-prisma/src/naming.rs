// Naming convention utilities for Prisma compatibility.
//
// Prisma uses camelCase for models by default (e.g., User, Session) and maps them
// to snake_case table/column names based on the `@@map` and `@map` directives.
// The better-auth CLI generates Prisma schemas with appropriate mappings.
//
// Key differences from Drizzle/Kysely:
// - Prisma model names are PascalCase (User, Session, Account)
// - Table names default to PascalCase unless @@map is used
// - Column names are camelCase by default unless @map is used
// - The better-auth CLI generates @map("snake_case") for all columns

use regex::Regex;
use std::sync::LazyLock;

/// Convert camelCase to snake_case.
pub fn to_snake_case(s: &str) -> String {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"([a-z0-9])([A-Z])").unwrap()
    });
    RE.replace_all(s, "${1}_${2}").to_lowercase()
}

/// Convert snake_case to camelCase.
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

/// Convert a better-auth model name to a Prisma table name.
///
/// Prisma uses lowercase model names in the database (matching better-auth conventions).
/// With `usePlural`, table names are pluralized.
pub fn model_to_table_name(model: &str, use_plural: bool) -> String {
    // Prisma models in the DB are lowercase by default (with @@map)
    let name = to_snake_case(model);
    if use_plural {
        pluralize(&name)
    } else {
        name
    }
}

/// Convert a better-auth field name to a Prisma column name.
///
/// Prisma uses camelCase internally but the CLI generates @map("snake_case") directives,
/// so the actual DB columns are snake_case.
pub fn field_to_column_name(field: &str) -> String {
    to_snake_case(field)
}

/// Convert a database column name back to the better-auth field name.
pub fn column_to_field_name(column: &str) -> String {
    to_camel_case(column)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_to_table_name() {
        assert_eq!(model_to_table_name("user", false), "user");
        assert_eq!(model_to_table_name("user", true), "users");
        assert_eq!(model_to_table_name("session", false), "session");
    }

    #[test]
    fn test_field_to_column_name() {
        assert_eq!(field_to_column_name("createdAt"), "created_at");
        assert_eq!(field_to_column_name("userId"), "user_id");
        assert_eq!(field_to_column_name("id"), "id");
    }

    #[test]
    fn test_column_to_field_name() {
        assert_eq!(column_to_field_name("created_at"), "createdAt");
        assert_eq!(column_to_field_name("user_id"), "userId");
        assert_eq!(column_to_field_name("id"), "id");
    }
}
