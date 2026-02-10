// Schema reader — reads Prisma schema files (.prisma) to extract model/field definitions.
//
// When migrating from the TypeScript version, users have existing Prisma schema files.
// This module parses the `.prisma` schema format to validate compatibility.

use std::collections::HashMap;
use std::path::Path;

/// A field definition in a Prisma model.
#[derive(Debug, Clone)]
pub struct PrismaField {
    /// Field name in Prisma (camelCase).
    pub name: String,
    /// Prisma type (String, Int, Boolean, DateTime, etc.).
    pub prisma_type: String,
    /// Whether the field is optional (marked with ?).
    pub optional: bool,
    /// Whether this is an @id field.
    pub is_id: bool,
    /// The @map directive value, if present (actual DB column name).
    pub map_name: Option<String>,
    /// Default value expression, if any.
    pub default: Option<String>,
}

/// A model definition in a Prisma schema.
#[derive(Debug, Clone)]
pub struct PrismaModel {
    /// Model name (PascalCase, e.g., "User").
    pub name: String,
    /// @@map directive value, if present (actual DB table name).
    pub map_name: Option<String>,
    /// Field definitions.
    pub fields: Vec<PrismaField>,
}

/// Result of reading a Prisma schema file.
#[derive(Debug, Clone)]
pub struct PrismaSchema {
    /// Models in the schema.
    pub models: HashMap<String, PrismaModel>,
    /// The datasource provider (e.g., "sqlite", "postgresql", "mysql", "mongodb").
    pub provider: Option<String>,
}

/// Read and parse a Prisma schema file.
///
/// # Arguments
/// * `schema_path` — Path to the `.prisma` schema file (e.g., `./prisma/schema.prisma`)
pub fn read_schema(schema_path: &Path) -> Result<PrismaSchema, String> {
    let content = std::fs::read_to_string(schema_path)
        .map_err(|e| format!("Failed to read Prisma schema file: {e}"))?;

    parse_schema(&content)
}

/// Parse a Prisma schema string.
pub fn parse_schema(content: &str) -> Result<PrismaSchema, String> {
    let mut models = HashMap::new();
    let mut provider = None;

    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i].trim();

        // Parse datasource block
        if line.starts_with("datasource") {
            while i < lines.len() && !lines[i].trim().starts_with('}') {
                let inner = lines[i].trim();
                if inner.starts_with("provider") {
                    if let Some(p) = extract_string_value(inner) {
                        provider = Some(p);
                    }
                }
                i += 1;
            }
        }

        // Parse model block
        if line.starts_with("model ") {
            let model_name = line
                .strip_prefix("model ")
                .and_then(|s| s.split_whitespace().next())
                .unwrap_or("")
                .to_string();

            let mut fields = Vec::new();
            let mut map_name = None;
            i += 1;

            while i < lines.len() && !lines[i].trim().starts_with('}') {
                let field_line = lines[i].trim();
                i += 1;

                if field_line.is_empty() || field_line.starts_with("//") {
                    continue;
                }

                // @@map directive
                if field_line.starts_with("@@map") {
                    if let Some(name) = extract_directive_arg(field_line) {
                        map_name = Some(name);
                    }
                    continue;
                }

                // Skip other directives (@@unique, @@index, etc.)
                if field_line.starts_with("@@") {
                    continue;
                }

                // Parse field definition
                if let Some(field) = parse_field(field_line) {
                    fields.push(field);
                }
            }

            models.insert(
                model_name.clone(),
                PrismaModel {
                    name: model_name,
                    map_name,
                    fields,
                },
            );
        }

        i += 1;
    }

    Ok(PrismaSchema { models, provider })
}

/// Parse a single field definition line.
fn parse_field(line: &str) -> Option<PrismaField> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }

    // Skip relation fields (they have @relation)
    if line.contains("@relation") && !line.contains("@id") {
        return None;
    }

    let name = parts[0].to_string();
    let mut prisma_type = parts[1].to_string();
    let optional = prisma_type.ends_with('?');
    if optional {
        prisma_type = prisma_type.trim_end_matches('?').to_string();
    }
    // Also handle array types
    prisma_type = prisma_type.trim_end_matches("[]").to_string();

    let is_id = line.contains("@id");

    let map_name = if line.contains("@map(") {
        extract_directive_arg_from(line, "@map")
    } else {
        None
    };

    let default = if line.contains("@default(") {
        extract_directive_arg_from(line, "@default")
    } else {
        None
    };

    Some(PrismaField {
        name,
        prisma_type,
        optional,
        is_id,
        map_name,
        default,
    })
}

/// Extract a string value from a line like `provider = "postgresql"`.
fn extract_string_value(line: &str) -> Option<String> {
    let after_eq = line.split('=').nth(1)?.trim();
    let unquoted = after_eq.trim_matches('"');
    Some(unquoted.to_string())
}

/// Extract the argument from a directive like `@@map("user")`.
fn extract_directive_arg(line: &str) -> Option<String> {
    let start = line.find('(')?;
    let end = line.find(')')?;
    let inner = &line[start + 1..end];
    Some(inner.trim_matches('"').to_string())
}

/// Extract the argument from a specific directive like `@map("user_id")` in a line.
fn extract_directive_arg_from(line: &str, directive: &str) -> Option<String> {
    let idx = line.find(directive)?;
    let rest = &line[idx + directive.len()..];
    let start = rest.find('(')?;
    let end = rest.find(')')?;
    let inner = &rest[start + 1..end];
    Some(inner.trim_matches('"').to_string())
}

/// Validate that a Prisma schema is compatible with better-auth's expected models.
pub fn validate_compatibility(schema: &PrismaSchema) -> Vec<String> {
    let mut warnings = Vec::new();

    let required_models = ["User", "Session", "Account", "Verification"];
    for model_name in &required_models {
        // Check both PascalCase and lowercase
        if !schema.models.contains_key(*model_name)
            && !schema
                .models
                .contains_key(&model_name.to_lowercase())
        {
            warnings.push(format!(
                "Required Prisma model '{}' not found in schema",
                model_name
            ));
        }
    }

    // Check User model has required fields
    let user_model = schema
        .models
        .get("User")
        .or_else(|| schema.models.get("user"));
    if let Some(user) = user_model {
        let required_fields = ["id", "email", "name"];
        for f in &required_fields {
            if !user.fields.iter().any(|field| field.name == *f) {
                warnings.push(format!(
                    "User model missing required field: '{f}'"
                ));
            }
        }
    }

    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_schema() {
        let schema = r#"
datasource db {
  provider = "sqlite"
  url      = "file:./dev.db"
}

model User {
  id            String    @id @default(cuid())
  email         String    @unique
  name          String?
  emailVerified Boolean   @default(false) @map("email_verified")
  createdAt     DateTime  @default(now()) @map("created_at")

  @@map("user")
}

model Session {
  id        String   @id @default(cuid())
  token     String   @unique
  userId    String   @map("user_id")
  expiresAt DateTime @map("expires_at")

  @@map("session")
}
        "#;

        let result = parse_schema(schema).unwrap();
        assert_eq!(result.provider, Some("sqlite".to_string()));
        assert_eq!(result.models.len(), 2);

        let user = result.models.get("User").unwrap();
        assert_eq!(user.name, "User");
        assert_eq!(user.map_name, Some("user".to_string()));
        assert!(user.fields.len() >= 4);
        assert!(user.fields[0].is_id);
        assert_eq!(user.fields[0].name, "id");
    }

    #[test]
    fn test_field_parsing() {
        let field = parse_field(
            r#"emailVerified Boolean @default(false) @map("email_verified")"#,
        )
        .unwrap();
        assert_eq!(field.name, "emailVerified");
        assert_eq!(field.prisma_type, "Boolean");
        assert!(!field.optional);
        assert_eq!(field.map_name, Some("email_verified".to_string()));
        assert_eq!(field.default, Some("false".to_string()));
    }

    #[test]
    fn test_optional_field() {
        let field = parse_field("name String?").unwrap();
        assert_eq!(field.name, "name");
        assert_eq!(field.prisma_type, "String");
        assert!(field.optional);
    }

    #[test]
    fn test_validate_compatibility() {
        let mut models = HashMap::new();
        models.insert(
            "User".to_string(),
            PrismaModel {
                name: "User".to_string(),
                map_name: Some("user".to_string()),
                fields: vec![
                    PrismaField {
                        name: "id".to_string(),
                        prisma_type: "String".to_string(),
                        optional: false,
                        is_id: true,
                        map_name: None,
                        default: None,
                    },
                    PrismaField {
                        name: "email".to_string(),
                        prisma_type: "String".to_string(),
                        optional: false,
                        is_id: false,
                        map_name: None,
                        default: None,
                    },
                    PrismaField {
                        name: "name".to_string(),
                        prisma_type: "String".to_string(),
                        optional: true,
                        is_id: false,
                        map_name: None,
                        default: None,
                    },
                ],
            },
        );

        let schema = PrismaSchema {
            models,
            provider: Some("sqlite".to_string()),
        };

        let warnings = validate_compatibility(&schema);
        // Should warn about missing Session, Account, Verification models
        assert!(warnings.len() >= 3);
    }
}
