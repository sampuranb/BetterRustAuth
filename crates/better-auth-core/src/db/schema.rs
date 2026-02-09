// Schema definition types — maps to packages/core/src/db/type.ts
// Defines the schema DSL used to describe auth tables and plugin-added fields.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Field types supported by the schema system.
/// Maps to `FieldType` in TypeScript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    String,
    Number,
    Boolean,
    Date,
}

/// Field attributes providing additional metadata about a schema field.
/// Maps to `FieldAttribute` in TypeScript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldAttribute {
    Unique,
    Required,
}

/// A single field definition within a table schema.
/// Maps to the field configuration objects in the TypeScript schema files.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaField {
    /// The field's data type.
    pub field_type: FieldType,
    /// Whether the field is required (non-nullable).
    #[serde(default)]
    pub required: bool,
    /// Whether the field must be unique across records.
    #[serde(default)]
    pub unique: bool,
    /// Default value for the field (as JSON).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<serde_json::Value>,
    /// If true, the field is auto-set to the current timestamp on create/update.
    #[serde(default)]
    pub auto_set_on_create: bool,
    #[serde(default)]
    pub auto_set_on_update: bool,
    /// Whether this field is an additional field added by a plugin.
    #[serde(default)]
    pub plugin_field: bool,
    /// The plugin ID that added this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_id: Option<String>,
    /// Reference to another table (foreign key).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<FieldReference>,
    /// Alias: same as `references`, used interchangeably.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<FieldReference>,
    /// If true, this field should be included in API output. Default: true.
    #[serde(default = "default_true")]
    pub returned: bool,
    /// Whether the field accepts user input. Default: true.
    /// Fields with `input: false` cannot be set by the user.
    #[serde(default = "default_true")]
    pub input: bool,
    /// Custom physical column name override (maps to TS `fieldName`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_name: Option<String>,
    /// Field name to use in the input (for API body parsing).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_name: Option<String>,
}

fn default_true() -> bool {
    true
}

impl SchemaField {
    /// Create a required string field.
    pub fn required_string() -> Self {
        Self {
            field_type: FieldType::String,
            required: true,
            unique: false,
            default_value: None,
            auto_set_on_create: false,
            auto_set_on_update: false,
            plugin_field: false,
            plugin_id: None,
            references: None,
            reference: None,
            returned: true,
            input: true,
            field_name: None,
            input_name: None,
        }
    }

    /// Create an optional string field.
    pub fn optional_string() -> Self {
        Self {
            required: false,
            ..Self::required_string()
        }
    }

    /// Create a required boolean field with a default value.
    pub fn boolean(default: bool) -> Self {
        Self {
            field_type: FieldType::Boolean,
            required: false,
            default_value: Some(serde_json::Value::Bool(default)),
            ..Self::required_string()
        }
    }

    /// Create a required date field (auto-set on creation).
    pub fn created_at() -> Self {
        Self {
            field_type: FieldType::Date,
            required: true,
            auto_set_on_create: true,
            ..Self::required_string()
        }
    }

    /// Create a required date field (auto-set on creation and update).
    pub fn updated_at() -> Self {
        Self {
            field_type: FieldType::Date,
            required: true,
            auto_set_on_create: true,
            auto_set_on_update: true,
            ..Self::required_string()
        }
    }

    pub fn with_unique(mut self) -> Self {
        self.unique = true;
        self
    }

    pub fn with_reference(mut self, table: &str, field: &str) -> Self {
        let fk = FieldReference {
            model: table.to_string(),
            table: table.to_string(),
            field: field.to_string(),
            on_delete: None,
        };
        self.references = Some(fk.clone());
        self.reference = Some(fk);
        self
    }

    pub fn hidden(mut self) -> Self {
        self.returned = false;
        self
    }
}

/// Foreign key reference configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldReference {
    /// Logical model name (e.g. "user").
    pub model: String,
    /// Physical table name (alias of model, may differ if renamed).
    #[serde(default)]
    pub table: String,
    /// Field name in the referenced table (usually "id").
    pub field: String,
    /// ON DELETE action (cascade, set null, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_delete: Option<String>,
}

/// A complete table definition within the auth schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthTable {
    /// The table name in the database.
    pub name: String,
    /// Map of field name → field definition.
    pub fields: HashMap<String, SchemaField>,
    /// Whether this table should allow field ordering.
    #[serde(default)]
    pub order: Option<i32>,
}

impl AuthTable {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            fields: HashMap::new(),
            order: None,
        }
    }

    pub fn field(mut self, name: &str, schema_field: SchemaField) -> Self {
        self.fields.insert(name.to_string(), schema_field);
        self
    }
}

/// The complete auth database schema — a collection of tables.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthSchema {
    pub tables: HashMap<String, AuthTable>,
}

impl AuthSchema {
    pub fn new() -> Self {
        Self {
            tables: HashMap::new(),
        }
    }

    pub fn table(mut self, table: AuthTable) -> Self {
        self.tables.insert(table.name.clone(), table);
        self
    }

    /// Build the default core auth schema (user, session, account, verification).
    pub fn core_schema() -> Self {
        let user = AuthTable::new("user")
            .field("id", SchemaField::required_string())
            .field("name", SchemaField::required_string())
            .field("email", SchemaField::required_string().with_unique())
            .field("emailVerified", SchemaField::boolean(false))
            .field("image", SchemaField::optional_string())
            .field("createdAt", SchemaField::created_at())
            .field("updatedAt", SchemaField::updated_at());

        let session = AuthTable::new("session")
            .field("id", SchemaField::required_string())
            .field("token", SchemaField::required_string().with_unique())
            .field(
                "expiresAt",
                SchemaField {
                    field_type: FieldType::Date,
                    required: true,
                    ..SchemaField::required_string()
                },
            )
            .field("ipAddress", SchemaField::optional_string())
            .field("userAgent", SchemaField::optional_string())
            .field(
                "userId",
                SchemaField::required_string().with_reference("user", "id"),
            )
            .field("createdAt", SchemaField::created_at())
            .field("updatedAt", SchemaField::updated_at());

        let account = AuthTable::new("account")
            .field("id", SchemaField::required_string())
            .field("accountId", SchemaField::required_string())
            .field("providerId", SchemaField::required_string())
            .field(
                "userId",
                SchemaField::required_string().with_reference("user", "id"),
            )
            .field("accessToken", SchemaField::optional_string())
            .field("refreshToken", SchemaField::optional_string())
            .field("idToken", SchemaField::optional_string())
            .field(
                "accessTokenExpiresAt",
                SchemaField {
                    field_type: FieldType::Date,
                    required: false,
                    ..SchemaField::required_string()
                },
            )
            .field(
                "refreshTokenExpiresAt",
                SchemaField {
                    field_type: FieldType::Date,
                    required: false,
                    ..SchemaField::required_string()
                },
            )
            .field("scope", SchemaField::optional_string())
            .field("password", SchemaField::optional_string().hidden())
            .field("createdAt", SchemaField::created_at())
            .field("updatedAt", SchemaField::updated_at());

        let verification = AuthTable::new("verification")
            .field("id", SchemaField::required_string())
            .field("identifier", SchemaField::required_string())
            .field("value", SchemaField::required_string())
            .field(
                "expiresAt",
                SchemaField {
                    field_type: FieldType::Date,
                    required: true,
                    ..SchemaField::required_string()
                },
            )
            .field("createdAt", SchemaField::created_at())
            .field("updatedAt", SchemaField::updated_at());

        Self::new()
            .table(user)
            .table(session)
            .table(account)
            .table(verification)
    }
}
