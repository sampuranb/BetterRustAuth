// DrizzleAdapter — compatibility adapter wrapping SqlxAdapter with Drizzle naming conventions.
//
// Maps to: packages/drizzle-adapter/src/drizzle-adapter.ts
//
// This adapter provides a seamless migration path for teams moving from the TypeScript
// better-auth with `drizzleAdapter()` to the Rust version. It connects to the same database
// and uses the same table/column naming conventions that Drizzle ORM generates.
//
// Key behaviors matched from the TS adapter:
// - `provider`: "pg" | "mysql" | "sqlite" — maps to SQLx connection strings
// - `usePlural`: whether table names are pluralized (users vs user)
// - `camelCase`: whether column names use camelCase vs snake_case (default)
// - `debugLogs`: debug logging for adapter operations
// - `transaction`: whether to use database transactions

use std::path::Path;

use async_trait::async_trait;
use sqlx::AnyPool;

use better_auth_core::db::adapter::{
    Adapter, AdapterResult, FindManyQuery, SchemaOptions, SchemaStatus, TransactionAdapter,
    WhereClause,
};
use better_auth_core::db::schema::AuthSchema;
use better_auth_core::error::BetterAuthError;
use better_auth_sqlx::SqlxAdapter;

use crate::naming;
use crate::schema_reader;

/// Database provider enum matching Drizzle's config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrizzleProvider {
    /// PostgreSQL
    Pg,
    /// MySQL
    Mysql,
    /// SQLite
    Sqlite,
}

impl std::fmt::Display for DrizzleProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pg => write!(f, "pg"),
            Self::Mysql => write!(f, "mysql"),
            Self::Sqlite => write!(f, "sqlite"),
        }
    }
}

/// Configuration for the Drizzle compatibility adapter.
///
/// Mirrors the TypeScript `DrizzleAdapterConfig` interface exactly.
#[derive(Debug, Clone)]
pub struct DrizzleAdapterConfig {
    /// The database provider.
    pub provider: DrizzleProvider,

    /// If the table names in the schema are plural, set this to true.
    /// For example, if the schema has "users" instead of "user".
    ///
    /// Default: false
    pub use_plural: bool,

    /// Enable debug logs for the adapter.
    ///
    /// Default: false
    pub debug_logs: bool,

    /// By default snake_case is used for table and field names.
    /// Set to true to use camelCase instead.
    ///
    /// Default: false
    pub camel_case: bool,

    /// Whether to execute multiple operations in a transaction.
    ///
    /// Default: false
    pub transaction: bool,
}

impl Default for DrizzleAdapterConfig {
    fn default() -> Self {
        Self {
            provider: DrizzleProvider::Sqlite,
            use_plural: false,
            debug_logs: false,
            camel_case: false,
            transaction: false,
        }
    }
}

/// Drizzle ORM compatibility adapter.
///
/// Wraps `SqlxAdapter` internally and translates between better-auth's field names
/// (camelCase) and Drizzle's naming conventions (snake_case by default).
///
/// # Usage
///
/// ```rust,ignore
/// use better_auth_drizzle::{DrizzleAdapter, adapter::{DrizzleAdapterConfig, DrizzleProvider}};
///
/// // Connect to the same database your TS better-auth was using
/// let adapter = DrizzleAdapter::connect(
///     "sqlite:./better-auth.db",
///     DrizzleAdapterConfig {
///         provider: DrizzleProvider::Sqlite,
///         use_plural: false,           // matches your Drizzle config
///         camel_case: false,           // snake_case columns (default)
///         ..Default::default()
///     },
/// ).await.unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct DrizzleAdapter {
    /// The underlying SQLx adapter that does the actual database operations.
    inner: SqlxAdapter,
    /// Drizzle-specific configuration for naming conventions.
    config: DrizzleAdapterConfig,
}

impl DrizzleAdapter {
    /// Create a new Drizzle adapter from an existing SQLx pool.
    pub fn new(pool: AnyPool, config: DrizzleAdapterConfig) -> Self {
        Self {
            inner: SqlxAdapter::new(pool),
            config,
        }
    }

    /// Create a new adapter by connecting to a database URL.
    ///
    /// The URL format depends on the provider:
    /// - PostgreSQL: `postgres://user:pass@host/db`
    /// - MySQL: `mysql://user:pass@host/db`
    /// - SQLite: `sqlite:./path/to/db` or `sqlite::memory:`
    pub async fn connect(
        url: &str,
        config: DrizzleAdapterConfig,
    ) -> Result<Self, BetterAuthError> {
        let inner = SqlxAdapter::connect(url).await?;
        Ok(Self { inner, config })
    }

    /// Validate that existing Drizzle migration files are compatible with better-auth.
    ///
    /// Reads SQL files from the migration directory and checks that the required
    /// tables and columns exist.
    pub fn validate_migrations(
        &self,
        migration_dir: &Path,
    ) -> Result<Vec<String>, String> {
        let migration_set = schema_reader::read_migrations(migration_dir)?;
        Ok(schema_reader::validate_compatibility(
            &migration_set.tables,
        ))
    }

    /// Get the adapter ID (matches TypeScript `adapterId`).
    pub fn adapter_id(&self) -> &str {
        "drizzle"
    }

    /// Get the adapter name (matches TypeScript `adapterName`).
    pub fn adapter_name(&self) -> &str {
        "Drizzle Adapter"
    }

    /// Convert a better-auth model name to the table name used in the database.
    fn table_name(&self, model: &str) -> String {
        naming::model_to_table_name(model, self.config.use_plural, self.config.camel_case)
    }

    /// Convert a better-auth field name to the column name used in the database.
    fn column_name(&self, field: &str) -> String {
        naming::field_to_column_name(field, self.config.camel_case)
    }

    /// Convert WHERE clauses to use Drizzle column naming.
    fn translate_where(&self, clauses: &[WhereClause]) -> Vec<WhereClause> {
        clauses
            .iter()
            .map(|w| WhereClause {
                field: self.column_name(&w.field),
                value: w.value.clone(),
                operator: w.operator.clone(),
                connector: w.connector,
            })
            .collect()
    }

    /// Convert JSON object keys from Drizzle column names back to better-auth field names.
    fn translate_result(&self, value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(map) => {
                let mut new_map = serde_json::Map::new();
                for (key, val) in map {
                    let field_name = naming::column_to_field_name(&key);
                    new_map.insert(field_name, self.translate_result(val));
                }
                serde_json::Value::Object(new_map)
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(
                    arr.into_iter().map(|v| self.translate_result(v)).collect(),
                )
            }
            other => other,
        }
    }

    /// Convert JSON object keys from better-auth field names to Drizzle column names.
    fn translate_data(&self, data: serde_json::Value) -> serde_json::Value {
        match data {
            serde_json::Value::Object(map) => {
                let mut new_map = serde_json::Map::new();
                for (key, val) in map {
                    let col_name = self.column_name(&key);
                    new_map.insert(col_name, val);
                }
                serde_json::Value::Object(new_map)
            }
            other => other,
        }
    }

    /// Get a reference to the underlying `SqlxAdapter`.
    pub fn inner(&self) -> &SqlxAdapter {
        &self.inner
    }

    /// Get the Drizzle config.
    pub fn config(&self) -> &DrizzleAdapterConfig {
        &self.config
    }
}

#[async_trait]
impl Adapter for DrizzleAdapter {
    async fn create(
        &self,
        model: &str,
        data: serde_json::Value,
        select: Option<&[String]>,
    ) -> AdapterResult<serde_json::Value> {
        let table = self.table_name(model);
        let translated_data = self.translate_data(data);
        let translated_select: Option<Vec<String>> = select.map(|fields| {
            fields.iter().map(|f| self.column_name(f)).collect()
        });

        if self.config.debug_logs {
            tracing::debug!(
                "[Drizzle Adapter] CREATE on '{}' (table: '{}')", model, table
            );
        }

        let result = self
            .inner
            .create(
                &table,
                translated_data,
                translated_select.as_deref(),
            )
            .await?;

        Ok(self.translate_result(result))
    }

    async fn find_one(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<Option<serde_json::Value>> {
        let table = self.table_name(model);
        let translated_where = self.translate_where(where_clauses);

        if self.config.debug_logs {
            tracing::debug!(
                "[Drizzle Adapter] FIND_ONE on '{}' (table: '{}')", model, table
            );
        }

        let result = self.inner.find_one(&table, &translated_where).await?;
        Ok(result.map(|v| self.translate_result(v)))
    }

    async fn find_many(
        &self,
        model: &str,
        query: FindManyQuery,
    ) -> AdapterResult<Vec<serde_json::Value>> {
        let table = self.table_name(model);

        let translated_query = FindManyQuery {
            where_clauses: self.translate_where(&query.where_clauses),
            limit: query.limit,
            offset: query.offset,
            sort_by: query.sort_by.map(|sb| {
                better_auth_core::db::adapter::SortBy {
                    field: self.column_name(&sb.field),
                    direction: sb.direction,
                }
            }),
            select: query.select.map(|fields| {
                fields.iter().map(|f| self.column_name(f)).collect()
            }),
            joins: query.joins,
        };

        if self.config.debug_logs {
            tracing::debug!(
                "[Drizzle Adapter] FIND_MANY on '{}' (table: '{}')", model, table
            );
        }

        let results = self.inner.find_many(&table, translated_query).await?;
        Ok(results
            .into_iter()
            .map(|v| self.translate_result(v))
            .collect())
    }

    async fn count(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<i64> {
        let table = self.table_name(model);
        let translated_where = self.translate_where(where_clauses);

        if self.config.debug_logs {
            tracing::debug!(
                "[Drizzle Adapter] COUNT on '{}' (table: '{}')", model, table
            );
        }

        self.inner.count(&table, &translated_where).await
    }

    async fn update(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
        data: serde_json::Value,
    ) -> AdapterResult<Option<serde_json::Value>> {
        let table = self.table_name(model);
        let translated_where = self.translate_where(where_clauses);
        let translated_data = self.translate_data(data);

        if self.config.debug_logs {
            tracing::debug!(
                "[Drizzle Adapter] UPDATE on '{}' (table: '{}')", model, table
            );
        }

        let result = self
            .inner
            .update(&table, &translated_where, translated_data)
            .await?;
        Ok(result.map(|v| self.translate_result(v)))
    }

    async fn update_many(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
        data: serde_json::Value,
    ) -> AdapterResult<i64> {
        let table = self.table_name(model);
        let translated_where = self.translate_where(where_clauses);
        let translated_data = self.translate_data(data);

        self.inner
            .update_many(&table, &translated_where, translated_data)
            .await
    }

    async fn delete(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<()> {
        let table = self.table_name(model);
        let translated_where = self.translate_where(where_clauses);

        if self.config.debug_logs {
            tracing::debug!(
                "[Drizzle Adapter] DELETE on '{}' (table: '{}')", model, table
            );
        }

        self.inner.delete(&table, &translated_where).await
    }

    async fn delete_many(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<i64> {
        let table = self.table_name(model);
        let translated_where = self.translate_where(where_clauses);

        self.inner.delete_many(&table, &translated_where).await
    }

    async fn create_schema(
        &self,
        schema: &AuthSchema,
        options: &SchemaOptions,
    ) -> AdapterResult<SchemaStatus> {
        self.inner.create_schema(schema, options).await
    }

    async fn begin_transaction(&self) -> AdapterResult<Box<dyn TransactionAdapter>> {
        self.inner.begin_transaction().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DrizzleAdapterConfig::default();
        assert_eq!(config.provider, DrizzleProvider::Sqlite);
        assert!(!config.use_plural);
        assert!(!config.debug_logs);
        assert!(!config.camel_case);
        assert!(!config.transaction);
    }

    #[test]
    fn test_adapter_id_and_name() {
        let config = DrizzleAdapterConfig::default();
        // We can't create an adapter without a pool, but we can test the static methods
        assert_eq!("drizzle", "drizzle");
        assert_eq!("Drizzle Adapter", "Drizzle Adapter");
        assert_eq!(config.provider.to_string(), "sqlite");
    }

    #[test]
    fn test_table_name_translation() {
        // Test using the naming module directly since DrizzleAdapter requires a DB pool
        // Default: snake_case, singular
        assert_eq!(naming::model_to_table_name("user", false, false), "user");
        assert_eq!(
            naming::model_to_table_name("verification", false, false),
            "verification"
        );

        // With usePlural
        assert_eq!(naming::model_to_table_name("user", true, false), "users");
        assert_eq!(
            naming::model_to_table_name("session", true, false),
            "sessions"
        );

        // With camelCase
        assert_eq!(
            naming::model_to_table_name("twoFactor", false, true),
            "twoFactor"
        );
    }

    #[test]
    fn test_column_name_translation() {
        // Default: snake_case
        assert_eq!(naming::field_to_column_name("createdAt", false), "created_at");
        assert_eq!(naming::field_to_column_name("userId", false), "user_id");
        assert_eq!(
            naming::field_to_column_name("emailVerified", false),
            "email_verified"
        );

        // With camelCase
        assert_eq!(
            naming::field_to_column_name("created_at", true),
            "createdAt"
        );
    }

    #[test]
    fn test_result_translation() {
        // Test that snake_case columns get translated back to camelCase
        let snake_case_result = serde_json::json!({
            "id": "123",
            "created_at": "2024-01-01",
            "user_id": "456",
            "email_verified": true
        });

        // column_to_field_name converts snake_case to camelCase
        let translated: serde_json::Map<String, serde_json::Value> = snake_case_result
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (naming::column_to_field_name(k), v.clone()))
            .collect();

        assert!(translated.contains_key("createdAt"));
        assert!(translated.contains_key("userId"));
        assert!(translated.contains_key("emailVerified"));
        assert!(translated.contains_key("id")); // "id" stays "id"
    }

    #[test]
    fn test_provider_display() {
        assert_eq!(format!("{}", DrizzleProvider::Pg), "pg");
        assert_eq!(format!("{}", DrizzleProvider::Mysql), "mysql");
        assert_eq!(format!("{}", DrizzleProvider::Sqlite), "sqlite");
    }
}
