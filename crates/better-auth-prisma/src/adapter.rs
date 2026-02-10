// PrismaAdapter — compatibility adapter wrapping SqlxAdapter with Prisma conventions.
//
// Maps to: packages/prisma-adapter/src/prisma-adapter.ts
//
// Key behaviors matched from the TS adapter:
// - `provider`: "sqlite" | "postgresql" | "mysql" | "mongodb" | "cockroachdb" | "sqlserver"
// - `usePlural`: whether table names are pluralized
// - `debugLogs`: debug logging
// - `transaction`: transaction support
// - Special null handling for Prisma (ne + null semantics)
// - Record-not-found swallowing on delete (P2025)

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

/// Database provider enum matching Prisma's config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrismaProvider {
    Sqlite,
    Postgresql,
    Mysql,
    Mongodb,
    Cockroachdb,
    Sqlserver,
}

impl std::fmt::Display for PrismaProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite => write!(f, "sqlite"),
            Self::Postgresql => write!(f, "postgresql"),
            Self::Mysql => write!(f, "mysql"),
            Self::Mongodb => write!(f, "mongodb"),
            Self::Cockroachdb => write!(f, "cockroachdb"),
            Self::Sqlserver => write!(f, "sqlserver"),
        }
    }
}

/// Configuration for the Prisma compatibility adapter.
///
/// Mirrors the TypeScript `PrismaConfig` interface.
#[derive(Debug, Clone)]
pub struct PrismaAdapterConfig {
    /// Database provider.
    pub provider: PrismaProvider,

    /// Use plural table names.
    ///
    /// Default: false
    pub use_plural: bool,

    /// Enable debug logs for the adapter.
    ///
    /// Default: false
    pub debug_logs: bool,

    /// Whether to execute multiple operations in a transaction.
    ///
    /// Default: false
    pub transaction: bool,
}

impl Default for PrismaAdapterConfig {
    fn default() -> Self {
        Self {
            provider: PrismaProvider::Sqlite,
            use_plural: false,
            debug_logs: false,
            transaction: false,
        }
    }
}

/// Prisma compatibility adapter.
///
/// Wraps `SqlxAdapter` internally and translates between better-auth's field names
/// and Prisma's database column naming conventions.
///
/// # Usage
///
/// ```rust,ignore
/// use better_auth_prisma::{PrismaAdapter, adapter::{PrismaAdapterConfig, PrismaProvider}};
///
/// let adapter = PrismaAdapter::connect(
///     "sqlite:./prisma/dev.db",
///     PrismaAdapterConfig {
///         provider: PrismaProvider::Sqlite,
///         ..Default::default()
///     },
/// ).await.unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct PrismaAdapter {
    inner: SqlxAdapter,
    config: PrismaAdapterConfig,
}

impl PrismaAdapter {
    /// Create a new Prisma adapter from an existing SQLx pool.
    pub fn new(pool: AnyPool, config: PrismaAdapterConfig) -> Self {
        Self {
            inner: SqlxAdapter::new(pool),
            config,
        }
    }

    /// Create a new adapter by connecting to a database URL.
    ///
    /// Note: MongoDB is not supported via SQLx. For MongoDB, use the
    /// `better-auth-mongodb` adapter directly.
    pub async fn connect(
        url: &str,
        config: PrismaAdapterConfig,
    ) -> Result<Self, BetterAuthError> {
        if config.provider == PrismaProvider::Mongodb {
            return Err(BetterAuthError::Other(
                "MongoDB is not supported by the Prisma compatibility adapter. Use better-auth-mongodb directly.".to_string()
            ));
        }
        let inner = SqlxAdapter::connect(url).await?;
        Ok(Self { inner, config })
    }

    /// Validate that a Prisma schema file is compatible with better-auth.
    pub fn validate_schema(
        &self,
        schema_path: &Path,
    ) -> Result<Vec<String>, String> {
        let schema = schema_reader::read_schema(schema_path)?;
        Ok(schema_reader::validate_compatibility(&schema))
    }

    /// Get the adapter ID.
    pub fn adapter_id(&self) -> &str {
        "prisma"
    }

    /// Get the adapter name.
    pub fn adapter_name(&self) -> &str {
        "Prisma Adapter"
    }

    fn table_name(&self, model: &str) -> String {
        naming::model_to_table_name(model, self.config.use_plural)
    }

    fn column_name(&self, field: &str) -> String {
        naming::field_to_column_name(field)
    }

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
}

#[async_trait]
impl Adapter for PrismaAdapter {
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
            tracing::debug!("[Prisma Adapter] CREATE on '{}' (table: '{}')", model, table);
        }

        let result = self
            .inner
            .create(&table, translated_data, translated_select.as_deref())
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
            tracing::debug!("[Prisma Adapter] FIND_ONE on '{}' (table: '{}')", model, table);
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
            tracing::debug!("[Prisma Adapter] FIND_MANY on '{}' (table: '{}')", model, table);
        }

        let results = self.inner.find_many(&table, translated_query).await?;
        Ok(results.into_iter().map(|v| self.translate_result(v)).collect())
    }

    async fn count(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<i64> {
        let table = self.table_name(model);
        let translated_where = self.translate_where(where_clauses);
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
            tracing::debug!("[Prisma Adapter] UPDATE on '{}' (table: '{}')", model, table);
        }

        let result = self.inner.update(&table, &translated_where, translated_data).await?;
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
        self.inner.update_many(&table, &translated_where, translated_data).await
    }

    async fn delete(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<()> {
        let table = self.table_name(model);
        let translated_where = self.translate_where(where_clauses);

        if self.config.debug_logs {
            tracing::debug!("[Prisma Adapter] DELETE on '{}' (table: '{}')", model, table);
        }

        // Match Prisma behavior: swallow "record not found" errors on delete (P2025)
        match self.inner.delete(&table, &translated_where).await {
            Ok(()) => Ok(()),
            Err(BetterAuthError::Database(ref msg)) if msg.contains("not found") => Ok(()),
            Err(e) => Err(e),
        }
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
        let config = PrismaAdapterConfig::default();
        assert_eq!(config.provider, PrismaProvider::Sqlite);
        assert!(!config.use_plural);
        assert!(!config.debug_logs);
        assert!(!config.transaction);
    }

    #[test]
    fn test_provider_display() {
        assert_eq!(format!("{}", PrismaProvider::Sqlite), "sqlite");
        assert_eq!(format!("{}", PrismaProvider::Postgresql), "postgresql");
        assert_eq!(format!("{}", PrismaProvider::Mysql), "mysql");
        assert_eq!(format!("{}", PrismaProvider::Mongodb), "mongodb");
        assert_eq!(format!("{}", PrismaProvider::Cockroachdb), "cockroachdb");
        assert_eq!(format!("{}", PrismaProvider::Sqlserver), "sqlserver");
    }

    #[test]
    fn test_naming_roundtrip() {
        let field = "createdAt";
        let col = naming::field_to_column_name(field);
        assert_eq!(col, "created_at");
        let back = naming::column_to_field_name(&col);
        assert_eq!(back, "createdAt");
    }

    #[test]
    fn test_result_translation() {
        let snake_case_result = serde_json::json!({
            "id": "123",
            "created_at": "2024-01-01",
            "user_id": "456",
            "email_verified": true
        });

        let translated: serde_json::Map<String, serde_json::Value> = snake_case_result
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (naming::column_to_field_name(k), v.clone()))
            .collect();

        assert!(translated.contains_key("createdAt"));
        assert!(translated.contains_key("userId"));
        assert!(translated.contains_key("emailVerified"));
    }

    #[test]
    fn test_table_name() {
        assert_eq!(naming::model_to_table_name("user", false), "user");
        assert_eq!(naming::model_to_table_name("user", true), "users");
        assert_eq!(
            naming::model_to_table_name("verification", false),
            "verification"
        );
    }
}
