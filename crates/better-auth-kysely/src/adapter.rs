// KyselyAdapter — compatibility adapter wrapping SqlxAdapter with Kysely conventions.
//
// Maps to: packages/kysely-adapter/src/kysely-adapter.ts
//
// Key behaviors matched from the TS adapter:
// - `type`: "postgres" | "mysql" | "sqlite" | "mssql" — database type detection
// - `usePlural`: whether table names are pluralized
// - `debugLogs`: debug logging
// - `transaction`: transaction support
// - MySQL RETURNING workaround (handled by SQLx natively)
// - MSSQL OUTPUT workaround (handled by SQLx natively)

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

/// Database type enum matching Kysely's `KyselyDatabaseType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KyselyDatabaseType {
    Postgres,
    Mysql,
    Sqlite,
    Mssql,
}

impl std::fmt::Display for KyselyDatabaseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Postgres => write!(f, "postgres"),
            Self::Mysql => write!(f, "mysql"),
            Self::Sqlite => write!(f, "sqlite"),
            Self::Mssql => write!(f, "mssql"),
        }
    }
}

/// Configuration for the Kysely compatibility adapter.
///
/// Mirrors the TypeScript `KyselyAdapterConfig` interface.
#[derive(Debug, Clone)]
pub struct KyselyAdapterConfig {
    /// Database type.
    pub database_type: Option<KyselyDatabaseType>,

    /// Use plural for table names.
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

impl Default for KyselyAdapterConfig {
    fn default() -> Self {
        Self {
            database_type: None,
            use_plural: false,
            debug_logs: false,
            transaction: false,
        }
    }
}

/// Kysely compatibility adapter.
///
/// Wraps `SqlxAdapter` internally and translates between better-auth's field names
/// (camelCase) and the snake_case column names that Kysely uses in the database.
///
/// # Usage
///
/// ```rust,ignore
/// use better_auth_kysely::{KyselyAdapter, adapter::KyselyAdapterConfig};
///
/// let adapter = KyselyAdapter::connect(
///     "sqlite:./better-auth.db",
///     KyselyAdapterConfig::default(),
/// ).await.unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct KyselyAdapter {
    inner: SqlxAdapter,
    config: KyselyAdapterConfig,
}

impl KyselyAdapter {
    /// Create a new Kysely adapter from an existing SQLx pool.
    pub fn new(pool: AnyPool, config: KyselyAdapterConfig) -> Self {
        Self {
            inner: SqlxAdapter::new(pool),
            config,
        }
    }

    /// Create a new adapter by connecting to a database URL.
    pub async fn connect(
        url: &str,
        config: KyselyAdapterConfig,
    ) -> Result<Self, BetterAuthError> {
        let inner = SqlxAdapter::connect(url).await?;
        Ok(Self { inner, config })
    }

    /// Get the adapter ID.
    pub fn adapter_id(&self) -> &str {
        "kysely"
    }

    /// Get the adapter name.
    pub fn adapter_name(&self) -> &str {
        "Kysely Adapter"
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
impl Adapter for KyselyAdapter {
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
            tracing::debug!("[Kysely Adapter] CREATE on '{}' (table: '{}')", model, table);
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
            tracing::debug!("[Kysely Adapter] FIND_ONE on '{}' (table: '{}')", model, table);
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
            tracing::debug!("[Kysely Adapter] FIND_MANY on '{}' (table: '{}')", model, table);
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
            tracing::debug!("[Kysely Adapter] UPDATE on '{}' (table: '{}')", model, table);
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
        let config = KyselyAdapterConfig::default();
        assert!(config.database_type.is_none());
        assert!(!config.use_plural);
        assert!(!config.debug_logs);
        assert!(!config.transaction);
    }

    #[test]
    fn test_database_type_display() {
        assert_eq!(format!("{}", KyselyDatabaseType::Postgres), "postgres");
        assert_eq!(format!("{}", KyselyDatabaseType::Mysql), "mysql");
        assert_eq!(format!("{}", KyselyDatabaseType::Sqlite), "sqlite");
        assert_eq!(format!("{}", KyselyDatabaseType::Mssql), "mssql");
    }

    #[test]
    fn test_naming_roundtrip() {
        let field = "createdAt";
        let column = naming::field_to_column_name(field);
        assert_eq!(column, "created_at");
        let back = naming::column_to_field_name(&column);
        assert_eq!(back, "createdAt");
    }

    #[test]
    fn test_table_name() {
        assert_eq!(naming::model_to_table_name("user", false), "user");
        assert_eq!(naming::model_to_table_name("user", true), "users");
        assert_eq!(naming::model_to_table_name("session", true), "sessions");
    }
}
