// SqlxAdapter — concrete implementation of the core Adapter trait using sqlx::Any.
//
// Uses the `sqlx::any` driver to support Postgres, MySQL, and SQLite through
// a single runtime-polymorphic pool.

use async_trait::async_trait;
use sqlx::any::AnyRow;
use sqlx::{AnyPool, Column, Row};

use better_auth_core::db::adapter::{
    Adapter, AdapterResult, FindManyQuery, SchemaOptions, SchemaStatus, TransactionAdapter,
    WhereClause,
};
use better_auth_core::db::schema::AuthSchema;
use better_auth_core::error::BetterAuthError;

use crate::query_builder;
use crate::transaction::SqlxTransactionAdapter;

/// SQLx-based database adapter.
///
/// Wraps an `AnyPool` and implements the core `Adapter` trait.
#[derive(Debug, Clone)]
pub struct SqlxAdapter {
    pool: AnyPool,
}

impl SqlxAdapter {
    /// Create a new adapter from an existing pool.
    pub fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    /// Create a new adapter by connecting to a database URL.
    pub async fn connect(url: &str) -> Result<Self, BetterAuthError> {
        // Install default drivers
        sqlx::any::install_default_drivers();

        // For SQLite in-memory databases, limit to 1 connection since each
        // connection to "sqlite::memory:" creates a separate database.
        let pool = if url.contains(":memory:") || url.contains("mode=memory") {
            sqlx::any::AnyPoolOptions::new()
                .max_connections(1)
                .connect(url)
                .await
        } else {
            AnyPool::connect(url).await
        }
        .map_err(|e| BetterAuthError::Other(format!("Database connection failed: {e}")))?;

        Ok(Self { pool })
    }

    /// Get a reference to the underlying pool.
    pub fn pool(&self) -> &AnyPool {
        &self.pool
    }
}

/// Convert an `AnyRow` into a `serde_json::Value` (JSON object).
///
/// Reads all columns from the row and produces a `{ "col": value, ... }` object.
pub(crate) fn row_to_json(row: &AnyRow) -> serde_json::Value {
    let mut map = serde_json::Map::new();

    for col in row.columns() {
        let name = col.name();
        // Try to extract as different types in priority order
        let value: serde_json::Value = if let Ok(v) = row.try_get::<String, _>(name) {
            serde_json::Value::String(v)
        } else if let Ok(v) = row.try_get::<i64, _>(name) {
            serde_json::Value::Number(v.into())
        } else if let Ok(v) = row.try_get::<i32, _>(name) {
            serde_json::Value::Number(v.into())
        } else if let Ok(v) = row.try_get::<f64, _>(name) {
            serde_json::Number::from_f64(v)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null)
        } else if let Ok(v) = row.try_get::<bool, _>(name) {
            serde_json::Value::Bool(v)
        } else {
            // NULL or unsupported type
            serde_json::Value::Null
        };

        map.insert(name.to_string(), value);
    }

    serde_json::Value::Object(map)
}

/// Typed bind value to avoid lifetime issues with sqlx.
#[derive(Debug, Clone)]
pub(crate) enum BindValue {
    Text(String),
    Int(i64),
    Float(f64),
    Null,
}

/// Execute a query with bind values and return rows.
pub(crate) async fn execute_fetch_all(
    pool: &AnyPool,
    sql: &str,
    binds: &[serde_json::Value],
) -> Result<Vec<AnyRow>, BetterAuthError> {
    let bind_vals: Vec<BindValue> = binds.iter().map(json_to_bind).collect();
    let mut query = sqlx::query(sql);
    for bv in &bind_vals {
        query = match bv {
            BindValue::Text(s) => query.bind(s.as_str()),
            BindValue::Int(i) => query.bind(*i),
            BindValue::Float(f) => query.bind(*f),
            BindValue::Null => query.bind(Option::<String>::None),
        };
    }
    query
        .fetch_all(pool)
        .await
        .map_err(|e| BetterAuthError::Other(format!("Query failed: {e}")))
}

/// Execute a query with bind values and return optional row.
pub(crate) async fn execute_fetch_optional(
    pool: &AnyPool,
    sql: &str,
    binds: &[serde_json::Value],
) -> Result<Option<AnyRow>, BetterAuthError> {
    let bind_vals: Vec<BindValue> = binds.iter().map(json_to_bind).collect();
    let mut query = sqlx::query(sql);
    for bv in &bind_vals {
        query = match bv {
            BindValue::Text(s) => query.bind(s.as_str()),
            BindValue::Int(i) => query.bind(*i),
            BindValue::Float(f) => query.bind(*f),
            BindValue::Null => query.bind(Option::<String>::None),
        };
    }
    query
        .fetch_optional(pool)
        .await
        .map_err(|e| BetterAuthError::Other(format!("Query failed: {e}")))
}

/// Execute a statement with bind values and return affected rows.
pub(crate) async fn execute_statement(
    pool: &AnyPool,
    sql: &str,
    binds: &[serde_json::Value],
) -> Result<u64, BetterAuthError> {
    let bind_vals: Vec<BindValue> = binds.iter().map(json_to_bind).collect();
    let mut query = sqlx::query(sql);
    for bv in &bind_vals {
        query = match bv {
            BindValue::Text(s) => query.bind(s.as_str()),
            BindValue::Int(i) => query.bind(*i),
            BindValue::Float(f) => query.bind(*f),
            BindValue::Null => query.bind(Option::<String>::None),
        };
    }
    let result = query
        .execute(pool)
        .await
        .map_err(|e| BetterAuthError::Other(format!("Execute failed: {e}")))?;
    Ok(result.rows_affected())
}

fn json_to_bind(v: &serde_json::Value) -> BindValue {
    match v {
        serde_json::Value::String(s) => BindValue::Text(s.clone()),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                BindValue::Int(i)
            } else if let Some(f) = n.as_f64() {
                BindValue::Float(f)
            } else {
                BindValue::Text(n.to_string())
            }
        }
        serde_json::Value::Bool(b) => BindValue::Int(if *b { 1 } else { 0 }),
        serde_json::Value::Null => BindValue::Null,
        _ => BindValue::Text(v.to_string()),
    }
}

#[async_trait]
impl Adapter for SqlxAdapter {
    async fn create(
        &self,
        model: &str,
        data: serde_json::Value,
        _select: Option<&[String]>,
    ) -> AdapterResult<serde_json::Value> {
        let frag = query_builder::build_insert(model, &data);
        // Execute the INSERT (no RETURNING — not supported by sqlx Any)
        execute_statement(&self.pool, &frag.sql, &frag.binds).await?;

        // Select back the inserted row. Use 'id' if present, otherwise return input data.
        if let Some(id) = data.get("id") {
            let where_frag = query_builder::build_where(
                &[WhereClause::eq("id", id.as_str().unwrap_or_default())],
                0,
            );
            let select_sql = format!(
                "SELECT * FROM {}{}",
                query_builder::quote_identifier(model),
                where_frag.sql
            );
            let row = execute_fetch_optional(&self.pool, &select_sql, &where_frag.binds)
                .await?
                .ok_or_else(|| BetterAuthError::Other("Create: select-back failed".into()))?;
            Ok(row_to_json(&row))
        } else {
            // No ID — return input data as-is
            Ok(data)
        }
    }

    async fn find_one(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<Option<serde_json::Value>> {
        let where_frag = query_builder::build_where(where_clauses, 0);
        let sql = format!(
            "SELECT * FROM {} {} LIMIT 1",
            query_builder::quote_identifier(model),
            where_frag.sql
        );
        let row = execute_fetch_optional(&self.pool, &sql, &where_frag.binds).await?;
        Ok(row.as_ref().map(row_to_json))
    }

    async fn find_many(
        &self,
        model: &str,
        query_params: FindManyQuery,
    ) -> AdapterResult<Vec<serde_json::Value>> {
        let where_frag = query_builder::build_where(&query_params.where_clauses, 0);
        let order_by = query_builder::build_order_by(&query_params);
        let limit_offset = query_builder::build_limit_offset(&query_params);
        let sql = format!(
            "SELECT * FROM {}{}{}{}",
            query_builder::quote_identifier(model),
            where_frag.sql,
            order_by,
            limit_offset
        );
        let rows = execute_fetch_all(&self.pool, &sql, &where_frag.binds).await?;
        Ok(rows.iter().map(row_to_json).collect())
    }

    async fn count(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<i64> {
        let where_frag = query_builder::build_where(where_clauses, 0);
        let sql = format!(
            "SELECT COUNT(*) as count FROM {}{}",
            query_builder::quote_identifier(model),
            where_frag.sql
        );
        let row = execute_fetch_optional(&self.pool, &sql, &where_frag.binds)
            .await?
            .ok_or_else(|| BetterAuthError::Other("Count returned no rows".into()))?;
        let count: i64 = row
            .try_get("count")
            .map_err(|e| BetterAuthError::Other(format!("Count decode failed: {e}")))?;
        Ok(count)
    }

    async fn update(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
        data: serde_json::Value,
    ) -> AdapterResult<Option<serde_json::Value>> {
        let set_frag = query_builder::build_update_set(&data, 0);
        let where_frag = query_builder::build_where(where_clauses, set_frag.binds.len());
        let sql = format!(
            "UPDATE {} SET {}{}",
            query_builder::quote_identifier(model),
            set_frag.sql,
            where_frag.sql
        );
        let mut all_binds = set_frag.binds;
        all_binds.extend(where_frag.binds);
        let affected = execute_statement(&self.pool, &sql, &all_binds).await?;
        if affected == 0 {
            return Ok(None);
        }
        // Select back the updated row
        let select_where = query_builder::build_where(where_clauses, 0);
        let select_sql = format!(
            "SELECT * FROM {}{}",
            query_builder::quote_identifier(model),
            select_where.sql
        );
        let row = execute_fetch_optional(&self.pool, &select_sql, &select_where.binds).await?;
        Ok(row.as_ref().map(row_to_json))
    }

    async fn update_many(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
        data: serde_json::Value,
    ) -> AdapterResult<i64> {
        let set_frag = query_builder::build_update_set(&data, 0);
        let where_frag = query_builder::build_where(where_clauses, set_frag.binds.len());
        let sql = format!(
            "UPDATE {} SET {}{}",
            query_builder::quote_identifier(model),
            set_frag.sql,
            where_frag.sql
        );
        let mut all_binds = set_frag.binds;
        all_binds.extend(where_frag.binds);
        let affected = execute_statement(&self.pool, &sql, &all_binds).await?;
        Ok(affected as i64)
    }

    async fn delete(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<()> {
        let where_frag = query_builder::build_where(where_clauses, 0);
        let sql = format!(
            "DELETE FROM {}{}",
            query_builder::quote_identifier(model),
            where_frag.sql
        );
        execute_statement(&self.pool, &sql, &where_frag.binds).await?;
        Ok(())
    }

    async fn delete_many(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<i64> {
        let where_frag = query_builder::build_where(where_clauses, 0);
        let sql = format!(
            "DELETE FROM {}{}",
            query_builder::quote_identifier(model),
            where_frag.sql
        );
        let affected = execute_statement(&self.pool, &sql, &where_frag.binds).await?;
        Ok(affected as i64)
    }

    async fn create_schema(
        &self,
        schema: &AuthSchema,
        options: &SchemaOptions,
    ) -> AdapterResult<SchemaStatus> {
        crate::schema::create_schema(&self.pool, schema, options).await
    }

    async fn begin_transaction(&self) -> AdapterResult<Box<dyn TransactionAdapter>> {
        let tx = self
            .pool
            .begin()
            .await
            .map_err(|e| BetterAuthError::Other(format!("Transaction begin failed: {e}")))?;
        Ok(Box::new(SqlxTransactionAdapter::new(tx)))
    }
}
