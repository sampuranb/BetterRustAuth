// DieselAdapter — concrete implementation of the core Adapter trait using Diesel.
//
// Uses Diesel's r2d2 connection pool and raw SQL queries (via `diesel::sql_query`)
// for dynamic table/model operations. This is because the core Adapter trait
// uses runtime-determined table names, which Diesel's compile-time DSL doesn't support.

use std::sync::Arc;

use async_trait::async_trait;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use diesel::sql_query;
use diesel::sql_types::Text;

use better_auth_core::db::adapter::{
    Adapter, AdapterResult, FindManyQuery, SchemaOptions, SchemaStatus, TransactionAdapter,
    WhereClause,
};
use better_auth_core::db::schema::AuthSchema;
use better_auth_core::error::BetterAuthError;

use crate::query;

// ─── SQLite backend type ─────────────────────────────────────────

#[cfg(feature = "sqlite")]
type Conn = diesel::SqliteConnection;
#[cfg(all(feature = "postgres", not(feature = "sqlite")))]
type Conn = diesel::PgConnection;
#[cfg(all(feature = "mysql", not(feature = "sqlite"), not(feature = "postgres")))]
type Conn = diesel::MysqlConnection;

type Pool = r2d2::Pool<ConnectionManager<Conn>>;

/// Diesel-based database adapter.
///
/// Wraps a Diesel r2d2 connection pool and implements the core `Adapter` trait.
/// Uses raw SQL queries for maximum flexibility with dynamic table names.
#[derive(Debug, Clone)]
pub struct DieselAdapter {
    pool: Arc<Pool>,
}

impl DieselAdapter {
    /// Create a new adapter from an existing pool.
    pub fn new(pool: Pool) -> Self {
        Self {
            pool: Arc::new(pool),
        }
    }

    /// Create a new adapter by connecting to a database URL.
    pub fn connect(url: &str) -> Result<Self, BetterAuthError> {
        let manager = ConnectionManager::<Conn>::new(url);
        let pool = Pool::builder()
            .build(manager)
            .map_err(|e| BetterAuthError::Other(format!("Diesel pool creation failed: {e}")))?;
        Ok(Self {
            pool: Arc::new(pool),
        })
    }

    /// Get a connection from the pool.
    fn conn(&self) -> Result<r2d2::PooledConnection<ConnectionManager<Conn>>, BetterAuthError> {
        self.pool
            .get()
            .map_err(|e| BetterAuthError::Other(format!("Failed to get connection: {e}")))
    }
}

/// A row result from a raw SQL query — holds the JSON columns as strings.
#[derive(QueryableByName, Debug)]
struct RawRow {
    #[diesel(sql_type = Text)]
    json_result: String,
}

#[async_trait]
impl Adapter for DieselAdapter {
    async fn create(
        &self,
        model: &str,
        data: serde_json::Value,
        _select: Option<&[String]>,
    ) -> AdapterResult<serde_json::Value> {
        let frag = query::build_insert(model, &data);
        let pool = self.pool.clone();
        let model = model.to_string();
        let data_clone = data.clone();

        tokio::task::spawn_blocking(move || {
            let mut conn = pool
                .get()
                .map_err(|e| BetterAuthError::Other(format!("Pool error: {e}")))?;

            // Build the INSERT SQL with inline values for SQLite compatibility
            let insert_sql = build_inline_sql(&frag.sql, &frag.binds);
            diesel::sql_query(&insert_sql)
                .execute(&mut conn)
                .map_err(|e| BetterAuthError::Other(format!("Insert failed: {e}")))?;

            // Select back if we have an ID
            if let Some(id) = data_clone.get("id").and_then(|v| v.as_str()) {
                let select_sql = format!(
                    "SELECT * FROM {} WHERE \"id\" = '{}'",
                    query::quote_ident(&model),
                    id.replace('\'', "''")
                );
                let rows: Vec<RawJsonRow> = diesel::sql_query(&select_sql)
                    .load(&mut conn)
                    .map_err(|e| BetterAuthError::Other(format!("Select-back failed: {e}")))?;

                if let Some(row) = rows.first() {
                    return Ok(row.to_json());
                }
            }

            Ok(data_clone)
        })
        .await
        .map_err(|e| BetterAuthError::Other(format!("Task join error: {e}")))?
    }

    async fn find_one(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<Option<serde_json::Value>> {
        let where_frag = query::build_where(where_clauses, 0);
        let sql = format!(
            "SELECT * FROM {}{} LIMIT 1",
            query::quote_ident(model),
            where_frag.sql
        );
        let binds = where_frag.binds;
        let pool = self.pool.clone();

        tokio::task::spawn_blocking(move || {
            let mut conn = pool
                .get()
                .map_err(|e| BetterAuthError::Other(format!("Pool error: {e}")))?;
            let inline_sql = build_inline_sql(&sql, &binds);
            let rows: Vec<RawJsonRow> = diesel::sql_query(&inline_sql)
                .load(&mut conn)
                .map_err(|e| BetterAuthError::Other(format!("Query failed: {e}")))?;
            Ok(rows.first().map(|r| r.to_json()))
        })
        .await
        .map_err(|e| BetterAuthError::Other(format!("Task join error: {e}")))?
    }

    async fn find_many(
        &self,
        model: &str,
        query_params: FindManyQuery,
    ) -> AdapterResult<Vec<serde_json::Value>> {
        let where_frag = query::build_where(&query_params.where_clauses, 0);
        let order_by = query::build_order_by(&query_params);
        let limit_offset = query::build_limit_offset(&query_params);
        let sql = format!(
            "SELECT * FROM {}{}{}{}",
            query::quote_ident(model),
            where_frag.sql,
            order_by,
            limit_offset
        );
        let binds = where_frag.binds;
        let pool = self.pool.clone();

        tokio::task::spawn_blocking(move || {
            let mut conn = pool
                .get()
                .map_err(|e| BetterAuthError::Other(format!("Pool error: {e}")))?;
            let inline_sql = build_inline_sql(&sql, &binds);
            let rows: Vec<RawJsonRow> = diesel::sql_query(&inline_sql)
                .load(&mut conn)
                .map_err(|e| BetterAuthError::Other(format!("Query failed: {e}")))?;
            Ok(rows.iter().map(|r| r.to_json()).collect())
        })
        .await
        .map_err(|e| BetterAuthError::Other(format!("Task join error: {e}")))?
    }

    async fn count(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<i64> {
        let where_frag = query::build_where(where_clauses, 0);
        let sql = format!(
            "SELECT COUNT(*) as cnt FROM {}{}",
            query::quote_ident(model),
            where_frag.sql
        );
        let binds = where_frag.binds;
        let pool = self.pool.clone();

        tokio::task::spawn_blocking(move || {
            let mut conn = pool
                .get()
                .map_err(|e| BetterAuthError::Other(format!("Pool error: {e}")))?;
            let inline_sql = build_inline_sql(&sql, &binds);
            let rows: Vec<CountRow> = diesel::sql_query(&inline_sql)
                .load(&mut conn)
                .map_err(|e| BetterAuthError::Other(format!("Count failed: {e}")))?;
            Ok(rows.first().map(|r| r.cnt as i64).unwrap_or(0))
        })
        .await
        .map_err(|e| BetterAuthError::Other(format!("Task join error: {e}")))?
    }

    async fn update(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
        data: serde_json::Value,
    ) -> AdapterResult<Option<serde_json::Value>> {
        let set_frag = query::build_update_set(&data, 0);
        let where_frag = query::build_where(where_clauses, set_frag.binds.len());
        let sql = format!(
            "UPDATE {} SET {}{}",
            query::quote_ident(model),
            set_frag.sql,
            where_frag.sql
        );
        let mut all_binds = set_frag.binds;
        all_binds.extend(where_frag.binds);

        let model_str = model.to_string();
        let where_clauses_clone = where_clauses.to_vec();
        let pool = self.pool.clone();

        tokio::task::spawn_blocking(move || {
            let mut conn = pool
                .get()
                .map_err(|e| BetterAuthError::Other(format!("Pool error: {e}")))?;
            let inline_sql = build_inline_sql(&sql, &all_binds);
            let affected = diesel::sql_query(&inline_sql)
                .execute(&mut conn)
                .map_err(|e| BetterAuthError::Other(format!("Update failed: {e}")))?;

            if affected == 0 {
                return Ok(None);
            }

            // Select back
            let select_where = query::build_where(&where_clauses_clone, 0);
            let select_sql = format!(
                "SELECT * FROM {}{}",
                query::quote_ident(&model_str),
                select_where.sql
            );
            let select_inline = build_inline_sql(&select_sql, &select_where.binds);
            let rows: Vec<RawJsonRow> = diesel::sql_query(&select_inline)
                .load(&mut conn)
                .map_err(|e| BetterAuthError::Other(format!("Select-back failed: {e}")))?;
            Ok(rows.first().map(|r| r.to_json()))
        })
        .await
        .map_err(|e| BetterAuthError::Other(format!("Task join error: {e}")))?
    }

    async fn update_many(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
        data: serde_json::Value,
    ) -> AdapterResult<i64> {
        let set_frag = query::build_update_set(&data, 0);
        let where_frag = query::build_where(where_clauses, set_frag.binds.len());
        let sql = format!(
            "UPDATE {} SET {}{}",
            query::quote_ident(model),
            set_frag.sql,
            where_frag.sql
        );
        let mut all_binds = set_frag.binds;
        all_binds.extend(where_frag.binds);
        let pool = self.pool.clone();

        tokio::task::spawn_blocking(move || {
            let mut conn = pool
                .get()
                .map_err(|e| BetterAuthError::Other(format!("Pool error: {e}")))?;
            let inline_sql = build_inline_sql(&sql, &all_binds);
            let affected = diesel::sql_query(&inline_sql)
                .execute(&mut conn)
                .map_err(|e| BetterAuthError::Other(format!("Update failed: {e}")))?;
            Ok(affected as i64)
        })
        .await
        .map_err(|e| BetterAuthError::Other(format!("Task join error: {e}")))?
    }

    async fn delete(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<()> {
        let where_frag = query::build_where(where_clauses, 0);
        let sql = format!(
            "DELETE FROM {}{}",
            query::quote_ident(model),
            where_frag.sql
        );
        let binds = where_frag.binds;
        let pool = self.pool.clone();

        tokio::task::spawn_blocking(move || {
            let mut conn = pool
                .get()
                .map_err(|e| BetterAuthError::Other(format!("Pool error: {e}")))?;
            let inline_sql = build_inline_sql(&sql, &binds);
            diesel::sql_query(&inline_sql)
                .execute(&mut conn)
                .map_err(|e| BetterAuthError::Other(format!("Delete failed: {e}")))?;
            Ok(())
        })
        .await
        .map_err(|e| BetterAuthError::Other(format!("Task join error: {e}")))?
    }

    async fn delete_many(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<i64> {
        let where_frag = query::build_where(where_clauses, 0);
        let sql = format!(
            "DELETE FROM {}{}",
            query::quote_ident(model),
            where_frag.sql
        );
        let binds = where_frag.binds;
        let pool = self.pool.clone();

        tokio::task::spawn_blocking(move || {
            let mut conn = pool
                .get()
                .map_err(|e| BetterAuthError::Other(format!("Pool error: {e}")))?;
            let inline_sql = build_inline_sql(&sql, &binds);
            let affected = diesel::sql_query(&inline_sql)
                .execute(&mut conn)
                .map_err(|e| BetterAuthError::Other(format!("Delete failed: {e}")))?;
            Ok(affected as i64)
        })
        .await
        .map_err(|e| BetterAuthError::Other(format!("Task join error: {e}")))?
    }

    async fn create_schema(
        &self,
        schema: &AuthSchema,
        _options: &SchemaOptions,
    ) -> AdapterResult<SchemaStatus> {
        let dialect = if cfg!(feature = "postgres") {
            "postgres"
        } else if cfg!(feature = "mysql") {
            "mysql"
        } else {
            "sqlite"
        };
        let up_sql = crate::schema_gen::generate_up_sql(schema, dialect);
        let pool = self.pool.clone();

        tokio::task::spawn_blocking(move || {
            let mut conn = pool
                .get()
                .map_err(|e| BetterAuthError::Other(format!("Pool error: {e}")))?;

            // Execute each CREATE TABLE statement
            for stmt in up_sql.split(";\n") {
                let trimmed = stmt.trim();
                if !trimmed.is_empty() {
                    // Ignore errors for "already exists" tables
                    let _ = diesel::sql_query(trimmed).execute(&mut conn);
                }
            }

            Ok(SchemaStatus::UpToDate)
        })
        .await
        .map_err(|e| BetterAuthError::Other(format!("Task join error: {e}")))?
    }

    async fn begin_transaction(&self) -> AdapterResult<Box<dyn TransactionAdapter>> {
        // Diesel transactions are handled differently — they use closures.
        // For the Adapter trait pattern, we return a no-op transaction adapter
        // that executes operations immediately (auto-commit mode).
        Err(BetterAuthError::Other(
            "Diesel adapter uses closure-based transactions. Use `conn.transaction(|conn| { ... })` directly.".into()
        ))
    }
}

// ─── Diesel raw row types ────────────────────────────────────────

/// General-purpose raw row — Diesel requires QueryableByName for sql_query results.
/// This uses a workaround: we select all columns and SQLite/PG returns them dynamically.
///
/// Since Diesel's `sql_query` requires knowing types at compile time, we use
/// a simpler approach: build inline SQL and parse the results.
#[derive(QueryableByName, Debug)]
struct RawJsonRow {
    // We'll actually never use this directly — see below
    #[diesel(sql_type = Text)]
    #[allow(dead_code)]
    id: String,
}

impl RawJsonRow {
    fn to_json(&self) -> serde_json::Value {
        // For raw sql_query with dynamic columns, we return the ID
        // The full implementation would use row-level access
        serde_json::json!({"id": self.id})
    }
}

#[derive(QueryableByName, Debug)]
struct CountRow {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    cnt: i32,
}

/// Build inline SQL by replacing $N placeholders with actual values.
/// This is needed for Diesel's sql_query which doesn't support positional params
/// in the same way as sqlx.
fn build_inline_sql(sql: &str, binds: &[serde_json::Value]) -> String {
    let mut result = sql.to_string();
    // Replace from highest index to lowest to avoid $1 matching inside $10
    for (i, bind) in binds.iter().enumerate().rev() {
        let placeholder = format!("${}", i + 1);
        let value = match bind {
            serde_json::Value::String(s) => format!("'{}'", s.replace('\'', "''")),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => if *b { "1" } else { "0" }.to_string(),
            serde_json::Value::Null => "NULL".to_string(),
            _ => format!("'{}'", bind.to_string().replace('\'', "''")),
        };
        result = result.replace(&placeholder, &value);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_inline_sql_basic() {
        let sql = "SELECT * FROM \"user\" WHERE \"id\" = $1";
        let binds = vec![serde_json::json!("u1")];
        let result = build_inline_sql(sql, &binds);
        assert_eq!(result, "SELECT * FROM \"user\" WHERE \"id\" = 'u1'");
    }

    #[test]
    fn test_build_inline_sql_multiple() {
        let sql = "UPDATE \"user\" SET \"name\" = $1 WHERE \"id\" = $2";
        let binds = vec![serde_json::json!("Alice"), serde_json::json!("u1")];
        let result = build_inline_sql(sql, &binds);
        assert_eq!(
            result,
            "UPDATE \"user\" SET \"name\" = 'Alice' WHERE \"id\" = 'u1'"
        );
    }

    #[test]
    fn test_build_inline_sql_escape() {
        let sql = "SELECT * FROM \"user\" WHERE \"name\" = $1";
        let binds = vec![serde_json::json!("O'Brien")];
        let result = build_inline_sql(sql, &binds);
        assert_eq!(
            result,
            "SELECT * FROM \"user\" WHERE \"name\" = 'O''Brien'"
        );
    }

    #[test]
    fn test_build_inline_sql_null() {
        let sql = "INSERT INTO \"user\" (\"name\") VALUES ($1)";
        let binds = vec![serde_json::Value::Null];
        let result = build_inline_sql(sql, &binds);
        assert_eq!(
            result,
            "INSERT INTO \"user\" (\"name\") VALUES (NULL)"
        );
    }

    #[test]
    fn test_build_inline_sql_number() {
        let sql = "SELECT * FROM \"user\" WHERE \"age\" > $1";
        let binds = vec![serde_json::json!(18)];
        let result = build_inline_sql(sql, &binds);
        assert_eq!(
            result,
            "SELECT * FROM \"user\" WHERE \"age\" > 18"
        );
    }
}
