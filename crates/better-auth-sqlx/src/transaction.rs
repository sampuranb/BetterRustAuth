// Transaction adapter — wraps sqlx::Transaction to implement Adapter + TransactionAdapter.
//
// Uses tokio::sync::Mutex to safely hold the transaction across async boundaries.

use async_trait::async_trait;
use sqlx::Row;
use tokio::sync::Mutex;

use better_auth_core::db::adapter::{
    Adapter, AdapterResult, FindManyQuery, SchemaOptions, SchemaStatus, TransactionAdapter,
    WhereClause,
};
use better_auth_core::db::schema::AuthSchema;
use better_auth_core::error::BetterAuthError;

use crate::adapter::{row_to_json, BindValue};
use crate::query_builder;

/// Transaction-scoped adapter.
///
/// Wraps a `sqlx::Transaction` and implements both `Adapter` and `TransactionAdapter`.
/// All operations within this adapter run inside the transaction.
pub struct SqlxTransactionAdapter {
    tx: Mutex<Option<sqlx::Transaction<'static, sqlx::Any>>>,
}

impl std::fmt::Debug for SqlxTransactionAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlxTransactionAdapter").finish()
    }
}

impl SqlxTransactionAdapter {
    pub fn new(tx: sqlx::Transaction<'static, sqlx::Any>) -> Self {
        Self {
            tx: Mutex::new(Some(tx)),
        }
    }
}

/// Convert JSON binds to BindValues for owned binding.
fn prepare_binds(binds: &[serde_json::Value]) -> Vec<BindValue> {
    binds
        .iter()
        .map(|v| match v {
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
        })
        .collect()
}

/// Build and bind a query, then fetch all rows within the transaction.
macro_rules! tx_fetch_all {
    ($self:expr, $sql:expr, $bind_vals:expr) => {{
        let mut guard = $self.tx.lock().await;
        let tx: &mut sqlx::Transaction<'static, sqlx::Any> = guard.as_mut().ok_or_else(|| {
            BetterAuthError::Other("Transaction already consumed".into())
        })?;

        let mut query = sqlx::query($sql.as_str());
        for bv in &$bind_vals {
            query = match bv {
                BindValue::Text(s) => query.bind(s.as_str()),
                BindValue::Int(i) => query.bind(*i),
                BindValue::Float(f) => query.bind(*f),
                BindValue::Null => query.bind(Option::<String>::None),
            };
        }

        query
            .fetch_all(&mut **tx)
            .await
            .map_err(|e| BetterAuthError::Other(format!("Query failed: {e}")))
    }};
}

/// Build and bind a query, then fetch optional row within the transaction.
macro_rules! tx_fetch_optional {
    ($self:expr, $sql:expr, $bind_vals:expr) => {{
        let mut guard = $self.tx.lock().await;
        let tx: &mut sqlx::Transaction<'static, sqlx::Any> = guard.as_mut().ok_or_else(|| {
            BetterAuthError::Other("Transaction already consumed".into())
        })?;

        let mut query = sqlx::query($sql.as_str());
        for bv in &$bind_vals {
            query = match bv {
                BindValue::Text(s) => query.bind(s.as_str()),
                BindValue::Int(i) => query.bind(*i),
                BindValue::Float(f) => query.bind(*f),
                BindValue::Null => query.bind(Option::<String>::None),
            };
        }

        query
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| BetterAuthError::Other(format!("Query failed: {e}")))
    }};
}

/// Build and bind a query, then execute (returning affected rows) within the transaction.
macro_rules! tx_execute {
    ($self:expr, $sql:expr, $bind_vals:expr) => {{
        let mut guard = $self.tx.lock().await;
        let tx: &mut sqlx::Transaction<'static, sqlx::Any> = guard.as_mut().ok_or_else(|| {
            BetterAuthError::Other("Transaction already consumed".into())
        })?;

        let mut query = sqlx::query($sql.as_str());
        for bv in &$bind_vals {
            query = match bv {
                BindValue::Text(s) => query.bind(s.as_str()),
                BindValue::Int(i) => query.bind(*i),
                BindValue::Float(f) => query.bind(*f),
                BindValue::Null => query.bind(Option::<String>::None),
            };
        }

        query
            .execute(&mut **tx)
            .await
            .map_err(|e| BetterAuthError::Other(format!("Execute failed: {e}")))
    }};
}

#[async_trait]
impl Adapter for SqlxTransactionAdapter {
    async fn create(
        &self,
        model: &str,
        data: serde_json::Value,
        _select: Option<&[String]>,
    ) -> AdapterResult<serde_json::Value> {
        let frag = query_builder::build_insert(model, &data);
        let sql = frag.sql.clone();
        let bind_vals = prepare_binds(&frag.binds);
        // Execute INSERT (no RETURNING)
        tx_execute!(self, sql, bind_vals)?;

        // Select back the inserted row by id
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
            let select_binds = prepare_binds(&where_frag.binds);
            let row = tx_fetch_optional!(self, select_sql, select_binds)?
                .ok_or_else(|| BetterAuthError::Other("Create: select-back failed".into()))?;
            Ok(row_to_json(&row))
        } else {
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
            "SELECT * FROM {}{} LIMIT 1",
            query_builder::quote_identifier(model),
            where_frag.sql
        );
        let bind_vals = prepare_binds(&where_frag.binds);
        let row = tx_fetch_optional!(self, sql, bind_vals)?;
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
        let bind_vals = prepare_binds(&where_frag.binds);
        let rows = tx_fetch_all!(self, sql, bind_vals)?;
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
        let bind_vals = prepare_binds(&where_frag.binds);
        let rows = tx_fetch_all!(self, sql, bind_vals)?;
        let row = rows
            .first()
            .ok_or_else(|| BetterAuthError::Other("Count returned no rows".into()))?;
        let count: i64 = row
            .try_get("count")
            .map_err(|e| BetterAuthError::Other(format!("Count decode: {e}")))?;
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
        let bind_vals = prepare_binds(&all_binds);
        let result = tx_execute!(self, sql, bind_vals)?;
        if result.rows_affected() == 0 {
            return Ok(None);
        }
        // Select back the updated row
        let select_where = query_builder::build_where(where_clauses, 0);
        let select_sql = format!(
            "SELECT * FROM {}{}",
            query_builder::quote_identifier(model),
            select_where.sql
        );
        let select_binds = prepare_binds(&select_where.binds);
        let row = tx_fetch_optional!(self, select_sql, select_binds)?;
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
        let bind_vals = prepare_binds(&all_binds);
        let result = tx_execute!(self, sql, bind_vals)?;
        Ok(result.rows_affected() as i64)
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
        let bind_vals = prepare_binds(&where_frag.binds);
        tx_execute!(self, sql, bind_vals)?;
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
        let bind_vals = prepare_binds(&where_frag.binds);
        let result = tx_execute!(self, sql, bind_vals)?;
        Ok(result.rows_affected() as i64)
    }

    async fn create_schema(
        &self,
        _schema: &AuthSchema,
        _options: &SchemaOptions,
    ) -> AdapterResult<SchemaStatus> {
        Err(BetterAuthError::Other(
            "create_schema not supported inside a transaction".into(),
        ))
    }

    async fn begin_transaction(&self) -> AdapterResult<Box<dyn TransactionAdapter>> {
        Err(BetterAuthError::Other(
            "Nested transactions are not supported".into(),
        ))
    }
}

#[async_trait]
impl TransactionAdapter for SqlxTransactionAdapter {
    async fn commit(self: Box<Self>) -> AdapterResult<()> {
        let tx: sqlx::Transaction<'static, sqlx::Any> = self
            .tx
            .into_inner()
            .ok_or_else(|| BetterAuthError::Other("Transaction already consumed".into()))?;

        tx.commit()
            .await
            .map_err(|e| BetterAuthError::Other(format!("Commit failed: {e}")))?;

        Ok(())
    }

    async fn rollback(self: Box<Self>) -> AdapterResult<()> {
        let tx: sqlx::Transaction<'static, sqlx::Any> = self
            .tx
            .into_inner()
            .ok_or_else(|| BetterAuthError::Other("Transaction already consumed".into()))?;

        tx.rollback()
            .await
            .map_err(|e| BetterAuthError::Other(format!("Rollback failed: {e}")))?;

        Ok(())
    }
}
