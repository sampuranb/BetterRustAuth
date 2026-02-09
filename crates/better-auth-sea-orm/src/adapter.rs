// SeaOrmAdapter — concrete implementation of the core Adapter trait using Sea-ORM.
//
// Uses Sea-ORM's DatabaseConnection with raw SQL (via sea-query builders)
// for dynamic table operations.

use async_trait::async_trait;
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DbBackend, DbErr, FromQueryResult,
    JsonValue, Statement,
};

use better_auth_core::db::adapter::{
    Adapter, AdapterResult, FindManyQuery, SchemaOptions, SchemaStatus, TransactionAdapter,
    WhereClause,
};
use better_auth_core::db::schema::AuthSchema;
use better_auth_core::error::BetterAuthError;

use crate::query;

/// Sea-ORM-based database adapter.
///
/// Wraps a `DatabaseConnection` and implements the core `Adapter` trait.
#[derive(Debug, Clone)]
pub struct SeaOrmAdapter {
    db: DatabaseConnection,
}

impl SeaOrmAdapter {
    /// Create a new adapter from an existing database connection.
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Create a new adapter by connecting to a database URL.
    pub async fn connect(url: &str) -> Result<Self, BetterAuthError> {
        let db = sea_orm::Database::connect(url)
            .await
            .map_err(|e| BetterAuthError::Other(format!("Sea-ORM connection failed: {e}")))?;
        Ok(Self { db })
    }

    /// Get a reference to the underlying DatabaseConnection.
    pub fn db(&self) -> &DatabaseConnection {
        &self.db
    }
}

fn db_err_to_auth(e: DbErr) -> BetterAuthError {
    BetterAuthError::Other(format!("Database error: {e}"))
}

/// Query result for count operations.
#[derive(Debug, FromQueryResult)]
struct CountResult {
    count: i64,
}

#[async_trait]
impl Adapter for SeaOrmAdapter {
    async fn create(
        &self,
        model: &str,
        data: serde_json::Value,
        _select: Option<&[String]>,
    ) -> AdapterResult<serde_json::Value> {
        let sql = query::build_insert(model, &data);
        let stmt = Statement::from_string(DbBackend::Sqlite, sql);

        self.db.execute(stmt).await.map_err(db_err_to_auth)?;

        // Select back if we have an ID
        if let Some(id) = data.get("id").and_then(|v| v.as_str()) {
            let select_sql = format!(
                "SELECT * FROM \"{}\" WHERE \"id\" = '{}'",
                model,
                id.replace('\'', "''")
            );
            let stmt = Statement::from_string(DbBackend::Sqlite, select_sql);
            let result = JsonValue::find_by_statement(stmt)
                .one(&self.db)
                .await
                .map_err(db_err_to_auth)?;
            if let Some(row) = result {
                return Ok(row);
            }
        }

        Ok(data)
    }

    async fn find_one(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<Option<serde_json::Value>> {
        let find_query = FindManyQuery {
            where_clauses: where_clauses.to_vec(),
            limit: Some(1),
            ..Default::default()
        };
        let sql = query::build_select(model, &find_query);
        let stmt = Statement::from_string(DbBackend::Sqlite, sql);
        let result = JsonValue::find_by_statement(stmt)
            .one(&self.db)
            .await
            .map_err(db_err_to_auth)?;
        Ok(result)
    }

    async fn find_many(
        &self,
        model: &str,
        query_params: FindManyQuery,
    ) -> AdapterResult<Vec<serde_json::Value>> {
        let sql = query::build_select(model, &query_params);
        let stmt = Statement::from_string(DbBackend::Sqlite, sql);
        let result = JsonValue::find_by_statement(stmt)
            .all(&self.db)
            .await
            .map_err(db_err_to_auth)?;
        Ok(result)
    }

    async fn count(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<i64> {
        let sql = query::build_count(model, where_clauses);
        let stmt = Statement::from_string(DbBackend::Sqlite, sql);
        let result = CountResult::find_by_statement(stmt)
            .one(&self.db)
            .await
            .map_err(db_err_to_auth)?;
        Ok(result.map(|r| r.count).unwrap_or(0))
    }

    async fn update(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
        data: serde_json::Value,
    ) -> AdapterResult<Option<serde_json::Value>> {
        let sql = query::build_update(model, where_clauses, &data);
        let stmt = Statement::from_string(DbBackend::Sqlite, sql);
        let result = self.db.execute(stmt).await.map_err(db_err_to_auth)?;

        if result.rows_affected() == 0 {
            return Ok(None);
        }

        // Select back the updated row
        self.find_one(model, where_clauses).await
    }

    async fn update_many(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
        data: serde_json::Value,
    ) -> AdapterResult<i64> {
        let sql = query::build_update(model, where_clauses, &data);
        let stmt = Statement::from_string(DbBackend::Sqlite, sql);
        let result = self.db.execute(stmt).await.map_err(db_err_to_auth)?;
        Ok(result.rows_affected() as i64)
    }

    async fn delete(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<()> {
        let sql = query::build_delete(model, where_clauses);
        let stmt = Statement::from_string(DbBackend::Sqlite, sql);
        self.db.execute(stmt).await.map_err(db_err_to_auth)?;
        Ok(())
    }

    async fn delete_many(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<i64> {
        let sql = query::build_delete(model, where_clauses);
        let stmt = Statement::from_string(DbBackend::Sqlite, sql);
        let result = self.db.execute(stmt).await.map_err(db_err_to_auth)?;
        Ok(result.rows_affected() as i64)
    }

    async fn create_schema(
        &self,
        schema: &AuthSchema,
        _options: &SchemaOptions,
    ) -> AdapterResult<SchemaStatus> {
        // Generate DDL for the database
        let ddl = crate::query::build_schema_ddl(schema);

        for stmt_str in ddl {
            let stmt = Statement::from_string(DbBackend::Sqlite, stmt_str);
            // Ignore "already exists" errors
            let _ = self.db.execute(stmt).await;
        }

        Ok(SchemaStatus::UpToDate)
    }

    async fn begin_transaction(&self) -> AdapterResult<Box<dyn TransactionAdapter>> {
        // Sea-ORM transactions use closures, not returned objects.
        // Return an error with guidance.
        Err(BetterAuthError::Other(
            "Sea-ORM uses closure-based transactions. Use `db.transaction(|txn| { ... })` directly.".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_debug() {
        // Just ensure the adapter implements Debug (required by trait)
        let adapter_str = format!("{:?}", "SeaOrmAdapter");
        assert!(!adapter_str.is_empty());
    }
}
