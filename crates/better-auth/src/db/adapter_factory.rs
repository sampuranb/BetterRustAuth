// Adapter factory — resolves the database adapter based on configuration.
//
// Maps to: packages/better-auth/src/db/adapter-base.ts (getBaseAdapter)

use std::sync::Arc;
use async_trait::async_trait;
use better_auth_core::db::adapter::{
    Adapter, AdapterResult, FindManyQuery, SchemaOptions, SchemaStatus,
    TransactionAdapter, WhereClause,
};
use better_auth_core::db::schema::AuthSchema;
use better_auth_core::error::BetterAuthError;
use serde_json::Value;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Adapter source — how the adapter is configured
// ---------------------------------------------------------------------------

/// How the database adapter was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterSource {
    /// User provided a factory function that returns an adapter.
    Function,
    /// Direct database connection (e.g., SQLx pool).
    DirectDB,
    /// In-memory adapter (for testing / no database configured).
    Memory,
}

// ---------------------------------------------------------------------------
// Adapter configuration
// ---------------------------------------------------------------------------

/// Database configuration — the user's database option.
pub enum DatabaseConfig {
    /// User provided an adapter factory function.
    AdapterFn(Box<dyn Fn() -> Arc<dyn Adapter> + Send + Sync>),
    /// User provided a pre-built adapter instance.
    Adapter(Arc<dyn Adapter>),
    /// No database configured — use memory adapter.
    None,
}

// ---------------------------------------------------------------------------
// Memory adapter — minimal in-memory store for testing
// ---------------------------------------------------------------------------

/// Minimal in-memory adapter for testing when no database is configured.
pub struct MemoryAdapter {
    tables: std::sync::Mutex<HashMap<String, Vec<Value>>>,
}

impl MemoryAdapter {
    pub fn new() -> Self {
        Self {
            tables: std::sync::Mutex::new(HashMap::new()),
        }
    }
}

impl std::fmt::Debug for MemoryAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryAdapter").finish()
    }
}

/// Simple WHERE clause matching for the memory adapter.
fn matches_where(record: &Value, wheres: &[WhereClause]) -> bool {
    let obj = match record.as_object() {
        Some(o) => o,
        None => return false,
    };

    for clause in wheres {
        let field_val = obj.get(&clause.field);
        let matches = match field_val {
            Some(v) => v == &clause.value,
            None => clause.value.is_null(),
        };
        if !matches {
            return false;
        }
    }
    true
}

#[async_trait]
impl Adapter for MemoryAdapter {
    async fn create(
        &self,
        model: &str,
        data: Value,
        _select: Option<&[String]>,
    ) -> AdapterResult<Value> {
        let mut tables = self.tables.lock().unwrap();
        let table = tables.entry(model.to_string()).or_default();
        table.push(data.clone());
        Ok(data)
    }

    async fn find_one(
        &self,
        model: &str,
        wheres: &[WhereClause],
    ) -> AdapterResult<Option<Value>> {
        let tables = self.tables.lock().unwrap();
        let table = match tables.get(model) {
            Some(t) => t,
            None => return Ok(None),
        };

        for record in table {
            if matches_where(record, wheres) {
                return Ok(Some(record.clone()));
            }
        }
        Ok(None)
    }

    async fn find_many(
        &self,
        model: &str,
        query: FindManyQuery,
    ) -> AdapterResult<Vec<Value>> {
        let tables = self.tables.lock().unwrap();
        let table = match tables.get(model) {
            Some(t) => t,
            None => return Ok(Vec::new()),
        };

        let mut results: Vec<Value> = table
            .iter()
            .filter(|r| {
                if query.where_clauses.is_empty() {
                    true
                } else {
                    matches_where(r, &query.where_clauses)
                }
            })
            .cloned()
            .collect();

        if let Some(limit) = query.limit {
            results.truncate(limit as usize);
        }

        Ok(results)
    }

    async fn count(
        &self,
        model: &str,
        wheres: &[WhereClause],
    ) -> AdapterResult<i64> {
        let tables = self.tables.lock().unwrap();
        let table = match tables.get(model) {
            Some(t) => t,
            None => return Ok(0),
        };
        if wheres.is_empty() {
            Ok(table.len() as i64)
        } else {
            Ok(table.iter().filter(|r| matches_where(r, wheres)).count() as i64)
        }
    }

    async fn update(
        &self,
        model: &str,
        wheres: &[WhereClause],
        data: Value,
    ) -> AdapterResult<Option<Value>> {
        let mut tables = self.tables.lock().unwrap();
        let table = match tables.get_mut(model) {
            Some(t) => t,
            None => return Ok(None),
        };

        for record in table.iter_mut() {
            if matches_where(record, wheres) {
                if let (Some(rec), Some(upd)) = (record.as_object_mut(), data.as_object()) {
                    for (k, v) in upd {
                        rec.insert(k.clone(), v.clone());
                    }
                }
                return Ok(Some(record.clone()));
            }
        }
        Ok(None)
    }

    async fn update_many(
        &self,
        model: &str,
        wheres: &[WhereClause],
        data: Value,
    ) -> AdapterResult<i64> {
        let mut tables = self.tables.lock().unwrap();
        let table = match tables.get_mut(model) {
            Some(t) => t,
            None => return Ok(0),
        };

        let mut count = 0i64;
        for record in table.iter_mut() {
            if matches_where(record, wheres) {
                if let (Some(rec), Some(upd)) = (record.as_object_mut(), data.as_object()) {
                    for (k, v) in upd {
                        rec.insert(k.clone(), v.clone());
                    }
                }
                count += 1;
            }
        }
        Ok(count)
    }

    async fn delete(
        &self,
        model: &str,
        wheres: &[WhereClause],
    ) -> AdapterResult<()> {
        let mut tables = self.tables.lock().unwrap();
        if let Some(table) = tables.get_mut(model) {
            table.retain(|r| !matches_where(r, wheres));
        }
        Ok(())
    }

    async fn delete_many(
        &self,
        model: &str,
        wheres: &[WhereClause],
    ) -> AdapterResult<i64> {
        let mut tables = self.tables.lock().unwrap();
        if let Some(table) = tables.get_mut(model) {
            let before = table.len();
            table.retain(|r| !matches_where(r, wheres));
            return Ok((before - table.len()) as i64);
        }
        Ok(0)
    }

    async fn create_schema(
        &self,
        _schema: &AuthSchema,
        _options: &SchemaOptions,
    ) -> AdapterResult<SchemaStatus> {
        // Memory adapter doesn't need schema migration
        Ok(SchemaStatus::UpToDate)
    }

    async fn begin_transaction(&self) -> AdapterResult<Box<dyn TransactionAdapter>> {
        Err(BetterAuthError::Other(
            "Memory adapter does not support transactions".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Factory function
// ---------------------------------------------------------------------------

/// Resolve the database adapter from configuration.
///
/// Matches TS `getBaseAdapter(options, handleDirectDatabase)`:
/// - If no database configured → memory adapter
/// - If function type → call the factory
/// - If adapter instance → use directly
pub fn get_base_adapter(config: DatabaseConfig) -> (Arc<dyn Adapter>, AdapterSource) {
    match config {
        DatabaseConfig::AdapterFn(factory) => {
            let adapter = factory();
            (adapter, AdapterSource::Function)
        }
        DatabaseConfig::Adapter(adapter) => (adapter, AdapterSource::DirectDB),
        DatabaseConfig::None => {
            let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn Adapter>;
            (adapter, AdapterSource::Memory)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_get_base_adapter_memory() {
        let (_, source) = get_base_adapter(DatabaseConfig::None);
        assert_eq!(source, AdapterSource::Memory);
    }

    #[test]
    fn test_get_base_adapter_function() {
        let factory = Box::new(|| -> Arc<dyn Adapter> {
            Arc::new(MemoryAdapter::new())
        });
        let (_, source) = get_base_adapter(DatabaseConfig::AdapterFn(factory));
        assert_eq!(source, AdapterSource::Function);
    }

    #[tokio::test]
    async fn test_memory_adapter_crud() {
        let adapter = MemoryAdapter::new();
        let data = json!({"id": "u1", "name": "Alice", "email": "alice@test.com"});

        // Create
        let created = adapter.create("user", data.clone(), None).await.unwrap();
        assert_eq!(created["name"], "Alice");

        // Find one
        let clause = WhereClause::eq("id", "u1");
        let found = adapter.find_one("user", &[clause.clone()]).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap()["name"], "Alice");

        // Update
        let update_data = json!({"name": "Alice B."});
        let updated = adapter.update("user", &[clause.clone()], update_data).await.unwrap();
        assert!(updated.is_some());
        assert_eq!(updated.unwrap()["name"], "Alice B.");

        // Count
        let count = adapter.count("user", &[]).await.unwrap();
        assert_eq!(count, 1);

        // Delete
        adapter.delete("user", &[clause]).await.unwrap();
        let count = adapter.count("user", &[]).await.unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_memory_adapter_update_many() {
        let adapter = MemoryAdapter::new();
        adapter.create("user", json!({"id": "u1", "active": true}), None).await.unwrap();
        adapter.create("user", json!({"id": "u2", "active": true}), None).await.unwrap();

        let count = adapter.update_many("user", &[], json!({"active": false})).await.unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_adapter_source_variants() {
        assert_eq!(AdapterSource::Memory, AdapterSource::Memory);
        assert_ne!(AdapterSource::Memory, AdapterSource::Function);
    }
}
