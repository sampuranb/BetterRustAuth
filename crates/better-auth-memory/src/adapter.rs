// In-memory database adapter — HashMap-based store implementing the core Adapter trait.
//
// Stores data in `HashMap<String, Vec<serde_json::Value>>` keyed by model/table name.
// Thread-safe via `tokio::sync::RwLock`. Supports all adapter operations:
// create, find_one, find_many, count, update, update_many, delete, delete_many,
// create_schema, begin_transaction.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use better_auth_core::db::adapter::{
    Adapter, AdapterResult, Connector, FindManyQuery, Operator, SchemaOptions, SchemaStatus,
    SortDirection, TransactionAdapter, WhereClause,
};
use better_auth_core::db::schema::AuthSchema;
use better_auth_core::error::BetterAuthError;

/// Type alias for the in-memory store.
type Store = HashMap<String, Vec<serde_json::Value>>;

/// In-memory database adapter.
///
/// All data is stored in a `HashMap` wrapped in an `Arc<RwLock<...>>` for
/// thread-safe concurrent access. Data is lost when the adapter is dropped.
#[derive(Debug, Clone)]
pub struct MemoryAdapter {
    store: Arc<RwLock<Store>>,
}

impl Default for MemoryAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryAdapter {
    /// Create a new empty in-memory adapter.
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new adapter pre-populated with data.
    pub fn with_data(data: Store) -> Self {
        Self {
            store: Arc::new(RwLock::new(data)),
        }
    }

    /// Get a snapshot of all data (for debugging/testing).
    pub async fn snapshot(&self) -> Store {
        self.store.read().await.clone()
    }

    /// Clear all data.
    pub async fn clear(&self) {
        self.store.write().await.clear();
    }

    /// Get record count for a specific model.
    pub async fn model_count(&self, model: &str) -> usize {
        self.store
            .read()
            .await
            .get(model)
            .map(|v| v.len())
            .unwrap_or(0)
    }
}

/// Check if a record matches a set of WHERE clauses.
fn matches_where(record: &serde_json::Value, clauses: &[WhereClause]) -> bool {
    if clauses.is_empty() {
        return true;
    }

    let mut result = true;
    let mut pending_or = false;

    for clause in clauses {
        let field_val = record.get(&clause.field).cloned().unwrap_or(serde_json::Value::Null);
        let clause_match = match_operator(&field_val, &clause.value, &clause.operator);

        if pending_or {
            result = result || clause_match;
        } else {
            result = result && clause_match;
        }

        pending_or = matches!(clause.connector, Some(Connector::Or));
    }

    result
}

/// Match a single operator condition.
fn match_operator(field_val: &serde_json::Value, target: &serde_json::Value, op: &Operator) -> bool {
    match op {
        Operator::Eq => field_val == target,
        Operator::Ne => field_val != target,
        Operator::Lt => compare_json(field_val, target).map_or(false, |c| c < 0),
        Operator::Lte => compare_json(field_val, target).map_or(false, |c| c <= 0),
        Operator::Gt => compare_json(field_val, target).map_or(false, |c| c > 0),
        Operator::Gte => compare_json(field_val, target).map_or(false, |c| c >= 0),
        Operator::In => {
            if let serde_json::Value::Array(arr) = target {
                arr.contains(field_val)
            } else {
                false
            }
        }
        Operator::Contains => {
            let fs = field_val.as_str().unwrap_or("");
            let ts = target.as_str().unwrap_or("");
            fs.contains(ts)
        }
        Operator::StartsWith => {
            let fs = field_val.as_str().unwrap_or("");
            let ts = target.as_str().unwrap_or("");
            fs.starts_with(ts)
        }
        Operator::EndsWith => {
            let fs = field_val.as_str().unwrap_or("");
            let ts = target.as_str().unwrap_or("");
            fs.ends_with(ts)
        }
    }
}

/// Compare two JSON values numerically/lexicographically.
fn compare_json(a: &serde_json::Value, b: &serde_json::Value) -> Option<i8> {
    match (a, b) {
        (serde_json::Value::Number(an), serde_json::Value::Number(bn)) => {
            let af = an.as_f64()?;
            let bf = bn.as_f64()?;
            Some(af.partial_cmp(&bf).map(|o| match o {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            })?)
        }
        (serde_json::Value::String(a_s), serde_json::Value::String(b_s)) => {
            Some(match a_s.cmp(b_s) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            })
        }
        _ => None,
    }
}

/// Apply sorting to records.
fn sort_records(records: &mut [serde_json::Value], query: &FindManyQuery) {
    if let Some(ref sort) = query.sort_by {
        records.sort_by(|a, b| {
            let av = a.get(&sort.field);
            let bv = b.get(&sort.field);
            let cmp = match (av, bv) {
                (Some(av), Some(bv)) => compare_json(av, bv).unwrap_or(0),
                (Some(_), None) => 1,
                (None, Some(_)) => -1,
                (None, None) => 0,
            };
            match sort.direction {
                SortDirection::Asc => cmp.cmp(&0),
                SortDirection::Desc => cmp.cmp(&0).reverse(),
            }
        });
    }
}

/// Apply field selection to a record.
fn select_fields(record: &serde_json::Value, select: &Option<Vec<String>>) -> serde_json::Value {
    match select {
        Some(fields) if !fields.is_empty() => {
            let obj = record.as_object().cloned().unwrap_or_default();
            let filtered: serde_json::Map<String, serde_json::Value> = obj
                .into_iter()
                .filter(|(k, _)| fields.contains(k))
                .collect();
            serde_json::Value::Object(filtered)
        }
        _ => record.clone(),
    }
}

/// Merge update data into an existing record.
fn merge_update(record: &mut serde_json::Value, data: &serde_json::Value) {
    if let (Some(rec_obj), Some(data_obj)) = (record.as_object_mut(), data.as_object()) {
        for (k, v) in data_obj {
            rec_obj.insert(k.clone(), v.clone());
        }
    }
}

#[async_trait]
impl Adapter for MemoryAdapter {
    async fn create(
        &self,
        model: &str,
        data: serde_json::Value,
        _select: Option<&[String]>,
    ) -> AdapterResult<serde_json::Value> {
        let mut record = data;

        // Auto-generate ID if not present
        if record.get("id").is_none()
            || record.get("id") == Some(&serde_json::Value::Null)
        {
            record
                .as_object_mut()
                .unwrap()
                .insert("id".to_string(), serde_json::Value::String(uuid::Uuid::new_v4().to_string()));
        }

        let mut store = self.store.write().await;
        store
            .entry(model.to_string())
            .or_default()
            .push(record.clone());

        Ok(record)
    }

    async fn find_one(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<Option<serde_json::Value>> {
        let store = self.store.read().await;
        let records = store.get(model);

        match records {
            Some(recs) => Ok(recs.iter().find(|r| matches_where(r, where_clauses)).cloned()),
            None => Ok(None),
        }
    }

    async fn find_many(
        &self,
        model: &str,
        query: FindManyQuery,
    ) -> AdapterResult<Vec<serde_json::Value>> {
        let store = self.store.read().await;
        let empty = Vec::new();
        let records = store.get(model).unwrap_or(&empty);

        let mut result: Vec<serde_json::Value> = records
            .iter()
            .filter(|r| matches_where(r, &query.where_clauses))
            .cloned()
            .collect();

        sort_records(&mut result, &query);

        // Apply offset
        if let Some(offset) = query.offset {
            if (offset as usize) < result.len() {
                result = result.split_off(offset as usize);
            } else {
                result.clear();
            }
        }

        // Apply limit
        if let Some(limit) = query.limit {
            result.truncate(limit as usize);
        }

        // Apply select
        let result = result
            .iter()
            .map(|r| select_fields(r, &query.select))
            .collect();

        Ok(result)
    }

    async fn count(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<i64> {
        let store = self.store.read().await;
        let empty = Vec::new();
        let records = store.get(model).unwrap_or(&empty);
        let count = records.iter().filter(|r| matches_where(r, where_clauses)).count();
        Ok(count as i64)
    }

    async fn update(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
        data: serde_json::Value,
    ) -> AdapterResult<Option<serde_json::Value>> {
        let mut store = self.store.write().await;
        let records = store.get_mut(model);

        match records {
            Some(recs) => {
                let found = recs.iter_mut().find(|r| matches_where(r, where_clauses));
                match found {
                    Some(record) => {
                        merge_update(record, &data);
                        Ok(Some(record.clone()))
                    }
                    None => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    async fn update_many(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
        data: serde_json::Value,
    ) -> AdapterResult<i64> {
        let mut store = self.store.write().await;
        let records = store.get_mut(model);
        let mut count = 0i64;

        if let Some(recs) = records {
            for record in recs.iter_mut() {
                if matches_where(record, where_clauses) {
                    merge_update(record, &data);
                    count += 1;
                }
            }
        }

        Ok(count)
    }

    async fn delete(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<()> {
        let mut store = self.store.write().await;
        if let Some(recs) = store.get_mut(model) {
            if let Some(pos) = recs.iter().position(|r| matches_where(r, where_clauses)) {
                recs.remove(pos);
            }
        }
        Ok(())
    }

    async fn delete_many(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<i64> {
        let mut store = self.store.write().await;
        if let Some(recs) = store.get_mut(model) {
            let before = recs.len();
            recs.retain(|r| !matches_where(r, where_clauses));
            Ok((before - recs.len()) as i64)
        } else {
            Ok(0)
        }
    }

    async fn create_schema(
        &self,
        _schema: &AuthSchema,
        _options: &SchemaOptions,
    ) -> AdapterResult<SchemaStatus> {
        // In-memory adapter has no persistent schema — always up to date.
        Ok(SchemaStatus::UpToDate)
    }

    async fn begin_transaction(&self) -> AdapterResult<Box<dyn TransactionAdapter>> {
        // Clone the current store for the transaction snapshot
        let snapshot = self.store.read().await.clone();
        Ok(Box::new(MemoryTransactionAdapter {
            parent: self.store.clone(),
            snapshot: Arc::new(RwLock::new(snapshot)),
            committed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }))
    }
}

// ─── Transaction Adapter ─────────────────────────────────────────

/// In-memory transaction adapter.
///
/// Creates a snapshot of the store at the beginning. Operations run against the
/// snapshot. On commit, the snapshot replaces the parent store. On rollback (or drop),
/// changes are discarded.
struct MemoryTransactionAdapter {
    parent: Arc<RwLock<Store>>,
    snapshot: Arc<RwLock<Store>>,
    committed: Arc<std::sync::atomic::AtomicBool>,
}

impl std::fmt::Debug for MemoryTransactionAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryTransactionAdapter").finish()
    }
}

#[async_trait]
impl Adapter for MemoryTransactionAdapter {
    async fn create(
        &self,
        model: &str,
        data: serde_json::Value,
        _select: Option<&[String]>,
    ) -> AdapterResult<serde_json::Value> {
        let mut record = data;
        if record.get("id").is_none() || record.get("id") == Some(&serde_json::Value::Null) {
            record
                .as_object_mut()
                .unwrap()
                .insert("id".to_string(), serde_json::Value::String(uuid::Uuid::new_v4().to_string()));
        }
        let mut store = self.snapshot.write().await;
        store.entry(model.to_string()).or_default().push(record.clone());
        Ok(record)
    }

    async fn find_one(&self, model: &str, where_clauses: &[WhereClause]) -> AdapterResult<Option<serde_json::Value>> {
        let store = self.snapshot.read().await;
        Ok(store.get(model).and_then(|recs| recs.iter().find(|r| matches_where(r, where_clauses)).cloned()))
    }

    async fn find_many(&self, model: &str, query: FindManyQuery) -> AdapterResult<Vec<serde_json::Value>> {
        let store = self.snapshot.read().await;
        let empty = Vec::new();
        let records = store.get(model).unwrap_or(&empty);
        let mut result: Vec<serde_json::Value> = records.iter().filter(|r| matches_where(r, &query.where_clauses)).cloned().collect();
        sort_records(&mut result, &query);
        if let Some(offset) = query.offset {
            if (offset as usize) < result.len() {
                result = result.split_off(offset as usize);
            } else {
                result.clear();
            }
        }
        if let Some(limit) = query.limit {
            result.truncate(limit as usize);
        }
        Ok(result)
    }

    async fn count(&self, model: &str, where_clauses: &[WhereClause]) -> AdapterResult<i64> {
        let store = self.snapshot.read().await;
        Ok(store.get(model).map(|recs| recs.iter().filter(|r| matches_where(r, where_clauses)).count()).unwrap_or(0) as i64)
    }

    async fn update(&self, model: &str, where_clauses: &[WhereClause], data: serde_json::Value) -> AdapterResult<Option<serde_json::Value>> {
        let mut store = self.snapshot.write().await;
        if let Some(recs) = store.get_mut(model) {
            if let Some(record) = recs.iter_mut().find(|r| matches_where(r, where_clauses)) {
                merge_update(record, &data);
                return Ok(Some(record.clone()));
            }
        }
        Ok(None)
    }

    async fn update_many(&self, model: &str, where_clauses: &[WhereClause], data: serde_json::Value) -> AdapterResult<i64> {
        let mut store = self.snapshot.write().await;
        let mut count = 0i64;
        if let Some(recs) = store.get_mut(model) {
            for record in recs.iter_mut() {
                if matches_where(record, where_clauses) {
                    merge_update(record, &data);
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    async fn delete(&self, model: &str, where_clauses: &[WhereClause]) -> AdapterResult<()> {
        let mut store = self.snapshot.write().await;
        if let Some(recs) = store.get_mut(model) {
            if let Some(pos) = recs.iter().position(|r| matches_where(r, where_clauses)) {
                recs.remove(pos);
            }
        }
        Ok(())
    }

    async fn delete_many(&self, model: &str, where_clauses: &[WhereClause]) -> AdapterResult<i64> {
        let mut store = self.snapshot.write().await;
        if let Some(recs) = store.get_mut(model) {
            let before = recs.len();
            recs.retain(|r| !matches_where(r, where_clauses));
            Ok((before - recs.len()) as i64)
        } else {
            Ok(0)
        }
    }

    async fn create_schema(&self, _schema: &AuthSchema, _options: &SchemaOptions) -> AdapterResult<SchemaStatus> {
        Ok(SchemaStatus::UpToDate)
    }

    async fn begin_transaction(&self) -> AdapterResult<Box<dyn TransactionAdapter>> {
        Err(BetterAuthError::Other("Nested transactions are not supported in the memory adapter".into()))
    }
}

#[async_trait]
impl TransactionAdapter for MemoryTransactionAdapter {
    async fn commit(self: Box<Self>) -> AdapterResult<()> {
        let snapshot = self.snapshot.read().await.clone();
        let mut parent = self.parent.write().await;
        *parent = snapshot;
        self.committed.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    async fn rollback(self: Box<Self>) -> AdapterResult<()> {
        // Do nothing — snapshot is discarded
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::db::adapter::SortBy;

    #[tokio::test]
    async fn test_create_and_find_one() {
        let adapter = MemoryAdapter::new();
        let data = serde_json::json!({"id": "u1", "name": "Alice", "email": "alice@test.com"});
        adapter.create("user", data, None).await.unwrap();

        let found = adapter.find_one("user", &[WhereClause::eq("id", "u1")]).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap()["name"], "Alice");
    }

    #[tokio::test]
    async fn test_create_auto_id() {
        let adapter = MemoryAdapter::new();
        let data = serde_json::json!({"name": "Bob"});
        let created = adapter.create("user", data, None).await.unwrap();
        assert!(created.get("id").is_some());
        assert!(created["id"].is_string());
    }

    #[tokio::test]
    async fn test_find_one_not_found() {
        let adapter = MemoryAdapter::new();
        let found = adapter.find_one("user", &[WhereClause::eq("id", "nonexistent")]).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_find_many() {
        let adapter = MemoryAdapter::new();
        adapter.create("user", serde_json::json!({"id": "u1", "name": "Alice"}), None).await.unwrap();
        adapter.create("user", serde_json::json!({"id": "u2", "name": "Bob"}), None).await.unwrap();
        adapter.create("user", serde_json::json!({"id": "u3", "name": "Charlie"}), None).await.unwrap();

        let all = adapter.find_many("user", FindManyQuery::default()).await.unwrap();
        assert_eq!(all.len(), 3);
    }

    #[tokio::test]
    async fn test_find_many_with_limit() {
        let adapter = MemoryAdapter::new();
        for i in 0..10 {
            adapter.create("user", serde_json::json!({"id": format!("u{}", i), "name": format!("User {}", i)}), None).await.unwrap();
        }

        let query = FindManyQuery {
            limit: Some(3),
            ..Default::default()
        };
        let result = adapter.find_many("user", query).await.unwrap();
        assert_eq!(result.len(), 3);
    }

    #[tokio::test]
    async fn test_find_many_with_offset() {
        let adapter = MemoryAdapter::new();
        for i in 0..5 {
            adapter.create("user", serde_json::json!({"id": format!("u{}", i)}), None).await.unwrap();
        }

        let query = FindManyQuery {
            offset: Some(3),
            ..Default::default()
        };
        let result = adapter.find_many("user", query).await.unwrap();
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_find_many_sorted() {
        let adapter = MemoryAdapter::new();
        adapter.create("user", serde_json::json!({"id": "u3", "name": "Charlie"}), None).await.unwrap();
        adapter.create("user", serde_json::json!({"id": "u1", "name": "Alice"}), None).await.unwrap();
        adapter.create("user", serde_json::json!({"id": "u2", "name": "Bob"}), None).await.unwrap();

        let query = FindManyQuery {
            sort_by: Some(SortBy { field: "name".into(), direction: SortDirection::Asc }),
            ..Default::default()
        };
        let result = adapter.find_many("user", query).await.unwrap();
        assert_eq!(result[0]["name"], "Alice");
        assert_eq!(result[2]["name"], "Charlie");
    }

    #[tokio::test]
    async fn test_count() {
        let adapter = MemoryAdapter::new();
        adapter.create("user", serde_json::json!({"id": "u1"}), None).await.unwrap();
        adapter.create("user", serde_json::json!({"id": "u2"}), None).await.unwrap();

        let count = adapter.count("user", &[]).await.unwrap();
        assert_eq!(count, 2);

        let count_filtered = adapter.count("user", &[WhereClause::eq("id", "u1")]).await.unwrap();
        assert_eq!(count_filtered, 1);
    }

    #[tokio::test]
    async fn test_update() {
        let adapter = MemoryAdapter::new();
        adapter.create("user", serde_json::json!({"id": "u1", "name": "Alice"}), None).await.unwrap();

        let updated = adapter.update("user", &[WhereClause::eq("id", "u1")], serde_json::json!({"name": "Alice Updated"})).await.unwrap();
        assert!(updated.is_some());
        assert_eq!(updated.unwrap()["name"], "Alice Updated");

        // Verify persistence
        let found = adapter.find_one("user", &[WhereClause::eq("id", "u1")]).await.unwrap().unwrap();
        assert_eq!(found["name"], "Alice Updated");
    }

    #[tokio::test]
    async fn test_update_many() {
        let adapter = MemoryAdapter::new();
        adapter.create("user", serde_json::json!({"id": "u1", "active": true}), None).await.unwrap();
        adapter.create("user", serde_json::json!({"id": "u2", "active": true}), None).await.unwrap();

        let count = adapter.update_many("user", &[], serde_json::json!({"active": false})).await.unwrap();
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn test_delete() {
        let adapter = MemoryAdapter::new();
        adapter.create("user", serde_json::json!({"id": "u1"}), None).await.unwrap();
        adapter.create("user", serde_json::json!({"id": "u2"}), None).await.unwrap();

        adapter.delete("user", &[WhereClause::eq("id", "u1")]).await.unwrap();
        let count = adapter.count("user", &[]).await.unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_delete_many() {
        let adapter = MemoryAdapter::new();
        for i in 0..5 {
            adapter.create("user", serde_json::json!({"id": format!("u{}", i)}), None).await.unwrap();
        }

        let deleted = adapter.delete_many("user", &[]).await.unwrap();
        assert_eq!(deleted, 5);
        assert_eq!(adapter.count("user", &[]).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_operator_ne() {
        let adapter = MemoryAdapter::new();
        adapter.create("user", serde_json::json!({"id": "u1", "role": "admin"}), None).await.unwrap();
        adapter.create("user", serde_json::json!({"id": "u2", "role": "member"}), None).await.unwrap();

        let clause = WhereClause {
            field: "role".into(),
            value: serde_json::json!("admin"),
            operator: Operator::Ne,
            connector: None,
        };
        let result = adapter.find_many("user", FindManyQuery { where_clauses: vec![clause], ..Default::default() }).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["role"], "member");
    }

    #[tokio::test]
    async fn test_operator_contains() {
        let adapter = MemoryAdapter::new();
        adapter.create("user", serde_json::json!({"id": "u1", "email": "alice@test.com"}), None).await.unwrap();
        adapter.create("user", serde_json::json!({"id": "u2", "email": "bob@other.com"}), None).await.unwrap();

        let clause = WhereClause {
            field: "email".into(),
            value: serde_json::json!("test.com"),
            operator: Operator::Contains,
            connector: None,
        };
        let result = adapter.find_many("user", FindManyQuery { where_clauses: vec![clause], ..Default::default() }).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["id"], "u1");
    }

    #[tokio::test]
    async fn test_operator_in() {
        let adapter = MemoryAdapter::new();
        adapter.create("user", serde_json::json!({"id": "u1", "role": "admin"}), None).await.unwrap();
        adapter.create("user", serde_json::json!({"id": "u2", "role": "member"}), None).await.unwrap();
        adapter.create("user", serde_json::json!({"id": "u3", "role": "guest"}), None).await.unwrap();

        let clause = WhereClause {
            field: "role".into(),
            value: serde_json::json!(["admin", "guest"]),
            operator: Operator::In,
            connector: None,
        };
        let result = adapter.find_many("user", FindManyQuery { where_clauses: vec![clause], ..Default::default() }).await.unwrap();
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_transaction_commit() {
        let adapter = MemoryAdapter::new();
        adapter.create("user", serde_json::json!({"id": "u1", "name": "Alice"}), None).await.unwrap();

        let tx = adapter.begin_transaction().await.unwrap();
        tx.create("user", serde_json::json!({"id": "u2", "name": "Bob"}), None).await.unwrap();
        tx.commit().await.unwrap();

        assert_eq!(adapter.count("user", &[]).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn test_transaction_rollback() {
        let adapter = MemoryAdapter::new();
        adapter.create("user", serde_json::json!({"id": "u1", "name": "Alice"}), None).await.unwrap();

        let tx = adapter.begin_transaction().await.unwrap();
        tx.create("user", serde_json::json!({"id": "u2", "name": "Bob"}), None).await.unwrap();
        tx.rollback().await.unwrap();

        // Rollback — Bob should not exist
        assert_eq!(adapter.count("user", &[]).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_clear() {
        let adapter = MemoryAdapter::new();
        adapter.create("user", serde_json::json!({"id": "u1"}), None).await.unwrap();
        adapter.clear().await;
        assert_eq!(adapter.model_count("user").await, 0);
    }

    #[tokio::test]
    async fn test_snapshot() {
        let adapter = MemoryAdapter::new();
        adapter.create("user", serde_json::json!({"id": "u1"}), None).await.unwrap();
        let snap = adapter.snapshot().await;
        assert!(snap.contains_key("user"));
        assert_eq!(snap["user"].len(), 1);
    }

    #[tokio::test]
    async fn test_create_schema() {
        let adapter = MemoryAdapter::new();
        let schema = AuthSchema::core_schema();
        let status = adapter.create_schema(&schema, &SchemaOptions::default()).await.unwrap();
        assert!(matches!(status, SchemaStatus::UpToDate));
    }
}
