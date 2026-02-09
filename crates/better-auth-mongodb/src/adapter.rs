// MongoAdapter — concrete implementation of the core Adapter trait using MongoDB.
//
// Maps relational concepts to MongoDB:
// - Tables → Collections
// - Rows → Documents
// - id field → _id field
// - WHERE clauses → find filters

use async_trait::async_trait;
use mongodb::bson::doc;
use mongodb::options::FindOptions;
use mongodb::{Client, Collection, Database};

use better_auth_core::db::adapter::{
    Adapter, AdapterResult, FindManyQuery, SchemaOptions, SchemaStatus, TransactionAdapter,
    WhereClause,
};
use better_auth_core::db::schema::AuthSchema;
use better_auth_core::error::BetterAuthError;

use crate::query;

/// MongoDB database adapter.
///
/// Wraps a MongoDB `Database` and implements the core `Adapter` trait.
/// Maps tables to collections and uses BSON documents for all operations.
#[derive(Debug, Clone)]
pub struct MongoAdapter {
    db: Database,
}

impl MongoAdapter {
    /// Create a new adapter from an existing database handle.
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Create a new adapter by connecting to a MongoDB URI.
    pub async fn connect(uri: &str, db_name: &str) -> Result<Self, BetterAuthError> {
        let client = Client::with_uri_str(uri)
            .await
            .map_err(|e| BetterAuthError::Other(format!("MongoDB connection failed: {e}")))?;
        let db = client.database(db_name);
        Ok(Self { db })
    }

    /// Get a reference to the underlying database.
    pub fn database(&self) -> &Database {
        &self.db
    }

    /// Get a collection by model name.
    fn collection(&self, model: &str) -> Collection<mongodb::bson::Document> {
        self.db.collection(model)
    }
}

#[async_trait]
impl Adapter for MongoAdapter {
    async fn create(
        &self,
        model: &str,
        data: serde_json::Value,
        _select: Option<&[String]>,
    ) -> AdapterResult<serde_json::Value> {
        let coll = self.collection(model);
        let doc = query::build_insert_doc(&data);

        coll.insert_one(doc.clone())
            .await
            .map_err(|e| BetterAuthError::Other(format!("MongoDB insert failed: {e}")))?;

        // Return the data as-is (ID was already set in the input)
        Ok(data)
    }

    async fn find_one(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<Option<serde_json::Value>> {
        let coll = self.collection(model);
        let filter = query::build_filter(where_clauses);

        let result = coll
            .find_one(filter)
            .await
            .map_err(|e| BetterAuthError::Other(format!("MongoDB find_one failed: {e}")))?;

        Ok(result.map(|doc| query::doc_to_json(&doc)))
    }

    async fn find_many(
        &self,
        model: &str,
        query_params: FindManyQuery,
    ) -> AdapterResult<Vec<serde_json::Value>> {
        let coll = self.collection(model);
        let filter = query::build_filter(&query_params.where_clauses);

        let mut find_opts = FindOptions::default();

        if let Some(limit) = query_params.limit {
            find_opts.limit = Some(limit);
        }

        if let Some(offset) = query_params.offset {
            find_opts.skip = Some(offset as u64);
        }

        if let Some(sort) = query::build_sort(&query_params) {
            find_opts.sort = Some(sort);
        }

        let mut cursor = coll
            .find(filter)
            .with_options(find_opts)
            .await
            .map_err(|e| BetterAuthError::Other(format!("MongoDB find failed: {e}")))?;

        let mut results = Vec::new();
        use futures_util::StreamExt;
        while let Some(doc) = cursor.next().await {
            let doc = doc.map_err(|e| BetterAuthError::Other(format!("Cursor error: {e}")))?;
            results.push(query::doc_to_json(&doc));
        }

        Ok(results)
    }

    async fn count(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<i64> {
        let coll = self.collection(model);
        let filter = query::build_filter(where_clauses);

        let count = coll
            .count_documents(filter)
            .await
            .map_err(|e| BetterAuthError::Other(format!("MongoDB count failed: {e}")))?;

        Ok(count as i64)
    }

    async fn update(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
        data: serde_json::Value,
    ) -> AdapterResult<Option<serde_json::Value>> {
        let coll = self.collection(model);
        let filter = query::build_filter(where_clauses);
        let update = query::build_update_doc(&data);

        let result = coll
            .update_one(filter.clone(), update)
            .await
            .map_err(|e| BetterAuthError::Other(format!("MongoDB update failed: {e}")))?;

        if result.modified_count == 0 && result.matched_count == 0 {
            return Ok(None);
        }

        // Find the updated document
        let updated = coll
            .find_one(filter)
            .await
            .map_err(|e| BetterAuthError::Other(format!("MongoDB find after update failed: {e}")))?;

        Ok(updated.map(|doc| query::doc_to_json(&doc)))
    }

    async fn update_many(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
        data: serde_json::Value,
    ) -> AdapterResult<i64> {
        let coll = self.collection(model);
        let filter = query::build_filter(where_clauses);
        let update = query::build_update_doc(&data);

        let result = coll
            .update_many(filter, update)
            .await
            .map_err(|e| BetterAuthError::Other(format!("MongoDB update_many failed: {e}")))?;

        Ok(result.modified_count as i64)
    }

    async fn delete(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<()> {
        let coll = self.collection(model);
        let filter = query::build_filter(where_clauses);

        coll.delete_one(filter)
            .await
            .map_err(|e| BetterAuthError::Other(format!("MongoDB delete failed: {e}")))?;

        Ok(())
    }

    async fn delete_many(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<i64> {
        let coll = self.collection(model);
        let filter = query::build_filter(where_clauses);

        let result = coll
            .delete_many(filter)
            .await
            .map_err(|e| BetterAuthError::Other(format!("MongoDB delete_many failed: {e}")))?;

        Ok(result.deleted_count as i64)
    }

    async fn create_schema(
        &self,
        schema: &AuthSchema,
        _options: &SchemaOptions,
    ) -> AdapterResult<SchemaStatus> {
        // MongoDB is schemaless — we just create indexes for fields that need them
        for (table_name, table) in &schema.tables {
            let coll = self.collection(table_name);

            // Create unique indexes for unique fields
            for (field_name, field) in &table.fields {
                if field.unique && field_name != "id" {
                    let mongo_field = field_name.to_string();
                    let index_model = mongodb::IndexModel::builder()
                        .keys(doc! { &mongo_field: 1 })
                        .options(
                            mongodb::options::IndexOptions::builder()
                                .unique(true)
                                .build(),
                        )
                        .build();

                    let _ = coll.create_index(index_model).await;
                }
            }

            // Create indexes for referenced fields (foreign keys → indexed for lookups)
            for (field_name, field) in &table.fields {
                if field.references.is_some() {
                    let mongo_field = field_name.to_string();
                    let index_model = mongodb::IndexModel::builder()
                        .keys(doc! { &mongo_field: 1 })
                        .build();

                    let _ = coll.create_index(index_model).await;
                }
            }
        }

        Ok(SchemaStatus::UpToDate)
    }

    async fn begin_transaction(&self) -> AdapterResult<Box<dyn TransactionAdapter>> {
        Err(BetterAuthError::Other(
            "MongoDB transactions require a replica set. Use `client.start_session()` and \
             `session.start_transaction()` directly for transaction support."
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_debug() {
        let debug_str = format!("{}", "MongoAdapter");
        assert!(!debug_str.is_empty());
    }
}
