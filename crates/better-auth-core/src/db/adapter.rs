// Database adapter trait — the core abstraction that all database backends implement.
//
// Maps to: packages/core/src/db/adapter/index.ts
// This is the central interface: create, findOne, findMany, update, delete, count,
// plus transaction support. All query filter operators are preserved.

use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::db::schema::AuthSchema;
use crate::error::BetterAuthError;

/// Result type for adapter operations.
pub type AdapterResult<T> = std::result::Result<T, BetterAuthError>;

// ─── Where Clause ────────────────────────────────────────────────

/// Comparison operators for WHERE clauses.
/// Matches the TypeScript `Operator` union type exactly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    /// Equal (default).
    Eq,
    /// Not equal.
    Ne,
    /// Less than.
    Lt,
    /// Less than or equal.
    Lte,
    /// Greater than.
    Gt,
    /// Greater than or equal.
    Gte,
    /// Value is in the given list.
    In,
    /// String contains substring.
    Contains,
    /// String starts with prefix.
    StartsWith,
    /// String ends with suffix.
    EndsWith,
}

impl Default for Operator {
    fn default() -> Self {
        Self::Eq
    }
}

/// A single WHERE condition.
/// Maps to the TypeScript `Where` type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhereClause {
    /// The field name to filter on.
    pub field: String,
    /// The comparison value.
    pub value: serde_json::Value,
    /// The comparison operator (default: Eq).
    #[serde(default)]
    pub operator: Operator,
    /// Connector to the next clause. None means this is the last/only clause.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector: Option<Connector>,
}

/// Logical connector between WHERE clauses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Connector {
    And,
    Or,
}

impl WhereClause {
    /// Simple equality filter.
    pub fn eq(field: impl Into<String>, value: impl Into<serde_json::Value>) -> Self {
        Self {
            field: field.into(),
            value: value.into(),
            operator: Operator::Eq,
            connector: None,
        }
    }

    /// Add an AND connector.
    pub fn and(mut self) -> Self {
        self.connector = Some(Connector::And);
        self
    }

    /// Add an OR connector.
    pub fn or(mut self) -> Self {
        self.connector = Some(Connector::Or);
        self
    }
}

// ─── Sort / Select / Pagination ──────────────────────────────────

/// Sort direction for ORDER BY.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDirection {
    Asc,
    Desc,
}

/// Sort specification (field + direction).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SortBy {
    pub field: String,
    pub direction: SortDirection,
}

// ─── Join Configuration ──────────────────────────────────────────

/// JOIN type. Maps to `JoinType` in TypeScript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JoinType {
    Inner,
    Left,
    Right,
    Full,
}

impl Default for JoinType {
    fn default() -> Self {
        Self::Left
    }
}

/// A single JOIN clause.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinConfig {
    /// The table to join with.
    pub table: String,
    /// Field on the LEFT table (the model being queried).
    pub on_left: String,
    /// Field on the RIGHT table (the joining table).
    pub on_right: String,
    /// JOIN type (default: LEFT).
    #[serde(default)]
    pub join_type: JoinType,
    /// Alias for the joined table in the result set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Select specific fields from the joined table.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub select: Option<Vec<String>>,
    /// Additional WHERE clauses for the join.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub where_clauses: Option<Vec<WhereClause>>,
}

// ─── Find Many Query ─────────────────────────────────────────────

/// Query parameters for `find_many`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindManyQuery {
    pub where_clauses: Vec<WhereClause>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort_by: Option<SortBy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub select: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub joins: Option<Vec<JoinConfig>>,
}

// ─── Schema Diff / Migration ─────────────────────────────────────

/// Result of a schema comparison (for migrations).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SchemaStatus {
    /// Schema matches — no changes needed.
    UpToDate,
    /// Schema needs changes. Contains the ALTER/CREATE statements.
    NeedsMigration {
        statements: Vec<String>,
    },
}

/// Options for schema creation/migration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SchemaOptions {
    /// If true, automatically apply migrations.
    #[serde(default)]
    pub auto_migrate: bool,
}

// ─── Adapter Trait ───────────────────────────────────────────────

/// The core database adapter trait.
///
/// Every database backend (SQLx, MongoDB, Memory) implements this trait.
/// The adapter works with `serde_json::Value` to be schema-agnostic —
/// the internal adapter layer (in the `better-auth` crate) converts
/// between typed models and `Value`.
///
/// Maps to: `Adapter` in `packages/core/src/db/adapter/index.ts`
#[async_trait]
pub trait Adapter: Send + Sync + fmt::Debug {
    /// Create a new record in the given model/table.
    /// Returns the created record (with auto-generated fields like `id`, `createdAt`).
    async fn create(
        &self,
        model: &str,
        data: serde_json::Value,
        select: Option<&[String]>,
    ) -> AdapterResult<serde_json::Value>;

    /// Find a single record matching the WHERE clauses.
    /// Returns `None` if no match found.
    async fn find_one(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<Option<serde_json::Value>>;

    /// Find multiple records matching the query parameters.
    async fn find_many(
        &self,
        model: &str,
        query: FindManyQuery,
    ) -> AdapterResult<Vec<serde_json::Value>>;

    /// Count records matching the WHERE clauses.
    async fn count(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<i64>;

    /// Update a single record matching the WHERE clauses.
    /// Returns the updated record, or `None` if no match was found.
    async fn update(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
        data: serde_json::Value,
    ) -> AdapterResult<Option<serde_json::Value>>;

    /// Update multiple records matching the WHERE clauses.
    /// Returns the number of affected rows.
    async fn update_many(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
        data: serde_json::Value,
    ) -> AdapterResult<i64>;

    /// Delete a single record matching the WHERE clauses.
    async fn delete(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<()>;

    /// Delete multiple records matching the WHERE clauses.
    /// Returns the number of deleted rows.
    async fn delete_many(
        &self,
        model: &str,
        where_clauses: &[WhereClause],
    ) -> AdapterResult<i64>;

    /// Check the current schema against the expected schema and report status.
    async fn create_schema(
        &self,
        schema: &AuthSchema,
        options: &SchemaOptions,
    ) -> AdapterResult<SchemaStatus>;

    /// Begin a new database transaction.
    /// Returns a transactional adapter that implements the same `Adapter` trait.
    async fn begin_transaction(&self) -> AdapterResult<Box<dyn TransactionAdapter>>;
}

/// Extension of [`Adapter`] for transaction contexts.
/// Provides commit/rollback on top of the standard CRUD operations.
#[async_trait]
pub trait TransactionAdapter: Adapter {
    /// Commit the transaction.
    async fn commit(self: Box<Self>) -> AdapterResult<()>;

    /// Rollback the transaction.
    async fn rollback(self: Box<Self>) -> AdapterResult<()>;
}
