// better-auth-sqlx — SQLx database adapter for better-auth.
//
// Provides a concrete implementation of the core Adapter trait using sqlx::AnyPool,
// supporting Postgres, MySQL, and SQLite through compile-time feature flags.

pub mod adapter;
pub mod migration;
pub mod query_builder;
pub mod schema;
pub mod transaction;

pub use adapter::SqlxAdapter;
pub use migration::{get_migrations, get_migrations_auto, MigrationPlan};
pub use transaction::SqlxTransactionAdapter;
