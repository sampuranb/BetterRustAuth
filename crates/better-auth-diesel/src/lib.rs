// better-auth-diesel — Diesel database adapter for better-auth.
//
// Provides a concrete implementation of the core Adapter trait using Diesel ORM
// with connection pooling via r2d2. Supports Postgres, MySQL, and SQLite
// through compile-time feature flags.

pub mod adapter;
pub mod query;
pub mod schema_gen;

pub use adapter::DieselAdapter;
