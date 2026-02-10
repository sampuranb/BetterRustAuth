// better-auth-drizzle — Drizzle ORM compatibility adapter for better-auth.
//
// Provides a drop-in replacement for teams migrating from the TypeScript better-auth
// with `drizzleAdapter()` to the Rust version. Wraps `better-auth-sqlx` internally
// and applies Drizzle's field/table naming conventions (snake_case by default,
// optional camelCase, optional plural table names).
//
// Maps to: packages/drizzle-adapter/src/drizzle-adapter.ts

pub mod adapter;
pub mod naming;
pub mod schema_reader;

pub use adapter::DrizzleAdapter;
