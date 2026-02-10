// better-auth-kysely — Kysely query builder compatibility adapter for better-auth.
//
// Provides a drop-in replacement for teams migrating from the TypeScript better-auth
// with `kyselyAdapter()` to the Rust version. Wraps `better-auth-sqlx` internally
// and applies Kysely's field/table naming conventions.
//
// Maps to: packages/kysely-adapter/src/kysely-adapter.ts

pub mod adapter;
pub mod naming;

pub use adapter::KyselyAdapter;
