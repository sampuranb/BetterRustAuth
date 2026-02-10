// better-auth-prisma — Prisma compatibility adapter for better-auth.
//
// Provides a drop-in replacement for teams migrating from the TypeScript better-auth
// with `prismaAdapter()` to the Rust version. Wraps `better-auth-sqlx` internally
// and applies Prisma's field/table naming conventions.
//
// Maps to: packages/prisma-adapter/src/prisma-adapter.ts

pub mod adapter;
pub mod naming;
pub mod schema_reader;

pub use adapter::PrismaAdapter;
