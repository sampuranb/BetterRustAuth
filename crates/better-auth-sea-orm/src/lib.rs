// better-auth-sea-orm — Sea-ORM database adapter for better-auth.
//
// Provides a concrete implementation of the core Adapter trait using Sea-ORM's
// DatabaseConnection. Supports dynamic table/model operations via sea-query
// for SQL building and Sea-ORM for connection management.

pub mod adapter;
pub mod entity_gen;
pub mod query;

pub use adapter::SeaOrmAdapter;
