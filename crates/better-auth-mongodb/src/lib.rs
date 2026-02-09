// better-auth-mongodb — MongoDB database adapter for better-auth.
//
// Provides a concrete implementation of the core Adapter trait using the
// official MongoDB Rust driver. Maps relational concepts (tables → collections,
// rows → documents) to MongoDB's document model.
//
// Maps to: packages/better-auth/src/adapters/mongodb-adapter/

pub mod adapter;
pub mod query;

pub use adapter::MongoAdapter;
