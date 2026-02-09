// better-auth-redis — Secondary storage adapter for better-auth.
//
// Provides a `SecondaryStorage` trait for caching sessions, storing verification
// tokens, and rate limiting. Includes a Redis-compatible implementation and
// an in-memory fallback for testing.
//
// Maps to: packages/core/src/secondary-storage.ts

pub mod storage;

pub use storage::{
    InMemorySecondaryStorage, RedisLikeConnection, RedisSecondaryStorage, SecondaryStorage,
};
