// better-auth-memory — In-memory database adapter for better-auth.
//
// Uses a HashMap-based store for fast, ephemeral data storage.
// Ideal for testing, prototyping, and development.
// Maps to the in-memory adapter approach from the TS equivalent.

pub mod adapter;

pub use adapter::MemoryAdapter;
