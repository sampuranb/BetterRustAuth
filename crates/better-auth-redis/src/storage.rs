// Secondary storage — trait + implementations for cache-layer operations.
//
// Maps to: packages/core/src/secondary-storage.ts
// Provides get/set/delete with TTL, plus higher-level helpers for sessions,
// verification tokens, and rate limiting.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::RwLock;

// ─── SecondaryStorage Trait ──────────────────────────────────────

/// Secondary storage trait for caching and ephemeral data.
///
/// Maps to the TypeScript `SecondaryStorage` interface.
/// Used for session caching, verification token storage, and rate limiting.
#[async_trait]
pub trait SecondaryStorage: Send + Sync + std::fmt::Debug {
    /// Get a value by key. Returns `None` if missing or expired.
    async fn get(&self, key: &str) -> Result<Option<String>, StorageError>;

    /// Set a value with an optional TTL (in seconds).
    async fn set(&self, key: &str, value: &str, ttl: Option<u64>) -> Result<(), StorageError>;

    /// Delete a key. Returns `true` if the key existed.
    async fn delete(&self, key: &str) -> Result<bool, StorageError>;

    /// Check if a key exists (and is not expired).
    async fn exists(&self, key: &str) -> Result<bool, StorageError> {
        Ok(self.get(key).await?.is_some())
    }

    /// Set a key's TTL (in seconds). Returns false if key doesn't exist.
    async fn expire(&self, key: &str, ttl: u64) -> Result<bool, StorageError>;

    /// Increment a numeric key by delta (for rate limiting).
    /// Creates the key with value `delta` if missing.
    async fn incr(&self, key: &str, delta: i64) -> Result<i64, StorageError>;

    /// Get multiple keys at once.
    async fn mget(&self, keys: &[&str]) -> Result<Vec<Option<String>>, StorageError> {
        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            results.push(self.get(key).await?);
        }
        Ok(results)
    }

    /// Delete multiple keys. Returns the number of keys deleted.
    async fn mdel(&self, keys: &[&str]) -> Result<i64, StorageError> {
        let mut count = 0i64;
        for key in keys {
            if self.delete(key).await? {
                count += 1;
            }
        }
        Ok(count)
    }
}

/// Errors from secondary storage operations.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Connection error: {0}")]
    Connection(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Storage error: {0}")]
    Other(String),
}

// ─── In-Memory Implementation ────────────────────────────────────

/// An entry in the in-memory store.
#[derive(Debug, Clone)]
struct Entry {
    value: String,
    expires_at: Option<Instant>,
}

impl Entry {
    fn is_expired(&self) -> bool {
        self.expires_at.map_or(false, |exp| Instant::now() > exp)
    }
}

/// In-memory implementation of `SecondaryStorage`.
///
/// Useful for testing and development. Not suitable for production
/// multi-process deployments.
#[derive(Debug, Clone)]
pub struct InMemorySecondaryStorage {
    store: Arc<RwLock<HashMap<String, Entry>>>,
}

impl Default for InMemorySecondaryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemorySecondaryStorage {
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Remove all expired entries.
    pub async fn cleanup(&self) {
        let mut store = self.store.write().await;
        store.retain(|_, entry| !entry.is_expired());
    }

    /// Get total number of non-expired entries.
    pub async fn len(&self) -> usize {
        let store = self.store.read().await;
        store.values().filter(|e| !e.is_expired()).count()
    }

    /// Check if the store is empty.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

#[async_trait]
impl SecondaryStorage for InMemorySecondaryStorage {
    async fn get(&self, key: &str) -> Result<Option<String>, StorageError> {
        let store = self.store.read().await;
        match store.get(key) {
            Some(entry) if !entry.is_expired() => Ok(Some(entry.value.clone())),
            _ => Ok(None),
        }
    }

    async fn set(&self, key: &str, value: &str, ttl: Option<u64>) -> Result<(), StorageError> {
        let expires_at = ttl.map(|secs| Instant::now() + Duration::from_secs(secs));
        let mut store = self.store.write().await;
        store.insert(
            key.to_string(),
            Entry {
                value: value.to_string(),
                expires_at,
            },
        );
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<bool, StorageError> {
        let mut store = self.store.write().await;
        Ok(store.remove(key).is_some())
    }

    async fn expire(&self, key: &str, ttl: u64) -> Result<bool, StorageError> {
        let mut store = self.store.write().await;
        if let Some(entry) = store.get_mut(key) {
            if !entry.is_expired() {
                entry.expires_at = Some(Instant::now() + Duration::from_secs(ttl));
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn incr(&self, key: &str, delta: i64) -> Result<i64, StorageError> {
        let mut store = self.store.write().await;
        let current = match store.get(key) {
            Some(entry) if !entry.is_expired() => {
                entry.value.parse::<i64>().unwrap_or(0)
            }
            _ => 0,
        };
        let new_val = current + delta;
        // Preserve existing TTL
        let expires_at = store.get(key).and_then(|e| e.expires_at);
        store.insert(
            key.to_string(),
            Entry {
                value: new_val.to_string(),
                expires_at,
            },
        );
        Ok(new_val)
    }
}

// ─── Redis-Like Connection Trait ─────────────────────────────────

/// Trait for Redis-like connections.
///
/// Implement this trait for your Redis client library (e.g., `redis`, `fred`,
/// `deadpool-redis`) to use `RedisSecondaryStorage`.
#[async_trait]
pub trait RedisLikeConnection: Send + Sync + std::fmt::Debug {
    async fn get(&self, key: &str) -> Result<Option<String>, StorageError>;
    async fn set_ex(&self, key: &str, value: &str, ttl_secs: u64) -> Result<(), StorageError>;
    async fn set(&self, key: &str, value: &str) -> Result<(), StorageError>;
    async fn del(&self, key: &str) -> Result<bool, StorageError>;
    async fn expire(&self, key: &str, ttl_secs: u64) -> Result<bool, StorageError>;
    async fn incr_by(&self, key: &str, delta: i64) -> Result<i64, StorageError>;
}

/// Redis secondary storage adapter.
///
/// Wraps a `RedisLikeConnection` and implements `SecondaryStorage`.
/// This allows any Redis client library to be used as the backing store.
#[derive(Debug)]
pub struct RedisSecondaryStorage<C: RedisLikeConnection> {
    conn: C,
    /// Optional key prefix for namespacing.
    pub prefix: String,
}

impl<C: RedisLikeConnection> RedisSecondaryStorage<C> {
    /// Create a new Redis secondary storage with a connection.
    pub fn new(conn: C) -> Self {
        Self {
            conn,
            prefix: "ba:".to_string(),
        }
    }

    /// Create with a custom key prefix.
    pub fn with_prefix(conn: C, prefix: impl Into<String>) -> Self {
        Self {
            conn,
            prefix: prefix.into(),
        }
    }

    fn prefixed(&self, key: &str) -> String {
        format!("{}{}", self.prefix, key)
    }
}

#[async_trait]
impl<C: RedisLikeConnection + 'static> SecondaryStorage for RedisSecondaryStorage<C> {
    async fn get(&self, key: &str) -> Result<Option<String>, StorageError> {
        self.conn.get(&self.prefixed(key)).await
    }

    async fn set(&self, key: &str, value: &str, ttl: Option<u64>) -> Result<(), StorageError> {
        let pk = self.prefixed(key);
        match ttl {
            Some(secs) => self.conn.set_ex(&pk, value, secs).await,
            None => self.conn.set(&pk, value).await,
        }
    }

    async fn delete(&self, key: &str) -> Result<bool, StorageError> {
        self.conn.del(&self.prefixed(key)).await
    }

    async fn expire(&self, key: &str, ttl: u64) -> Result<bool, StorageError> {
        self.conn.expire(&self.prefixed(key), ttl).await
    }

    async fn incr(&self, key: &str, delta: i64) -> Result<i64, StorageError> {
        self.conn.incr_by(&self.prefixed(key), delta).await
    }
}

// ─── Helper functions ────────────────────────────────────────────

/// Create a session cache key.
pub fn session_key(session_token: &str) -> String {
    format!("session:{}", session_token)
}

/// Create a verification token cache key.
pub fn verification_key(identifier: &str, token: &str) -> String {
    format!("verification:{}:{}", identifier, token)
}

/// Create a rate limit cache key.
pub fn rate_limit_key(identifier: &str, window: &str) -> String {
    format!("rate_limit:{}:{}", identifier, window)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_set_and_get() {
        let storage = InMemorySecondaryStorage::new();
        storage.set("key1", "value1", None).await.unwrap();
        let result = storage.get("key1").await.unwrap();
        assert_eq!(result, Some("value1".to_string()));
    }

    #[tokio::test]
    async fn test_get_missing() {
        let storage = InMemorySecondaryStorage::new();
        let result = storage.get("missing").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete() {
        let storage = InMemorySecondaryStorage::new();
        storage.set("key1", "value1", None).await.unwrap();
        let deleted = storage.delete("key1").await.unwrap();
        assert!(deleted);
        let result = storage.get("key1").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_missing() {
        let storage = InMemorySecondaryStorage::new();
        let deleted = storage.delete("missing").await.unwrap();
        assert!(!deleted);
    }

    #[tokio::test]
    async fn test_exists() {
        let storage = InMemorySecondaryStorage::new();
        storage.set("key1", "val", None).await.unwrap();
        assert!(storage.exists("key1").await.unwrap());
        assert!(!storage.exists("missing").await.unwrap());
    }

    #[tokio::test]
    async fn test_incr() {
        let storage = InMemorySecondaryStorage::new();
        let val = storage.incr("counter", 1).await.unwrap();
        assert_eq!(val, 1);
        let val = storage.incr("counter", 5).await.unwrap();
        assert_eq!(val, 6);
        let val = storage.incr("counter", -2).await.unwrap();
        assert_eq!(val, 4);
    }

    #[tokio::test]
    async fn test_ttl_expiry() {
        let storage = InMemorySecondaryStorage::new();
        // Set with 0-second TTL (immediately expired)
        storage.set("key1", "value1", Some(0)).await.unwrap();
        // Wait a tiny bit to ensure expiry
        tokio::time::sleep(Duration::from_millis(10)).await;
        let result = storage.get("key1").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_expire_existing() {
        let storage = InMemorySecondaryStorage::new();
        storage.set("key1", "value1", None).await.unwrap();
        let result = storage.expire("key1", 3600).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_expire_missing() {
        let storage = InMemorySecondaryStorage::new();
        let result = storage.expire("missing", 3600).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_mget() {
        let storage = InMemorySecondaryStorage::new();
        storage.set("k1", "v1", None).await.unwrap();
        storage.set("k2", "v2", None).await.unwrap();
        let results = storage.mget(&["k1", "k2", "k3"]).await.unwrap();
        assert_eq!(results, vec![
            Some("v1".to_string()),
            Some("v2".to_string()),
            None
        ]);
    }

    #[tokio::test]
    async fn test_mdel() {
        let storage = InMemorySecondaryStorage::new();
        storage.set("k1", "v1", None).await.unwrap();
        storage.set("k2", "v2", None).await.unwrap();
        let count = storage.mdel(&["k1", "k3"]).await.unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_cleanup() {
        let storage = InMemorySecondaryStorage::new();
        storage.set("live", "val", None).await.unwrap();
        storage.set("expired", "val", Some(0)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        storage.cleanup().await;
        assert_eq!(storage.len().await, 1);
    }

    #[tokio::test]
    async fn test_helper_keys() {
        assert_eq!(session_key("abc123"), "session:abc123");
        assert_eq!(verification_key("email", "tok"), "verification:email:tok");
        assert_eq!(rate_limit_key("ip:1.2.3.4", "60s"), "rate_limit:ip:1.2.3.4:60s");
    }

    #[tokio::test]
    async fn test_len_and_is_empty() {
        let storage = InMemorySecondaryStorage::new();
        assert!(storage.is_empty().await);
        storage.set("k1", "v1", None).await.unwrap();
        assert!(!storage.is_empty().await);
        assert_eq!(storage.len().await, 1);
    }
}
