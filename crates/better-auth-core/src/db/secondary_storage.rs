// Secondary storage trait — maps to packages/core/src/types/init-options.ts SecondaryStorage.
//
// An abstract key-value store used for sessions, rate-limiting, verification
// tokens, and other ephemeral data that benefits from fast lookup and TTL support.
// Implementations include in-memory, Redis, and database-backed stores.

use async_trait::async_trait;

/// A secondary key-value storage backend.
///
/// Used for caching sessions, rate-limit counters, verification tokens, and
/// other ephemeral data. Implementations should support TTL-based expiration.
///
/// Maps to the TypeScript `SecondaryStorage` interface:
/// ```ts
/// interface SecondaryStorage {
///     get: (key: string) => Promise<string | null>;
///     set: (key: string, value: string, ttl?: number) => Promise<void>;
///     delete: (key: string) => Promise<void>;
/// }
/// ```
#[async_trait]
pub trait SecondaryStorage: Send + Sync + std::fmt::Debug {
    /// Get a value by key. Returns `None` if the key doesn't exist or has expired.
    async fn get(&self, key: &str) -> Result<Option<String>, SecondaryStorageError>;

    /// Set a key-value pair with an optional TTL in seconds.
    /// If `ttl` is `None`, the entry never expires (or uses a very long default TTL).
    async fn set(&self, key: &str, value: &str, ttl: Option<u64>) -> Result<(), SecondaryStorageError>;

    /// Delete a key.
    async fn delete(&self, key: &str) -> Result<(), SecondaryStorageError>;
}

/// Errors from secondary storage operations.
#[derive(Debug, thiserror::Error)]
pub enum SecondaryStorageError {
    #[error("Secondary storage operation failed: {0}")]
    OperationFailed(String),
}

/// Rate limit storage — specialized secondary storage for rate-limit data.
///
/// Maps to the TypeScript `BetterAuthRateLimitStorage` interface.
#[async_trait]
pub trait RateLimitStorage: Send + Sync + std::fmt::Debug {
    /// Get rate-limit data for a key.
    async fn get(&self, key: &str) -> Option<RateLimitData>;

    /// Set rate-limit data for a key.
    /// `update` indicates whether this is updating an existing entry.
    async fn set(&self, key: &str, value: RateLimitData, update: bool);
}

/// Rate limit data stored per key.
///
/// Mirrors TS `RateLimit` type.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RateLimitData {
    /// The rate limit key (ip:path).
    pub key: String,
    /// Number of requests in the current window.
    pub count: u64,
    /// Timestamp (millis) of the last request.
    pub last_request: u64,
}

/// An in-memory secondary storage implementation backed by a HashMap with TTL.
///
/// Useful for development, testing, and single-server deployments.
/// For production multi-server setups, use Redis.
#[derive(Debug)]
pub struct MemorySecondaryStorage {
    store: std::sync::Mutex<std::collections::HashMap<String, MemoryEntry>>,
}

#[derive(Debug, Clone)]
struct MemoryEntry {
    value: String,
    expires_at: Option<std::time::Instant>,
}

impl MemorySecondaryStorage {
    pub fn new() -> Self {
        Self {
            store: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl Default for MemorySecondaryStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecondaryStorage for MemorySecondaryStorage {
    async fn get(&self, key: &str) -> Result<Option<String>, SecondaryStorageError> {
        let mut store = self.store.lock().unwrap();
        if let Some(entry) = store.get(key) {
            if let Some(expires_at) = entry.expires_at {
                if std::time::Instant::now() >= expires_at {
                    store.remove(key);
                    return Ok(None);
                }
            }
            Ok(Some(entry.value.clone()))
        } else {
            Ok(None)
        }
    }

    async fn set(&self, key: &str, value: &str, ttl: Option<u64>) -> Result<(), SecondaryStorageError> {
        let mut store = self.store.lock().unwrap();
        let expires_at = ttl.map(|secs| std::time::Instant::now() + std::time::Duration::from_secs(secs));
        store.insert(
            key.to_string(),
            MemoryEntry {
                value: value.to_string(),
                expires_at,
            },
        );
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), SecondaryStorageError> {
        let mut store = self.store.lock().unwrap();
        store.remove(key);
        Ok(())
    }
}

/// In-memory rate limit storage.
#[derive(Debug, Default)]
pub struct MemoryRateLimitStorage {
    store: std::sync::Mutex<std::collections::HashMap<String, MemoryRateLimitEntry>>,
}

#[derive(Debug, Clone)]
struct MemoryRateLimitEntry {
    data: RateLimitData,
    expires_at: u64, // millis since epoch
}

impl MemoryRateLimitStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RateLimitStorage for MemoryRateLimitStorage {
    async fn get(&self, key: &str) -> Option<RateLimitData> {
        let store = self.store.lock().unwrap();
        let entry = store.get(key)?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        if now_ms >= entry.expires_at {
            return None;
        }
        Some(entry.data.clone())
    }

    async fn set(&self, key: &str, value: RateLimitData, _update: bool) {
        let mut store = self.store.lock().unwrap();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        // Default TTL: 60 seconds for rate limit entries
        let expires_at = now_ms + 60_000;
        store.insert(
            key.to_string(),
            MemoryRateLimitEntry {
                data: value,
                expires_at,
            },
        );
    }
}

/// Wrap a `SecondaryStorage` implementation to provide `RateLimitStorage`.
///
/// Maps to TS `getRateLimitStorage` when `storage === "secondary-storage"`.
#[derive(Debug)]
pub struct SecondaryStorageRateLimitAdapter {
    inner: std::sync::Arc<dyn SecondaryStorage>,
    window: u64,
}

impl SecondaryStorageRateLimitAdapter {
    pub fn new(storage: std::sync::Arc<dyn SecondaryStorage>, window: u64) -> Self {
        Self {
            inner: storage,
            window,
        }
    }
}

#[async_trait]
impl RateLimitStorage for SecondaryStorageRateLimitAdapter {
    async fn get(&self, key: &str) -> Option<RateLimitData> {
        let value = self.inner.get(key).await.ok()??;
        serde_json::from_str(&value).ok()
    }

    async fn set(&self, key: &str, value: RateLimitData, _update: bool) {
        if let Ok(json) = serde_json::to_string(&value) {
            let _ = self.inner.set(key, &json, Some(self.window)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_secondary_storage_get_set() {
        let storage = MemorySecondaryStorage::new();
        storage.set("key1", "value1", None).await.unwrap();
        let val = storage.get("key1").await.unwrap();
        assert_eq!(val, Some("value1".to_string()));
    }

    #[tokio::test]
    async fn test_memory_secondary_storage_delete() {
        let storage = MemorySecondaryStorage::new();
        storage.set("key1", "value1", None).await.unwrap();
        storage.delete("key1").await.unwrap();
        let val = storage.get("key1").await.unwrap();
        assert_eq!(val, None);
    }

    #[tokio::test]
    async fn test_memory_secondary_storage_missing_key() {
        let storage = MemorySecondaryStorage::new();
        let val = storage.get("nonexistent").await.unwrap();
        assert_eq!(val, None);
    }

    #[tokio::test]
    async fn test_memory_secondary_storage_overwrite() {
        let storage = MemorySecondaryStorage::new();
        storage.set("k", "v1", None).await.unwrap();
        storage.set("k", "v2", None).await.unwrap();
        let val = storage.get("k").await.unwrap();
        assert_eq!(val, Some("v2".to_string()));
    }

    #[tokio::test]
    async fn test_memory_rate_limit_storage() {
        let store = MemoryRateLimitStorage::new();
        let data = RateLimitData {
            key: "127.0.0.1:/sign-in".into(),
            count: 1,
            last_request: 1000,
        };
        store.set("test-key", data.clone(), false).await;
        let fetched = store.get("test-key").await;
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().count, 1);
    }

    #[tokio::test]
    async fn test_secondary_storage_rate_limit_adapter() {
        let storage = std::sync::Arc::new(MemorySecondaryStorage::new());
        let adapter = SecondaryStorageRateLimitAdapter::new(storage, 60);
        let data = RateLimitData {
            key: "test".into(),
            count: 5,
            last_request: 2000,
        };
        adapter.set("rl:test", data, false).await;
        let fetched = adapter.get("rl:test").await;
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().count, 5);
    }
}
