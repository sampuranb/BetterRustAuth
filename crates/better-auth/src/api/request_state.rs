// Request-scoped state — maps to packages/core/src/context/request-state.ts
//
// In TS, this uses `AsyncLocalStorage` to store per-request state as a WeakMap.
// In Rust, we use tokio task-local storage or pass state directly via request
// extensions. Since Axum passes request state through extractors, we implement
// this as a type-safe store that can be embedded in the request extensions.

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A type-erased store for request-scoped state.
///
/// This is the Rust equivalent of the TS `RequestStateWeakMap`.
/// Each request gets its own `RequestStateStore`, which handlers and hooks
/// can read from and write to during request processing.
///
/// Thread-safe via `Mutex` for use across async tasks within one request.
#[derive(Debug, Clone, Default)]
pub struct RequestStateStore {
    inner: Arc<Mutex<HashMap<TypeId, Box<dyn Any + Send + Sync>>>>,
}

impl RequestStateStore {
    /// Create a new empty request state store.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get a value from the store by type.
    ///
    /// Returns `None` if no value of that type has been set.
    pub fn get<T: Any + Send + Sync + Clone>(&self) -> Option<T> {
        let guard = self.inner.lock().ok()?;
        guard
            .get(&TypeId::of::<T>())
            .and_then(|v| v.downcast_ref::<T>())
            .cloned()
    }

    /// Set a value in the store by type.
    ///
    /// Overwrites any previous value of the same type.
    pub fn set<T: Any + Send + Sync>(&self, value: T) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.insert(TypeId::of::<T>(), Box::new(value));
        }
    }

    /// Check if the store contains a value of the given type.
    pub fn has<T: Any + Send + Sync>(&self) -> bool {
        self.inner
            .lock()
            .map(|guard| guard.contains_key(&TypeId::of::<T>()))
            .unwrap_or(false)
    }

    /// Remove a value from the store. Returns the removed value if it existed.
    pub fn remove<T: Any + Send + Sync + Clone>(&self) -> Option<T> {
        let mut guard = self.inner.lock().ok()?;
        guard
            .remove(&TypeId::of::<T>())
            .and_then(|v| v.downcast::<T>().ok())
            .map(|v| *v)
    }
}

/// A typed request state handle, analogous to TS `defineRequestState`.
///
/// This allows defining named request-scoped state with a default factory.
/// Lazy initialization happens on first `get()`.
///
/// # Example
/// ```ignore
/// let oauth_state: RequestState<Option<OAuthData>> = RequestState::new(|| None);
///
/// // In a handler:
/// let data = oauth_state.get(&store);
/// oauth_state.set(&store, Some(my_data));
/// ```
pub struct RequestState<T> {
    type_id: TypeId,
    init_fn: Box<dyn Fn() -> T + Send + Sync>,
}

impl<T: Any + Send + Sync + Clone> RequestState<T> {
    /// Define a new request state with a default factory.
    ///
    /// Maps to TS `defineRequestState(initFn)`.
    pub fn new<F: Fn() -> T + Send + Sync + 'static>(init_fn: F) -> Self {
        Self {
            type_id: TypeId::of::<T>(),
            init_fn: Box::new(init_fn),
        }
    }

    /// Get the current value, initializing with the factory if not yet set.
    pub fn get(&self, store: &RequestStateStore) -> T {
        if let Some(value) = store.get::<T>() {
            return value;
        }
        let initial = (self.init_fn)();
        store.set(initial.clone());
        initial
    }

    /// Set the value in the store.
    pub fn set(&self, store: &RequestStateStore, value: T) {
        store.set(value);
    }
}

impl<T> std::fmt::Debug for RequestState<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestState")
            .field("type_id", &self.type_id)
            .finish()
    }
}

// ─── Request-Scoped OAuth State ─────────────────────────────────

/// OAuth state that can be stored per-request.
///
/// Maps to `api/state/oauth.ts` — `getOAuthState` / `setOAuthState`.
#[derive(Debug, Clone, Default)]
pub struct OAuthRequestState {
    pub callback_url: Option<String>,
    pub code_verifier: Option<String>,
    pub error_url: Option<String>,
    pub new_user_url: Option<String>,
    pub link: Option<LinkData>,
    pub expires_at: Option<i64>,
    pub request_sign_up: bool,
}

/// Link data for account linking flows.
#[derive(Debug, Clone)]
pub struct LinkData {
    pub email: String,
    pub user_id: String,
}

// ─── Session Refresh State ──────────────────────────────────────

/// Whether to skip session refresh for this request.
///
/// Maps to `api/state/should-session-refresh.ts`.
#[derive(Debug, Clone)]
pub struct ShouldSkipSessionRefresh(pub bool);

impl Default for ShouldSkipSessionRefresh {
    fn default() -> Self {
        Self(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_state_store_basic() {
        let store = RequestStateStore::new();

        // Initially empty
        assert!(!store.has::<String>());
        assert!(store.get::<String>().is_none());

        // Set and get
        store.set("hello".to_string());
        assert!(store.has::<String>());
        assert_eq!(store.get::<String>().unwrap(), "hello");

        // Different types don't interfere
        store.set(42u32);
        assert_eq!(store.get::<u32>().unwrap(), 42);
        assert_eq!(store.get::<String>().unwrap(), "hello");
    }

    #[test]
    fn test_request_state_store_overwrite() {
        let store = RequestStateStore::new();
        store.set("first".to_string());
        store.set("second".to_string());
        assert_eq!(store.get::<String>().unwrap(), "second");
    }

    #[test]
    fn test_request_state_store_remove() {
        let store = RequestStateStore::new();
        store.set("value".to_string());
        let removed = store.remove::<String>();
        assert_eq!(removed.unwrap(), "value");
        assert!(!store.has::<String>());
    }

    #[test]
    fn test_request_state_lazy_init() {
        let state: RequestState<String> = RequestState::new(|| "default".to_string());
        let store = RequestStateStore::new();

        // First access initializes
        let val = state.get(&store);
        assert_eq!(val, "default");

        // Setting overrides
        state.set(&store, "custom".to_string());
        let val = state.get(&store);
        assert_eq!(val, "custom");
    }

    #[test]
    fn test_oauth_request_state() {
        let store = RequestStateStore::new();

        let oauth = OAuthRequestState {
            callback_url: Some("https://example.com/cb".into()),
            code_verifier: Some("abc123".into()),
            request_sign_up: true,
            ..Default::default()
        };
        store.set(oauth.clone());

        let retrieved = store.get::<OAuthRequestState>().unwrap();
        assert_eq!(retrieved.callback_url.as_deref(), Some("https://example.com/cb"));
        assert!(retrieved.request_sign_up);
    }

    #[test]
    fn test_should_skip_session_refresh() {
        let store = RequestStateStore::new();

        // Default is false
        let state: RequestState<ShouldSkipSessionRefresh> =
            RequestState::new(ShouldSkipSessionRefresh::default);
        let val = state.get(&store);
        assert!(!val.0);

        // Set to true
        state.set(&store, ShouldSkipSessionRefresh(true));
        let val = state.get(&store);
        assert!(val.0);
    }

    #[test]
    fn test_store_clone_shares_data() {
        let store = RequestStateStore::new();
        let store2 = store.clone();

        store.set("shared".to_string());
        assert_eq!(store2.get::<String>().unwrap(), "shared");
    }
}
