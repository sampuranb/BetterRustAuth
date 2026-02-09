//! Session management — caching, auto-refresh, and cross-thread sync.
//!
//! Maps to the TS `session-atom.ts`, `session-refresh.ts`, `broadcast-channel.ts`,
//! `focus-manager.ts`, and `online-manager.ts` from the client SDK.
//!
//! ## TS Parity
//! - `SessionAtom` → `SessionCache` with freshness tracking
//! - `createSessionRefreshManager` → `SessionRefreshManager` with polling
//! - `BroadcastChannel` → `tokio::sync::watch` for cross-task sync
//! - `FocusManager` / `OnlineManager` → callback-based event hooks

use std::sync::Arc;
use std::time::Instant;
use tokio::sync::watch;

use crate::types::SessionData;

/// In-memory session cache with freshness tracking.
///
/// The cache is shared across all methods via `Arc<RwLock<SessionCache>>`.
#[derive(Debug, Clone)]
pub struct SessionCache {
    /// Cached session data (user + session).
    pub(crate) data: Option<SessionData>,
    /// When the session was last fetched from the server.
    last_fetched: Option<Instant>,
    /// When the last session request was made (for rate limiting).
    last_request: Option<Instant>,
    /// Maximum age in seconds before the cache is considered stale.
    max_age_secs: u64,
}

/// Rate limit: don't refetch if a session request was made within this many seconds.
/// Maps to TS `FOCUS_REFETCH_RATE_LIMIT_SECONDS`.
const FOCUS_REFETCH_RATE_LIMIT_SECONDS: u64 = 5;

impl SessionCache {
    /// Create a new empty session cache.
    pub fn new(max_age_secs: u64) -> Self {
        Self {
            data: None,
            last_fetched: None,
            last_request: None,
            max_age_secs,
        }
    }

    /// Store a session in the cache, updating the freshness timestamp.
    pub fn set(&mut self, data: SessionData) {
        self.data = Some(data);
        self.last_fetched = Some(Instant::now());
    }

    /// Get the cached session if it's still fresh.
    pub fn get_if_fresh(&self) -> Option<&SessionData> {
        let data = self.data.as_ref()?;
        let last = self.last_fetched?;
        if last.elapsed().as_secs() < self.max_age_secs {
            Some(data)
        } else {
            None
        }
    }

    /// Clear the cache entirely.
    pub fn clear(&mut self) {
        self.data = None;
        self.last_fetched = None;
    }

    /// Mark the cache as stale without removing the data.
    pub fn invalidate(&mut self) {
        self.last_fetched = None;
    }

    /// Check if the cache has any data (fresh or stale).
    pub fn has_data(&self) -> bool {
        self.data.is_some()
    }

    /// Check if the cache is fresh.
    pub fn is_fresh(&self) -> bool {
        self.get_if_fresh().is_some()
    }

    /// Check if a refetch is rate-limited (too recent).
    /// Maps to TS `FOCUS_REFETCH_RATE_LIMIT_SECONDS` check.
    pub fn is_rate_limited(&self) -> bool {
        if let Some(last) = self.last_request {
            last.elapsed().as_secs() < FOCUS_REFETCH_RATE_LIMIT_SECONDS
        } else {
            false
        }
    }

    /// Record that a session request was made (for rate limiting).
    pub fn mark_request(&mut self) {
        self.last_request = Some(Instant::now());
    }
}

/// Configuration for the session refresh manager.
///
/// Maps to TS `SessionRefreshOptions` and related config.
#[derive(Debug, Clone)]
pub struct SessionRefreshConfig {
    /// If > 0, poll for session freshness every N seconds.
    /// Maps to TS `refetchInterval`.
    pub refetch_interval_secs: u64,
    /// Whether to refetch session on window/app focus.
    /// Maps to TS `refetchOnWindowFocus`.
    pub refetch_on_focus: bool,
    /// Whether to refetch when coming back online.
    /// Maps to TS `refetchWhenOffline`.
    pub refetch_when_offline: bool,
}

impl Default for SessionRefreshConfig {
    fn default() -> Self {
        Self {
            refetch_interval_secs: 0,
            refetch_on_focus: true,
            refetch_when_offline: false,
        }
    }
}

/// Session signal broadcaster for cross-task session sync.
///
/// Maps to TS `BroadcastChannel` for cross-tab session synchronization.
/// In Rust, uses `tokio::sync::watch` for cross-task communication.
#[derive(Clone)]
pub struct SessionBroadcast {
    sender: Arc<watch::Sender<u64>>,
    receiver: watch::Receiver<u64>,
}

impl SessionBroadcast {
    /// Create a new session broadcast channel.
    pub fn new() -> Self {
        let (sender, receiver) = watch::channel(0u64);
        Self {
            sender: Arc::new(sender),
            receiver,
        }
    }

    /// Signal that the session has been updated.
    /// All receivers will be notified.
    pub fn notify(&self) {
        let current = *self.sender.borrow();
        let _ = self.sender.send(current.wrapping_add(1));
    }

    /// Wait for the next session update signal.
    /// Returns when a new signal is received.
    pub async fn wait_for_update(&mut self) {
        let _ = self.receiver.changed().await;
    }

    /// Get a new receiver for this broadcast channel.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.receiver.clone()
    }
}

impl Default for SessionBroadcast {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SessionBroadcast {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionBroadcast")
            .field("version", &*self.sender.borrow())
            .finish()
    }
}

/// Event types that can trigger a session refetch.
/// Maps to TS `triggerRefetch` event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefetchEvent {
    /// Periodic polling timer fired.
    Poll,
    /// App/window gained focus (visibility change).
    Focus,
    /// Cross-task broadcast received.
    Broadcast,
    /// Network came back online.
    Online,
    /// Manual invalidation.
    Manual,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_cache_basics() {
        let cache = SessionCache::new(60);
        assert!(cache.get_if_fresh().is_none());

        let mut cache = cache;
        cache.set(SessionData {
            user: serde_json::json!({"id": "u1", "name": "Alice", "email": "alice@example.com"}),
            session: serde_json::json!({"id": "s1", "token": "tok", "userId": "u1"}),
        });

        assert!(cache.get_if_fresh().is_some());
        let cached = cache.get_if_fresh().unwrap();
        assert_eq!(cached.user["name"], "Alice");

        cache.clear();
        assert!(cache.get_if_fresh().is_none());
    }

    #[test]
    fn test_session_cache_invalidate() {
        let mut cache = SessionCache::new(60);
        cache.set(SessionData {
            user: serde_json::json!({"id": "u1"}),
            session: serde_json::json!({"id": "s1"}),
        });
        assert!(cache.get_if_fresh().is_some());
        cache.invalidate();
        assert!(cache.get_if_fresh().is_none());
        assert!(cache.data.is_some());
    }

    #[test]
    fn test_session_cache_expiry() {
        let mut cache = SessionCache::new(0);
        cache.set(SessionData {
            user: serde_json::json!({"id": "u1"}),
            session: serde_json::json!({"id": "s1"}),
        });
        assert!(cache.get_if_fresh().is_none());
    }

    #[test]
    fn test_rate_limiting() {
        let mut cache = SessionCache::new(60);
        assert!(!cache.is_rate_limited());
        cache.mark_request();
        assert!(cache.is_rate_limited());
    }

    #[tokio::test]
    async fn test_session_broadcast() {
        let broadcast = SessionBroadcast::new();
        let mut rx = broadcast.subscribe();

        broadcast.notify();
        let _ = rx.changed().await;
        assert_eq!(*rx.borrow(), 1);

        broadcast.notify();
        let _ = rx.changed().await;
        assert_eq!(*rx.borrow(), 2);
    }

    #[test]
    fn test_refresh_config_defaults() {
        let config = SessionRefreshConfig::default();
        assert_eq!(config.refetch_interval_secs, 0);
        assert!(config.refetch_on_focus);
        assert!(!config.refetch_when_offline);
    }
}
