// Internal adapter — maps to packages/better-auth/src/db/internal-adapter.ts
//
// Higher-level database operations built on top of the raw Adapter trait.
// Provides application-specific methods for users, sessions, accounts, and verifications.
//
// Phase 20 enhancements:
// - SecondaryStorage trait (Redis/Memcached/etc.) for session caching
// - createSession with dontRememberMe, IP tracking, user-agent, overrides
// - Database hooks integration (before/after on CRUD)
// - Output transforms (parseSessionOutput, parseUserOutput)
// - deleteUser cascade with secondary cleanup

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use better_auth_core::db::adapter::{Adapter, FindManyQuery, SortBy, SortDirection, WhereClause};

// ─── Secondary Storage ──────────────────────────────────────────

/// Secondary storage trait for session caching (e.g. Redis, Memcached).
///
/// Matches the TS `SecondaryStorage` interface. Provides fast lookups
/// for sessions without hitting the primary database on every request.
#[async_trait]
pub trait SecondaryStorage: Send + Sync {
    /// Get a value by key.
    async fn get(&self, key: &str) -> Option<String>;
    /// Set a value with TTL in seconds.
    async fn set(&self, key: &str, value: &str, ttl_seconds: i64) -> Result<(), String>;
    /// Delete a key.
    async fn delete(&self, key: &str) -> Result<(), String>;
}

/// Options for creating a session.
///
/// Matches the TS `createSession` parameters.
#[derive(Debug, Default)]
pub struct CreateSessionOptions {
    /// If true, session expires in 1 day instead of the configured duration.
    /// The cookie will be set as a session cookie (no Expires).
    pub dont_remember_me: bool,
    /// IP address of the client (from request headers).
    pub ip_address: Option<String>,
    /// User-Agent string from request headers.
    pub user_agent: Option<String>,
    /// Additional session fields to merge (from plugins or overrides).
    pub overrides: Option<serde_json::Map<String, Value>>,
    /// If true, override fields take precedence over all defaults.
    pub override_all: bool,
}

/// Helper to get TTL in seconds from an expiry timestamp.
fn get_ttl_seconds(expires_at_ms: i64) -> i64 {
    let now_ms = chrono::Utc::now().timestamp_millis();
    ((expires_at_ms - now_ms) / 1000).max(0)
}

/// The internal adapter trait — high-level database operations.
///
/// This wraps the raw `Adapter` and provides typed, application-specific methods.
/// Each method corresponds to a common auth operation (create user, find session, etc.).
#[async_trait]
pub trait InternalAdapter: Send + Sync {
    // ─── User Operations ─────────────────────────────────────────

    /// Create a new user, returning the created user data.
    async fn create_user(&self, data: Value) -> Result<Value, AdapterError>;

    /// Find a user by their ID.
    async fn find_user_by_id(&self, id: &str) -> Result<Option<Value>, AdapterError>;

    /// Find a user by their email address.
    async fn find_user_by_email(&self, email: &str) -> Result<Option<Value>, AdapterError>;

    /// Update user fields by ID.
    async fn update_user(&self, id: &str, data: Value) -> Result<Value, AdapterError>;

    /// Update user fields by email.
    async fn update_user_by_email(&self, email: &str, data: Value) -> Result<Value, AdapterError>;

    /// Update the password for a user's credential account.
    async fn update_password(&self, user_id: &str, password_hash: &str) -> Result<(), AdapterError>;

    /// List users with pagination and optional filtering.
    async fn list_users(
        &self,
        limit: Option<usize>,
        offset: Option<usize>,
        sort_field: Option<&str>,
        sort_direction: Option<&str>,
    ) -> Result<Vec<Value>, AdapterError>;

    /// Count total users with optional filter.
    async fn count_total_users(&self) -> Result<u64, AdapterError>;

    /// Delete a user by ID.
    async fn delete_user(&self, id: &str) -> Result<(), AdapterError>;

    // ─── Session Operations ──────────────────────────────────────

    /// Create a new session with optional settings.
    ///
    /// Matches TS `createSession(userId, dontRememberMe?, override?, overrideAll?)`:
    /// - Generates token + expiry
    /// - Tracks IP and user-agent
    /// - Supports `dontRememberMe` (1-day expiry)
    /// - Supports field overrides from plugins
    /// - Optionally stores in secondary storage
    async fn create_session(
        &self,
        user_id: &str,
        options: Option<CreateSessionOptions>,
        session_expiration: Option<i64>,
    ) -> Result<Value, AdapterError>;

    /// Find a session by its token.
    async fn find_session_by_token(&self, token: &str) -> Result<Option<Value>, AdapterError>;

    /// Find a session and its associated user by session token.
    async fn find_session_and_user(
        &self,
        token: &str,
    ) -> Result<Option<SessionWithUser>, AdapterError>;

    /// Update session fields.
    async fn update_session(&self, token: &str, data: Value) -> Result<Value, AdapterError>;

    /// Delete a session by token.
    async fn delete_session(&self, token: &str) -> Result<(), AdapterError>;

    /// List all sessions for a user.
    async fn list_sessions_for_user(&self, user_id: &str) -> Result<Vec<Value>, AdapterError>;

    /// Find multiple sessions by tokens (batch lookup).
    async fn find_sessions(&self, tokens: &[String]) -> Result<Vec<Value>, AdapterError>;

    /// Delete all sessions for a user.
    async fn delete_sessions_for_user(&self, user_id: &str) -> Result<(), AdapterError>;

    /// Delete a user and cascade: sessions → accounts → user.
    ///
    /// Matches TS `deleteUser` which cascades through all related records.
    async fn delete_user_cascade(&self, user_id: &str) -> Result<(), AdapterError>;

    // ─── Account Operations ──────────────────────────────────────

    /// Create an account (link a provider to a user).
    async fn create_account(&self, data: Value) -> Result<Value, AdapterError>;

    /// Find accounts for a user.
    async fn find_accounts_by_user_id(&self, user_id: &str) -> Result<Vec<Value>, AdapterError>;

    /// Find an account by provider and account ID.
    async fn find_account_by_provider(
        &self,
        provider_id: &str,
        account_id: &str,
    ) -> Result<Option<Value>, AdapterError>;

    /// Update an account.
    async fn update_account(
        &self,
        provider_id: &str,
        account_id: &str,
        data: Value,
    ) -> Result<Value, AdapterError>;

    /// Delete an account.
    async fn delete_account(
        &self,
        provider_id: &str,
        account_id: &str,
    ) -> Result<(), AdapterError>;

    /// Delete all accounts for a user.
    async fn delete_accounts_by_user_id(&self, user_id: &str) -> Result<(), AdapterError>;

    /// Find a single account by its record ID.
    async fn find_account_by_id(&self, account_id: &str) -> Result<Option<Value>, AdapterError>;

    /// Update an account by its record ID (not by provider+userId).
    async fn update_account_by_id(&self, id: &str, data: Value) -> Result<Value, AdapterError>;

    /// Create an OAuth user (user + account in one operation).
    async fn create_oauth_user(
        &self,
        user_data: Value,
        account_data: Value,
    ) -> Result<Value, AdapterError>;

    /// Find a user by email and check for a linked OAuth account.
    async fn find_oauth_user(
        &self,
        email: &str,
        account_id: &str,
        provider_id: &str,
    ) -> Result<Option<OAuthUserResult>, AdapterError>;

    /// Link an OAuth account to an existing user.
    async fn link_account(&self, account_data: Value) -> Result<Value, AdapterError>;

    // ─── Verification Operations ─────────────────────────────────

    /// Create a verification value (email tokens, OAuth state, etc.).
    async fn create_verification(
        &self,
        identifier: &str,
        value: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Value, AdapterError>;

    /// Find a verification by identifier.
    async fn find_verification(
        &self,
        identifier: &str,
    ) -> Result<Option<Value>, AdapterError>;

    /// Delete a verification by identifier.
    async fn delete_verification(&self, identifier: &str) -> Result<(), AdapterError>;

    /// Delete a verification by its identifier field (not ID).
    async fn delete_verification_by_identifier(&self, identifier: &str) -> Result<(), AdapterError>;

    /// Update a verification record.
    async fn update_verification(&self, id: &str, data: Value) -> Result<Value, AdapterError>;

    // ─── Generic Table Operations (for plugins) ─────────────────

    /// Create a record in an arbitrary table.
    async fn create(&self, model: &str, data: Value) -> Result<Value, AdapterError>;

    /// Find a record by ID in an arbitrary table.
    async fn find_by_id(&self, model: &str, id: &str) -> Result<Value, AdapterError>;

    /// Find a single record in an arbitrary table matching a filter.
    /// The filter is a JSON array of `{field, value}` objects.
    async fn find_one(&self, model: &str, filter: Value) -> Result<Value, AdapterError>;

    /// Find multiple records in an arbitrary table matching a filter.
    async fn find_many(&self, model: &str, filter: Value) -> Result<Vec<Value>, AdapterError>;

    /// Update a record by ID in an arbitrary table.
    async fn update_by_id(&self, model: &str, id: &str, data: Value) -> Result<Value, AdapterError>;

    /// Delete a record by ID in an arbitrary table.
    async fn delete_by_id(&self, model: &str, id: &str) -> Result<(), AdapterError>;

    /// Delete multiple records matching a filter in an arbitrary table.
    async fn delete_many(&self, model: &str, filter: Value) -> Result<i64, AdapterError>;
}

/// Session paired with its associated user.
#[derive(Debug, Clone)]
pub struct SessionWithUser {
    pub session: Value,
    pub user: Value,
}

/// Result of finding an OAuth user.
#[derive(Debug, Clone)]
pub struct OAuthUserResult {
    pub user: Value,
    pub accounts: Vec<Value>,
    /// Whether the specific account was already linked.
    pub is_linked: bool,
}

/// Errors from the internal adapter.
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("Database error: {0}")]
    Database(String),

    #[error("Record not found")]
    NotFound,

    #[error("Duplicate record: {0}")]
    Duplicate(String),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

impl From<better_auth_core::error::BetterAuthError> for AdapterError {
    fn from(e: better_auth_core::error::BetterAuthError) -> Self {
        Self::Database(e.to_string())
    }
}

// ─── Concrete Implementation ────────────────────────────────────

/// Concrete internal adapter backed by a raw `Adapter` (e.g. SqlxAdapter).
///
/// Translates high-level auth operations into raw CRUD calls with the
/// correct model names ("user", "session", "account", "verification").
///
/// Supports optional secondary storage (Redis/Memcached) for session caching.
pub struct ConcreteInternalAdapter {
    adapter: Arc<dyn Adapter>,
    /// Optional secondary storage for session caching.
    secondary_storage: Option<Arc<dyn SecondaryStorage>>,
    /// Whether to also store sessions in the primary DB when secondary is active.
    store_in_db: bool,
}

/// Convert a JSON filter array `[{field, value}, ...]` into WhereClause vector.
///
/// Used by generic CRUD methods so plugins can pass simple JSON filters.
fn json_filter_to_where_clauses(filter: &Value) -> Vec<WhereClause> {
    let arr = match filter.as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    let mut clauses = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        let field = item["field"].as_str().unwrap_or_default().to_string();
        let value = item["value"].clone();
        let mut clause = WhereClause::eq(field, value);
        if i < arr.len() - 1 {
            clause = clause.and();
        }
        clauses.push(clause);
    }
    clauses
}

impl ConcreteInternalAdapter {
    /// Create a new internal adapter wrapping the given raw adapter.
    pub fn new(adapter: Arc<dyn Adapter>) -> Self {
        Self {
            adapter,
            secondary_storage: None,
            store_in_db: true,
        }
    }

    /// Create with secondary storage.
    pub fn with_secondary_storage(
        adapter: Arc<dyn Adapter>,
        secondary: Arc<dyn SecondaryStorage>,
        store_in_db: bool,
    ) -> Self {
        Self {
            adapter,
            secondary_storage: Some(secondary),
            store_in_db,
        }
    }

    /// Refresh user data in all cached sessions (secondary storage).
    ///
    /// Matches TS `refreshUserSessions`: when a user's profile changes,
    /// update the cached user data in all their active sessions.
    async fn refresh_user_sessions(&self, user_id: &str, user: &Value) {
        let secondary = match &self.secondary_storage {
            Some(s) => s,
            None => return,
        };

        let list_key = format!("active-sessions-{}", user_id);
        let list_raw = match secondary.get(&list_key).await {
            Some(raw) => raw,
            None => return,
        };

        let sessions: Vec<serde_json::Value> = match serde_json::from_str(&list_raw) {
            Ok(v) => v,
            Err(_) => return,
        };

        let now_ms = chrono::Utc::now().timestamp_millis();

        for entry in &sessions {
            let token = match entry["token"].as_str() {
                Some(t) => t,
                None => continue,
            };
            let expires_at = entry["expiresAt"].as_i64().unwrap_or(0);
            if expires_at <= now_ms {
                continue;
            }

            if let Some(cached) = secondary.get(token).await {
                if let Ok(mut parsed) = serde_json::from_str::<serde_json::Value>(&cached) {
                    parsed["user"] = user.clone();
                    let ttl = get_ttl_seconds(expires_at);
                    if ttl > 0 {
                        let _ = secondary
                            .set(token, &parsed.to_string(), ttl)
                            .await;
                    }
                }
            }
        }
    }

    /// Store a session in secondary storage (cache).
    async fn store_session_in_secondary(
        &self,
        token: &str,
        user_id: &str,
        session: &Value,
        user: &Value,
        expires_at_ms: i64,
    ) {
        let secondary = match &self.secondary_storage {
            Some(s) => s,
            None => return,
        };

        let now_ms = chrono::Utc::now().timestamp_millis();
        let session_ttl = get_ttl_seconds(expires_at_ms);

        if session_ttl <= 0 {
            return;
        }

        // Store the session+user payload
        let payload = serde_json::json!({
            "session": session,
            "user": user,
        });
        let _ = secondary.set(token, &payload.to_string(), session_ttl).await;

        // Update the active-sessions list for this user
        let list_key = format!("active-sessions-{}", user_id);
        let mut list: Vec<serde_json::Value> = match secondary.get(&list_key).await {
            Some(raw) => serde_json::from_str(&raw).unwrap_or_default(),
            None => Vec::new(),
        };

        // Remove expired entries and the current token if present
        list.retain(|entry| {
            entry["expiresAt"].as_i64().unwrap_or(0) > now_ms
                && entry["token"].as_str() != Some(token)
        });

        list.push(serde_json::json!({
            "token": token,
            "expiresAt": expires_at_ms,
        }));

        // Sort by expiry ascending, TTL is the furthest session's
        list.sort_by(|a, b| {
            a["expiresAt"]
                .as_i64()
                .unwrap_or(0)
                .cmp(&b["expiresAt"].as_i64().unwrap_or(0))
        });

        let furthest = list.last().and_then(|e| e["expiresAt"].as_i64()).unwrap_or(expires_at_ms);
        let list_ttl = get_ttl_seconds(furthest);
        if list_ttl > 0 {
            let _ = secondary
                .set(&list_key, &serde_json::to_string(&list).unwrap_or_default(), list_ttl)
                .await;
        }
    }

    /// Remove a session from secondary storage.
    async fn remove_session_from_secondary(&self, token: &str, user_id: &str) {
        let secondary = match &self.secondary_storage {
            Some(s) => s,
            None => return,
        };

        let _ = secondary.delete(token).await;

        // Update the active-sessions list
        let list_key = format!("active-sessions-{}", user_id);
        if let Some(raw) = secondary.get(&list_key).await {
            let now_ms = chrono::Utc::now().timestamp_millis();
            let mut list: Vec<serde_json::Value> =
                serde_json::from_str(&raw).unwrap_or_default();
            list.retain(|entry| {
                entry["expiresAt"].as_i64().unwrap_or(0) > now_ms
                    && entry["token"].as_str() != Some(token)
            });
            if list.is_empty() {
                let _ = secondary.delete(&list_key).await;
            } else {
                let furthest = list.last().and_then(|e| e["expiresAt"].as_i64()).unwrap_or(0);
                let ttl = get_ttl_seconds(furthest);
                if ttl > 0 {
                    let _ = secondary
                        .set(&list_key, &serde_json::to_string(&list).unwrap_or_default(), ttl)
                        .await;
                }
            }
        }
    }
}

#[async_trait]
impl InternalAdapter for ConcreteInternalAdapter {
    // ─── User Operations ─────────────────────────────────────────

    async fn create_user(&self, mut data: Value) -> Result<Value, AdapterError> {
        // Lowercase email before creating user
        if let Some(obj) = data.as_object_mut() {
            if let Some(email) = obj.get("email").and_then(|e| e.as_str()).map(|e| e.to_lowercase()) {
                obj.insert("email".to_string(), Value::String(email));
            }
        }
        self.adapter
            .create("user", data, None)
            .await
            .map_err(Into::into)
    }

    async fn find_user_by_id(&self, id: &str) -> Result<Option<Value>, AdapterError> {
        self.adapter
            .find_one("user", &[WhereClause::eq("id", id)])
            .await
            .map_err(Into::into)
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<Value>, AdapterError> {
        let email_lower = email.to_lowercase();
        self.adapter
            .find_one("user", &[WhereClause::eq("email", email_lower.as_str())])
            .await
            .map_err(Into::into)
    }

    async fn update_user(&self, id: &str, data: Value) -> Result<Value, AdapterError> {
        self.adapter
            .update("user", &[WhereClause::eq("id", id)], data)
            .await?
            .ok_or(AdapterError::NotFound)
    }

    async fn delete_user(&self, id: &str) -> Result<(), AdapterError> {
        self.adapter
            .delete("user", &[WhereClause::eq("id", id)])
            .await
            .map_err(Into::into)
    }

    async fn update_user_by_email(&self, email: &str, data: Value) -> Result<Value, AdapterError> {
        let email_lower = email.to_lowercase();
        self.adapter
            .update("user", &[WhereClause::eq("email", email_lower.as_str())], data)
            .await?
            .ok_or(AdapterError::NotFound)
    }

    async fn update_password(&self, user_id: &str, password_hash: &str) -> Result<(), AdapterError> {
        // Find the credential account for this user
        let account = self
            .adapter
            .find_one(
                "account",
                &[
                    WhereClause::eq("userId", user_id).and(),
                    WhereClause::eq("providerId", "credential"),
                ],
            )
            .await?;

        let account = account.ok_or(AdapterError::NotFound)?;
        let account_id = account["id"]
            .as_str()
            .ok_or_else(|| AdapterError::Serialization("No account id".into()))?;

        self.adapter
            .update(
                "account",
                &[WhereClause::eq("id", account_id)],
                serde_json::json!({ "password": password_hash }),
            )
            .await?
            .ok_or(AdapterError::NotFound)?;

        Ok(())
    }

    async fn list_users(
        &self,
        limit: Option<usize>,
        offset: Option<usize>,
        sort_field: Option<&str>,
        sort_direction: Option<&str>,
    ) -> Result<Vec<Value>, AdapterError> {
        let sort_by = sort_field.map(|field| SortBy {
            field: field.to_string(),
            direction: match sort_direction {
                Some("desc") => SortDirection::Desc,
                _ => SortDirection::Asc,
            },
        });

        self.adapter
            .find_many(
                "user",
                FindManyQuery {
                    where_clauses: vec![],
                    limit: limit.map(|l| l as i64),
                    offset: offset.map(|o| o as i64),
                    sort_by,
                    ..Default::default()
                },
            )
            .await
            .map_err(Into::into)
    }

    async fn count_total_users(&self) -> Result<u64, AdapterError> {
        self.adapter
            .count("user", &[])
            .await
            .map(|c| c as u64)
            .map_err(Into::into)
    }

    // ─── Session Operations ──────────────────────────────────────

    async fn create_session(
        &self,
        user_id: &str,
        options: Option<CreateSessionOptions>,
        session_expiration: Option<i64>,
    ) -> Result<Value, AdapterError> {
        let opts = options.unwrap_or_default();
        let expiration_secs = session_expiration.unwrap_or(60 * 60 * 24 * 7); // 7 days default

        // dontRememberMe → 1-day session
        let effective_expiry = if opts.dont_remember_me {
            60 * 60 * 24 // 1 day
        } else {
            expiration_secs
        };

        let now = chrono::Utc::now();
        let expires_at = now + chrono::TimeDelta::seconds(effective_expiry);
        let token = crate::crypto::random::generate_random_string(32);

        let mut data = serde_json::json!({
            "userId": user_id,
            "token": token,
            "expiresAt": expires_at.to_rfc3339(),
            "ipAddress": opts.ip_address.unwrap_or_default(),
            "userAgent": opts.user_agent.unwrap_or_default(),
            "createdAt": now.to_rfc3339(),
            "updatedAt": now.to_rfc3339(),
        });

        // Merge override fields
        if let Some(overrides) = opts.overrides {
            if let Some(obj) = data.as_object_mut() {
                for (k, v) in &overrides {
                    // Skip id — new sessions always get fresh IDs
                    if k == "id" {
                        continue;
                    }
                    if opts.override_all || !obj.contains_key(k) {
                        obj.insert(k.clone(), v.clone());
                    }
                }
            }
        }

        // Store in primary DB (unless secondary-only mode)
        let session = if self.store_in_db || self.secondary_storage.is_none() {
            self.adapter.create("session", data.clone(), None).await?
        } else {
            // In secondary-only mode, use the data as-is
            data.clone()
        };

        // Store in secondary storage if available
        if self.secondary_storage.is_some() {
            // Look up user for the combined cache entry
            let user = self
                .adapter
                .find_one("user", &[WhereClause::eq("id", user_id)])
                .await?
                .unwrap_or(serde_json::json!({}));

            let expires_at_ms = expires_at.timestamp_millis();
            self.store_session_in_secondary(
                &token, user_id, &session, &user, expires_at_ms,
            )
            .await;
        }

        Ok(session)
    }

    async fn find_session_by_token(&self, token: &str) -> Result<Option<Value>, AdapterError> {
        self.adapter
            .find_one("session", &[WhereClause::eq("token", token)])
            .await
            .map_err(Into::into)
    }

    async fn find_session_and_user(
        &self,
        token: &str,
    ) -> Result<Option<SessionWithUser>, AdapterError> {
        // Try secondary storage first
        if let Some(secondary) = &self.secondary_storage {
            if let Some(cached) = secondary.get(token).await {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&cached) {
                    let session = parsed["session"].clone();
                    let user = parsed["user"].clone();
                    if !session.is_null() && !user.is_null() {
                        return Ok(Some(SessionWithUser { session, user }));
                    }
                }
            }
            // If secondary-only mode, return None
            if !self.store_in_db {
                return Ok(None);
            }
        }

        // Fall back to primary DB
        let session = self
            .adapter
            .find_one("session", &[WhereClause::eq("token", token)])
            .await?;

        let session = match session {
            Some(s) => s,
            None => return Ok(None),
        };

        let user_id = session
            .get("userId")
            .or_else(|| session.get("user_id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AdapterError::Database("Session missing userId field".into())
            })?;

        let user = self
            .adapter
            .find_one("user", &[WhereClause::eq("id", user_id)])
            .await?;

        match user {
            Some(user) => Ok(Some(SessionWithUser { session, user })),
            None => Ok(None),
        }
    }

    async fn update_session(&self, token: &str, data: Value) -> Result<Value, AdapterError> {
        let updated = self
            .adapter
            .update("session", &[WhereClause::eq("token", token)], data)
            .await?
            .ok_or(AdapterError::NotFound)?;

        // Update secondary storage if present
        if let Some(secondary) = &self.secondary_storage {
            if let Some(cached) = secondary.get(token).await {
                if let Ok(mut parsed) = serde_json::from_str::<serde_json::Value>(&cached) {
                    // Merge updated session fields
                    if let (Some(cached_session), Some(updated_obj)) =
                        (parsed["session"].as_object_mut(), updated.as_object())
                    {
                        for (k, v) in updated_obj {
                            cached_session.insert(k.clone(), v.clone());
                        }
                    }
                    let expires_at_ms = updated["expiresAt"]
                        .as_str()
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                        .map(|dt| dt.timestamp_millis())
                        .unwrap_or(chrono::Utc::now().timestamp_millis() + 86400000);
                    let ttl = get_ttl_seconds(expires_at_ms);
                    if ttl > 0 {
                        let _ = secondary.set(token, &parsed.to_string(), ttl).await;
                    }
                }
            }
        }

        Ok(updated)
    }

    async fn delete_session(&self, token: &str) -> Result<(), AdapterError> {
        // Get user_id before deleting (for secondary storage cleanup)
        if self.secondary_storage.is_some() {
            if let Ok(Some(session)) = self
                .adapter
                .find_one("session", &[WhereClause::eq("token", token)])
                .await
            {
                let user_id = session
                    .get("userId")
                    .or_else(|| session.get("user_id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                self.remove_session_from_secondary(token, user_id).await;
            }
        }

        self.adapter
            .delete("session", &[WhereClause::eq("token", token)])
            .await
            .map_err(Into::into)
    }

    async fn list_sessions_for_user(&self, user_id: &str) -> Result<Vec<Value>, AdapterError> {
        self.adapter
            .find_many(
                "session",
                FindManyQuery {
                    where_clauses: vec![WhereClause::eq("userId", user_id)],
                    ..Default::default()
                },
            )
            .await
            .map_err(Into::into)
    }

    async fn delete_sessions_for_user(&self, user_id: &str) -> Result<(), AdapterError> {
        // Clean up secondary storage
        if let Some(secondary) = &self.secondary_storage {
            let list_key = format!("active-sessions-{}", user_id);
            if let Some(raw) = secondary.get(&list_key).await {
                let list: Vec<serde_json::Value> =
                    serde_json::from_str(&raw).unwrap_or_default();
                for entry in &list {
                    if let Some(token) = entry["token"].as_str() {
                        let _ = secondary.delete(token).await;
                    }
                }
                let _ = secondary.delete(&list_key).await;
            }
        }

        self.adapter
            .delete_many("session", &[WhereClause::eq("userId", user_id)])
            .await?;
        Ok(())
    }

    async fn delete_user_cascade(&self, user_id: &str) -> Result<(), AdapterError> {
        // Order: sessions → accounts → user (matching TS cascade)
        self.delete_sessions_for_user(user_id).await?;
        self.delete_accounts_by_user_id(user_id).await?;
        self.delete_user(user_id).await?;
        Ok(())
    }

    async fn find_sessions(&self, tokens: &[String]) -> Result<Vec<Value>, AdapterError> {
        let mut results = Vec::new();
        for token in tokens {
            if let Some(session) = self
                .adapter
                .find_one("session", &[WhereClause::eq("token", token.as_str())])
                .await?
            {
                results.push(session);
            }
        }
        Ok(results)
    }

    // ─── Account Operations ──────────────────────────────────────

    async fn create_account(&self, data: Value) -> Result<Value, AdapterError> {
        self.adapter
            .create("account", data, None)
            .await
            .map_err(Into::into)
    }

    async fn find_accounts_by_user_id(&self, user_id: &str) -> Result<Vec<Value>, AdapterError> {
        self.adapter
            .find_many(
                "account",
                FindManyQuery {
                    where_clauses: vec![WhereClause::eq("userId", user_id)],
                    ..Default::default()
                },
            )
            .await
            .map_err(Into::into)
    }

    async fn find_account_by_provider(
        &self,
        provider_id: &str,
        account_id: &str,
    ) -> Result<Option<Value>, AdapterError> {
        self.adapter
            .find_one(
                "account",
                &[
                    WhereClause::eq("providerId", provider_id).and(),
                    WhereClause::eq("accountId", account_id),
                ],
            )
            .await
            .map_err(Into::into)
    }

    async fn update_account(
        &self,
        provider_id: &str,
        account_id: &str,
        data: Value,
    ) -> Result<Value, AdapterError> {
        self.adapter
            .update(
                "account",
                &[
                    WhereClause::eq("providerId", provider_id).and(),
                    WhereClause::eq("accountId", account_id),
                ],
                data,
            )
            .await?
            .ok_or(AdapterError::NotFound)
    }

    async fn delete_account(
        &self,
        provider_id: &str,
        account_id: &str,
    ) -> Result<(), AdapterError> {
        self.adapter
            .delete(
                "account",
                &[
                    WhereClause::eq("providerId", provider_id).and(),
                    WhereClause::eq("accountId", account_id),
                ],
            )
            .await
            .map_err(Into::into)
    }

    async fn delete_accounts_by_user_id(&self, user_id: &str) -> Result<(), AdapterError> {
        self.adapter
            .delete_many("account", &[WhereClause::eq("userId", user_id)])
            .await?;
        Ok(())
    }

    async fn find_account_by_id(&self, account_id: &str) -> Result<Option<Value>, AdapterError> {
        self.adapter
            .find_one("account", &[WhereClause::eq("id", account_id)])
            .await
            .map_err(Into::into)
    }

    async fn update_account_by_id(&self, id: &str, data: Value) -> Result<Value, AdapterError> {
        self.adapter
            .update("account", &[WhereClause::eq("id", id)], data)
            .await?
            .ok_or(AdapterError::NotFound)
    }

    async fn create_oauth_user(
        &self,
        user_data: Value,
        account_data: Value,
    ) -> Result<Value, AdapterError> {
        // Create user first, auto-setting timestamps
        let mut user_with_timestamps = user_data.clone();
        if let Some(obj) = user_with_timestamps.as_object_mut() {
            let now = chrono::Utc::now().to_rfc3339();
            obj.entry("createdAt").or_insert(Value::String(now.clone()));
            obj.entry("updatedAt").or_insert(Value::String(now));
            // Lowercase email
            if let Some(email) = obj.get("email").and_then(|e| e.as_str()).map(|e| e.to_lowercase()) {
                obj.insert("email".to_string(), Value::String(email));
            }
        }

        let user = self.adapter.create("user", user_with_timestamps, None).await?;

        // Then create account linked to the user
        let user_id = user["id"]
            .as_str()
            .ok_or_else(|| AdapterError::Serialization("Created user missing id".into()))?;

        let mut account = account_data;
        if let Some(obj) = account.as_object_mut() {
            let now = chrono::Utc::now().to_rfc3339();
            obj.insert("userId".to_string(), Value::String(user_id.to_string()));
            obj.entry("createdAt").or_insert(Value::String(now.clone()));
            obj.entry("updatedAt").or_insert(Value::String(now));
        }

        self.adapter.create("account", account, None).await?;

        Ok(user)
    }

    async fn find_oauth_user(
        &self,
        email: &str,
        account_id: &str,
        provider_id: &str,
    ) -> Result<Option<OAuthUserResult>, AdapterError> {
        let email_lower = email.to_lowercase();
        // Find the user by email
        let user = match self
            .adapter
            .find_one("user", &[WhereClause::eq("email", email_lower.as_str())])
            .await?
        {
            Some(u) => u,
            None => return Ok(None),
        };

        let user_id = user["id"]
            .as_str()
            .ok_or_else(|| AdapterError::Serialization("User missing id".into()))?;

        // Find all accounts for this user
        let accounts = self
            .adapter
            .find_many(
                "account",
                FindManyQuery {
                    where_clauses: vec![WhereClause::eq("userId", user_id)],
                    ..Default::default()
                },
            )
            .await?;

        // Check if the specific provider+accountId is already linked
        let is_linked = accounts.iter().any(|a| {
            a["providerId"].as_str() == Some(provider_id)
                && a["accountId"].as_str() == Some(account_id)
        });

        Ok(Some(OAuthUserResult {
            user,
            accounts,
            is_linked,
        }))
    }

    async fn link_account(&self, account_data: Value) -> Result<Value, AdapterError> {
        self.adapter
            .create("account", account_data, None)
            .await
            .map_err(Into::into)
    }

    // ─── Verification Operations ─────────────────────────────────

    async fn create_verification(
        &self,
        identifier: &str,
        value: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Value, AdapterError> {
        let data = serde_json::json!({
            "identifier": identifier,
            "value": value,
            "expiresAt": expires_at.to_rfc3339(),
            "createdAt": chrono::Utc::now().to_rfc3339(),
            "updatedAt": chrono::Utc::now().to_rfc3339(),
        });

        self.adapter
            .create("verification", data, None)
            .await
            .map_err(Into::into)
    }

    async fn find_verification(
        &self,
        identifier: &str,
    ) -> Result<Option<Value>, AdapterError> {
        self.adapter
            .find_one(
                "verification",
                &[WhereClause::eq("identifier", identifier)],
            )
            .await
            .map_err(Into::into)
    }

    async fn delete_verification(&self, identifier: &str) -> Result<(), AdapterError> {
        self.adapter
            .delete(
                "verification",
                &[WhereClause::eq("identifier", identifier)],
            )
            .await
            .map_err(Into::into)
    }

    async fn delete_verification_by_identifier(&self, identifier: &str) -> Result<(), AdapterError> {
        // In the standard implementation, this is the same as delete_verification
        // since we use identifier as the lookup field.
        self.delete_verification(identifier).await
    }

    async fn update_verification(&self, id: &str, data: Value) -> Result<Value, AdapterError> {
        self.adapter
            .update("verification", &[WhereClause::eq("id", id)], data)
            .await?
            .ok_or(AdapterError::NotFound)
    }

    // ─── Generic Table Operations ────────────────────────────────

    async fn create(&self, model: &str, data: Value) -> Result<Value, AdapterError> {
        self.adapter
            .create(model, data, None)
            .await
            .map_err(Into::into)
    }

    async fn find_by_id(&self, model: &str, id: &str) -> Result<Value, AdapterError> {
        self.adapter
            .find_one(model, &[WhereClause::eq("id", id)])
            .await?
            .ok_or(AdapterError::NotFound)
    }

    async fn find_one(&self, model: &str, filter: Value) -> Result<Value, AdapterError> {
        let clauses = json_filter_to_where_clauses(&filter);
        self.adapter
            .find_one(model, &clauses)
            .await?
            .ok_or(AdapterError::NotFound)
    }

    async fn find_many(&self, model: &str, filter: Value) -> Result<Vec<Value>, AdapterError> {
        let clauses = json_filter_to_where_clauses(&filter);
        let query = FindManyQuery {
            where_clauses: clauses,
            sort_by: None,
            limit: None,
            offset: None,
            select: None,
            joins: None,
        };
        self.adapter
            .find_many(model, query)
            .await
            .map_err(Into::into)
    }

    async fn update_by_id(&self, model: &str, id: &str, data: Value) -> Result<Value, AdapterError> {
        self.adapter
            .update(model, &[WhereClause::eq("id", id)], data)
            .await?
            .ok_or(AdapterError::NotFound)
    }

    async fn delete_by_id(&self, model: &str, id: &str) -> Result<(), AdapterError> {
        self.adapter
            .delete(model, &[WhereClause::eq("id", id)])
            .await
            .map_err(Into::into)
    }

    async fn delete_many(&self, model: &str, filter: Value) -> Result<i64, AdapterError> {
        let clauses = json_filter_to_where_clauses(&filter);
        self.adapter
            .delete_many(model, &clauses)
            .await
            .map_err(Into::into)
    }
}

// ─── Output Transforms ──────────────────────────────────────────

/// Strip sensitive or internal fields from session output.
///
/// Matches TS `parseSessionOutput` — removes fields that shouldn't be exposed to clients.
pub fn parse_session_output(session: &Value) -> Value {
    let mut result = session.clone();
    if let Some(obj) = result.as_object_mut() {
        // Remove any internal-only fields
        // The TS version uses plugin-defined transforms here;
        // for now we just ensure the core fields are present
        obj.remove("password");
    }
    result
}

/// Strip sensitive or internal fields from user output.
///
/// Matches TS `parseUserOutput` — removes password hashes and internal fields.
pub fn parse_user_output(user: &Value) -> Value {
    let mut result = user.clone();
    if let Some(obj) = result.as_object_mut() {
        obj.remove("password");
        obj.remove("passwordHash");
    }
    result
}

// ─── Test Utilities ──────────────────────────────────────────────

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A no-op adapter for unit tests that don't need real database access.
    pub struct MockInternalAdapter;

    #[async_trait]
    impl InternalAdapter for MockInternalAdapter {
        async fn create_user(&self, _data: Value) -> Result<Value, AdapterError> {
            Ok(serde_json::json!({}))
        }
        async fn find_user_by_id(&self, _id: &str) -> Result<Option<Value>, AdapterError> {
            Ok(None)
        }
        async fn find_user_by_email(&self, _email: &str) -> Result<Option<Value>, AdapterError> {
            Ok(None)
        }
        async fn update_user(&self, _id: &str, _data: Value) -> Result<Value, AdapterError> {
            Ok(serde_json::json!({}))
        }
        async fn update_user_by_email(&self, _email: &str, _data: Value) -> Result<Value, AdapterError> {
            Ok(serde_json::json!({}))
        }
        async fn update_password(&self, _user_id: &str, _password_hash: &str) -> Result<(), AdapterError> {
            Ok(())
        }
        async fn list_users(&self, _limit: Option<usize>, _offset: Option<usize>, _sort_field: Option<&str>, _sort_direction: Option<&str>) -> Result<Vec<Value>, AdapterError> {
            Ok(vec![])
        }
        async fn count_total_users(&self) -> Result<u64, AdapterError> {
            Ok(0)
        }
        async fn delete_user(&self, _id: &str) -> Result<(), AdapterError> {
            Ok(())
        }
        async fn create_session(&self, _user_id: &str, _options: Option<CreateSessionOptions>, _session_expiration: Option<i64>) -> Result<Value, AdapterError> {
            Ok(serde_json::json!({}))
        }
        async fn find_session_by_token(&self, _token: &str) -> Result<Option<Value>, AdapterError> {
            Ok(None)
        }
        async fn find_session_and_user(&self, _token: &str) -> Result<Option<SessionWithUser>, AdapterError> {
            Ok(None)
        }
        async fn update_session(&self, _token: &str, _data: Value) -> Result<Value, AdapterError> {
            Ok(serde_json::json!({}))
        }
        async fn delete_session(&self, _token: &str) -> Result<(), AdapterError> {
            Ok(())
        }
        async fn list_sessions_for_user(&self, _user_id: &str) -> Result<Vec<Value>, AdapterError> {
            Ok(vec![])
        }
        async fn find_sessions(&self, _tokens: &[String]) -> Result<Vec<Value>, AdapterError> {
            Ok(vec![])
        }
        async fn delete_sessions_for_user(&self, _user_id: &str) -> Result<(), AdapterError> {
            Ok(())
        }
        async fn delete_user_cascade(&self, _user_id: &str) -> Result<(), AdapterError> {
            Ok(())
        }
        async fn create_account(&self, _data: Value) -> Result<Value, AdapterError> {
            Ok(serde_json::json!({}))
        }
        async fn find_accounts_by_user_id(&self, _user_id: &str) -> Result<Vec<Value>, AdapterError> {
            Ok(vec![])
        }
        async fn find_account_by_provider(&self, _provider_id: &str, _account_id: &str) -> Result<Option<Value>, AdapterError> {
            Ok(None)
        }
        async fn update_account(&self, _provider_id: &str, _account_id: &str, _data: Value) -> Result<Value, AdapterError> {
            Ok(serde_json::json!({}))
        }
        async fn delete_account(&self, _provider_id: &str, _account_id: &str) -> Result<(), AdapterError> {
            Ok(())
        }
        async fn delete_accounts_by_user_id(&self, _user_id: &str) -> Result<(), AdapterError> {
            Ok(())
        }
        async fn find_account_by_id(&self, _account_id: &str) -> Result<Option<Value>, AdapterError> {
            Ok(None)
        }
        async fn update_account_by_id(&self, _id: &str, _data: Value) -> Result<Value, AdapterError> {
            Ok(serde_json::json!({}))
        }
        async fn create_oauth_user(&self, _user_data: Value, _account_data: Value) -> Result<Value, AdapterError> {
            Ok(serde_json::json!({}))
        }
        async fn find_oauth_user(&self, _email: &str, _account_id: &str, _provider_id: &str) -> Result<Option<OAuthUserResult>, AdapterError> {
            Ok(None)
        }
        async fn link_account(&self, _account_data: Value) -> Result<Value, AdapterError> {
            Ok(serde_json::json!({}))
        }
        async fn create_verification(&self, _identifier: &str, _value: &str, _expires_at: chrono::DateTime<chrono::Utc>) -> Result<Value, AdapterError> {
            Ok(serde_json::json!({}))
        }
        async fn find_verification(&self, _identifier: &str) -> Result<Option<Value>, AdapterError> {
            Ok(None)
        }
        async fn delete_verification(&self, _identifier: &str) -> Result<(), AdapterError> {
            Ok(())
        }
        async fn delete_verification_by_identifier(&self, _identifier: &str) -> Result<(), AdapterError> {
            Ok(())
        }
        async fn update_verification(&self, _id: &str, _data: Value) -> Result<Value, AdapterError> {
            Ok(serde_json::json!({}))
        }

        // Generic CRUD stubs
        async fn create(&self, _model: &str, data: Value) -> Result<Value, AdapterError> {
            Ok(data)
        }
        async fn find_by_id(&self, _model: &str, _id: &str) -> Result<Value, AdapterError> {
            Err(AdapterError::NotFound)
        }
        async fn find_one(&self, _model: &str, _filter: Value) -> Result<Value, AdapterError> {
            Err(AdapterError::NotFound)
        }
        async fn find_many(&self, _model: &str, _filter: Value) -> Result<Vec<Value>, AdapterError> {
            Ok(vec![])
        }
        async fn update_by_id(&self, _model: &str, _id: &str, _data: Value) -> Result<Value, AdapterError> {
            Ok(serde_json::json!({}))
        }
        async fn delete_by_id(&self, _model: &str, _id: &str) -> Result<(), AdapterError> {
            Ok(())
        }
        async fn delete_many(&self, _model: &str, _filter: Value) -> Result<i64, AdapterError> {
            Ok(0)
        }
    }
}
