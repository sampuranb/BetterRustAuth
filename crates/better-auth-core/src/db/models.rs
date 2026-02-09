// Database models matching the exact TypeScript schema definitions.
// See: packages/core/src/db/schema/ (user.ts, session.ts, account.ts, verification.ts, rate-limit.ts)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// User model — exact match to the TypeScript `user` table schema.
///
/// Source: `packages/core/src/db/schema/user.ts`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: String,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Additional fields from plugins (flattened into the user object).
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl User {
    pub fn new(id: String, name: String, email: String) -> Self {
        let now = Utc::now();
        Self {
            id,
            name,
            email: email.to_lowercase(),
            email_verified: false,
            image: None,
            created_at: now,
            updated_at: now,
            extra: serde_json::Map::new(),
        }
    }
}

/// Session model — exact match to the TypeScript `session` table schema.
///
/// Source: `packages/core/src/db/schema/session.ts`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: String,
    /// Session token (stored hashed in DB when `hashSessionToken` is enabled).
    pub token: String,
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Additional fields from plugins.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Account model — exact match to the TypeScript `account` table schema.
///
/// Represents both OAuth provider accounts and credential (email/password) accounts.
///
/// Source: `packages/core/src/db/schema/account.ts`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub id: String,
    /// Provider-specific user identifier (e.g., Google sub, GitHub id).
    pub account_id: String,
    /// Provider identifier (e.g., "google", "github", "credential").
    pub provider_id: String,
    pub user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Hashed password (only for `provider_id == "credential"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Additional fields from plugins.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Verification model — stores temporary verification values (email tokens,
/// password reset tokens, OAuth state, etc.).
///
/// Source: `packages/core/src/db/schema/verification.ts`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verification {
    pub id: String,
    /// The lookup key (e.g., state string, "reset-password:{token}").
    pub identifier: String,
    /// The stored value (e.g., JSON state data, user ID).
    pub value: String,
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Rate limit model — tracks per-key request counts.
///
/// Source: `packages/core/src/db/schema/rate-limit.ts`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimit {
    pub id: String,
    /// Unique rate limit key (e.g., "ip:endpoint").
    pub key: String,
    pub count: i32,
    /// Unix timestamp (seconds) of the last request.
    pub last_request: i64,
}
