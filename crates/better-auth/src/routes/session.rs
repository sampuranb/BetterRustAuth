// Session routes — maps to packages/better-auth/src/api/routes/session.ts
//
// Endpoints:
//   GET/POST /get-session   — Get current session with cookie caching + sliding window refresh
//   GET      /list-sessions — List all active sessions for the current user
//   POST     /revoke-session — Revoke a single session by token
//   POST     /revoke-sessions — Revoke all sessions for the current user
//   POST     /revoke-other-sessions — Revoke all sessions except the current one

use std::sync::Arc;

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use crate::context::AuthContext;
use crate::internal_adapter::AdapterError;

// ─── Types ───────────────────────────────────────────────────────────────────

/// Session response returned by get-session.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    pub session: serde_json::Value,
    pub user: serde_json::Value,
    /// When deferred session refresh is enabled, indicates if the session needs a POST refresh.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs_refresh: Option<bool>,
}

/// Simple status response for revoke operations.
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub status: bool,
}

/// Query parameters for get-session.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetSessionQuery {
    /// If true, bypass the cookie cache and fetch from DB.
    #[serde(default)]
    pub disable_cookie_cache: bool,
    /// If true, don't refresh/extend the session.
    #[serde(default)]
    pub disable_refresh: bool,
}

/// Options controlling session retrieval behavior.
#[derive(Debug, Clone)]
pub struct GetSessionOptions {
    /// HTTP method (GET or POST). When deferSessionRefresh is enabled,
    /// GET is read-only while POST can trigger DB writes.
    pub is_post: bool,
    /// If true, the user opted out of "remember me".
    pub dont_remember_me: bool,
    /// Per-request query overrides.
    pub query: GetSessionQuery,
}

impl Default for GetSessionOptions {
    fn default() -> Self {
        Self {
            is_post: false,
            dont_remember_me: false,
            query: GetSessionQuery::default(),
        }
    }
}

/// Result of getting a session — includes cookie actions the caller must execute.
#[derive(Debug)]
pub struct GetSessionResult {
    /// The session response to return to the client, or None if no valid session.
    pub response: Option<SessionResponse>,
    /// If Some, the caller should set the session cookie with the given expiry.
    pub set_session_cookie: Option<SetSessionCookieAction>,
    /// If true, the caller should delete the session cookie.
    pub delete_session_cookie: bool,
    /// If true, the caller should expire the session data cookie (cache).
    pub expire_session_data_cookie: bool,
}

/// Instruction to set a session cookie.
#[derive(Debug, Clone)]
pub struct SetSessionCookieAction {
    pub token: String,
    pub max_age_secs: i64,
}

// ─── Freshness ───────────────────────────────────────────────────────────────

/// Check if a session is "fresh" enough for sensitive operations.
///
/// Maps to TS `freshSessionMiddleware`.
///
/// * `fresh_age_secs` — max age in seconds for the session to be considered fresh.
///   If 0, freshness check is disabled.
/// * Returns `true` if the session is fresh.
pub fn is_session_fresh(session: &serde_json::Value, fresh_age_secs: u64) -> bool {
    if fresh_age_secs == 0 {
        return true;
    }

    let last_updated = session["updatedAt"]
        .as_str()
        .or_else(|| session["createdAt"].as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.to_utc());

    match last_updated {
        Some(updated) => {
            let age = (Utc::now() - updated).num_seconds() as u64;
            age < fresh_age_secs
        }
        None => false,
    }
}

// ─── Core: getSession ────────────────────────────────────────────────────────

/// Handle get-session.
///
/// Full implementation matching TS `getSession`:
/// 1. Look up session + user by token
/// 2. Check if session has expired (clean up if so)
/// 3. Handle `dontRememberMe` / `disableRefresh` early return
/// 4. Sliding window refresh: if session is due to be updated, extend expiry
/// 5. Handle deferred session refresh (GET vs POST distinction)
/// 6. Return session and user data
pub async fn handle_get_session(
    ctx: Arc<AuthContext>,
    session_token: &str,
    options: GetSessionOptions,
) -> Result<GetSessionResult, AdapterError> {
    // deferSessionRefresh is not yet a config field — default to false
    let defer_session_refresh = false;

    // POST is only allowed when deferSessionRefresh is enabled
    if options.is_post && !defer_session_refresh {
        return Ok(GetSessionResult {
            response: None,
            set_session_cookie: None,
            delete_session_cookie: false,
            expire_session_data_cookie: false,
        });
    }

    // 1. Find session and user
    let session_user = match ctx.adapter.find_session_and_user(session_token).await? {
        Some(su) => su,
        None => {
            return Ok(GetSessionResult {
                response: None,
                set_session_cookie: None,
                delete_session_cookie: true,
                expire_session_data_cookie: false,
            });
        }
    };

    // 2. Check expiration
    let expires_at = parse_datetime_field(&session_user.session, "expiresAt");
    if let Some(exp) = expires_at {
        if exp < Utc::now() {
            // Session expired — clean up
            // Only delete on POST when deferSessionRefresh is enabled
            if !defer_session_refresh || options.is_post {
                let _ = ctx.adapter.delete_session(session_token).await;
            }
            return Ok(GetSessionResult {
                response: None,
                set_session_cookie: None,
                delete_session_cookie: true,
                expire_session_data_cookie: false,
            });
        }
    }

    // 3. If dontRememberMe or disableRefresh, return session as-is
    let disable_refresh = options.query.disable_refresh;

    if options.dont_remember_me || disable_refresh {
        return Ok(GetSessionResult {
            response: Some(SessionResponse {
                session: session_user.session,
                user: session_user.user,
                needs_refresh: None,
            }),
            set_session_cookie: None,
            delete_session_cookie: false,
            expire_session_data_cookie: false,
        });
    }

    // 4. Sliding window: calculate if session is due to be updated
    let expires_in = ctx.session_config.expires_in;
    let update_age = ctx.session_config.update_age;

    let session_is_due_to_be_updated = if let Some(exp) = expires_at {
        let exp_ms = exp.timestamp_millis();
        let due_date_ms = exp_ms - (expires_in as i64 * 1000) + (update_age as i64 * 1000);
        due_date_ms <= Utc::now().timestamp_millis()
    } else {
        false
    };

    let needs_refresh = session_is_due_to_be_updated && !disable_refresh;

    // 5. Handle deferred session refresh
    if defer_session_refresh && !options.is_post {
        // GET with deferred refresh — return session but flag if it needs refresh
        return Ok(GetSessionResult {
            response: Some(SessionResponse {
                session: session_user.session,
                user: session_user.user,
                needs_refresh: Some(needs_refresh),
            }),
            set_session_cookie: None,
            delete_session_cookie: false,
            expire_session_data_cookie: false,
        });
    }

    // 6. Perform refresh if needed
    if needs_refresh {
        let new_expires = Utc::now() + TimeDelta::seconds(expires_in as i64);
        let update = serde_json::json!({
            "expiresAt": new_expires.to_rfc3339(),
            "updatedAt": Utc::now().to_rfc3339(),
        });
        let updated_session = ctx
            .adapter
            .update_session(session_token, update)
            .await?;

        let max_age = (new_expires - Utc::now()).num_seconds();
        return Ok(GetSessionResult {
            response: Some(SessionResponse {
                session: updated_session,
                user: session_user.user,
                needs_refresh: None,
            }),
            set_session_cookie: Some(SetSessionCookieAction {
                token: session_token.to_string(),
                max_age_secs: max_age,
            }),
            delete_session_cookie: false,
            expire_session_data_cookie: false,
        });
    }

    // 7. Normal case — return session as-is
    Ok(GetSessionResult {
        response: Some(SessionResponse {
            session: session_user.session,
            user: session_user.user,
            needs_refresh: None,
        }),
        set_session_cookie: None,
        delete_session_cookie: false,
        expire_session_data_cookie: false,
    })
}

// ─── listSessions ────────────────────────────────────────────────────────────

/// List all active sessions for the current user.
///
/// Maps to TypeScript `listSessions`.
pub async fn handle_list_sessions(
    ctx: Arc<AuthContext>,
    user_id: &str,
) -> Result<Vec<serde_json::Value>, AdapterError> {
    let sessions = ctx.adapter.list_sessions_for_user(user_id).await?;

    // Filter to only active (non-expired) sessions
    let now = Utc::now();
    let active: Vec<serde_json::Value> = sessions
        .into_iter()
        .filter(|s| {
            parse_datetime_field(s, "expiresAt")
                .map(|e| e > now)
                .unwrap_or(false)
        })
        .collect();

    Ok(active)
}

// ─── revokeSession ───────────────────────────────────────────────────────────

/// Revoke a single session by token.
///
/// Maps to TypeScript `revokeSession`.
/// Only allows revoking sessions owned by the current user.
pub async fn handle_revoke_session(
    ctx: Arc<AuthContext>,
    current_user_id: &str,
    token_to_revoke: &str,
) -> Result<StatusResponse, AdapterError> {
    // Find the session to verify ownership
    let session = ctx
        .adapter
        .find_session_and_user(token_to_revoke)
        .await?;

    if let Some(su) = session {
        if su.session["userId"].as_str() == Some(current_user_id) {
            ctx.adapter.delete_session(token_to_revoke).await?;
        }
    }

    Ok(StatusResponse { status: true })
}

// ─── revokeSessions ─────────────────────────────────────────────────────────

/// Revoke all sessions for the current user.
///
/// Maps to TypeScript `revokeSessions`.
pub async fn handle_revoke_sessions(
    ctx: Arc<AuthContext>,
    user_id: &str,
) -> Result<StatusResponse, AdapterError> {
    ctx.adapter.delete_sessions_for_user(user_id).await?;
    Ok(StatusResponse { status: true })
}

// ─── revokeOtherSessions ────────────────────────────────────────────────────

/// Revoke all sessions except the current one.
///
/// Maps to TypeScript `revokeOtherSessions`.
pub async fn handle_revoke_other_sessions(
    ctx: Arc<AuthContext>,
    user_id: &str,
    current_session_token: &str,
) -> Result<StatusResponse, AdapterError> {
    let sessions = ctx.adapter.list_sessions_for_user(user_id).await?;

    let now = Utc::now();
    for session in sessions {
        let token = session["token"].as_str().unwrap_or_default();
        if token == current_session_token {
            continue;
        }
        // Only revoke active sessions
        let is_active = parse_datetime_field(&session, "expiresAt")
            .map(|e| e > now)
            .unwrap_or(false);
        if is_active {
            let _ = ctx.adapter.delete_session(token).await;
        }
    }

    Ok(StatusResponse { status: true })
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Parse a datetime field from a JSON Value (supports RFC 3339 strings).
fn parse_datetime_field(value: &serde_json::Value, field: &str) -> Option<DateTime<Utc>> {
    value[field]
        .as_str()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.to_utc())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_datetime_field() {
        let val = serde_json::json!({
            "expiresAt": "2030-01-01T00:00:00Z",
        });
        let dt = parse_datetime_field(&val, "expiresAt");
        assert!(dt.is_some());
        assert!(dt.unwrap() > Utc::now());
    }

    #[test]
    fn test_parse_datetime_field_missing() {
        let val = serde_json::json!({});
        assert!(parse_datetime_field(&val, "expiresAt").is_none());
    }

    #[test]
    fn test_is_session_fresh_disabled() {
        let session = serde_json::json!({});
        assert!(is_session_fresh(&session, 0));
    }

    #[test]
    fn test_is_session_fresh_recent() {
        let session = serde_json::json!({
            "updatedAt": Utc::now().to_rfc3339(),
        });
        assert!(is_session_fresh(&session, 300)); // 5 minutes
    }

    #[test]
    fn test_is_session_fresh_stale() {
        let old = Utc::now() - TimeDelta::seconds(600);
        let session = serde_json::json!({
            "updatedAt": old.to_rfc3339(),
        });
        assert!(!is_session_fresh(&session, 300)); // 5 minutes
    }

    #[test]
    fn test_session_response_serialization() {
        let resp = SessionResponse {
            session: serde_json::json!({"id": "s1"}),
            user: serde_json::json!({"id": "u1"}),
            needs_refresh: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("needsRefresh").is_none());

        let resp_with_refresh = SessionResponse {
            needs_refresh: Some(true),
            ..resp
        };
        let json = serde_json::to_value(&resp_with_refresh).unwrap();
        assert_eq!(json["needsRefresh"], true);
    }
}
