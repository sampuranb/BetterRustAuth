//! Request and response types for the Better Auth client.
//!
//! These mirror the shapes used by the TS client's request/response types,
//! using `serde_json::Value` for dynamic fields (user, session) and typed
//! structs for well-known request shapes.

use serde::{Deserialize, Serialize};

// ─── Health ─────────────────────────────────────────────────────────

/// Response from `GET /ok`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OkResponse {
    pub ok: bool,
}

// ─── Authentication ─────────────────────────────────────────────────

/// Request body for `POST /sign-up/email`.
///
/// Maps to TS `client.signUp.email({...})`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignUpRequest {
    pub email: String,
    pub password: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

/// Response from `POST /sign-up/email`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignUpResponse {
    pub user: serde_json::Value,
    pub session: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// Request body for `POST /sign-in/email`.
///
/// Maps to TS `client.signIn.email({...})`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInRequest {
    pub email: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remember_me: Option<bool>,
}

/// Response from `POST /sign-in/email`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignInResponse {
    pub user: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// If `true`, a 2FA redirect is needed.
    #[serde(skip_serializing_if = "Option::is_none", rename = "twoFactorRedirect")]
    pub two_factor_redirect: Option<bool>,
    /// Redirect URL (e.g. for social sign-in).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<bool>,
}

/// Request body for `POST /sign-in/social`.
///
/// Maps to TS `client.signIn.social({...})`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialSignInRequest {
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "callbackURL")]
    pub callback_url: Option<String>,
}

/// Response from `POST /sign-in/social`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialSignInResponse {
    /// Authorization URL to redirect the user to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<bool>,
}

// ─── Session ────────────────────────────────────────────────────────

/// Session data returned from the server.
///
/// Maps to TS `{ user: User, session: Session }` response shape.
/// Uses `serde_json::Value` for the user and session objects to support
/// dynamic fields from plugins (additional-fields, custom-session, etc.).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionData {
    pub user: serde_json::Value,
    pub session: serde_json::Value,
}

impl SessionData {
    /// Get the user's ID from the session data.
    pub fn user_id(&self) -> Option<&str> {
        self.user.get("id")?.as_str()
    }

    /// Get the user's email from the session data.
    pub fn user_email(&self) -> Option<&str> {
        self.user.get("email")?.as_str()
    }

    /// Get the user's name from the session data.
    pub fn user_name(&self) -> Option<&str> {
        self.user.get("name")?.as_str()
    }

    /// Get the session token.
    pub fn session_token(&self) -> Option<&str> {
        self.session.get("token")?.as_str()
    }

    /// Get the session ID.
    pub fn session_id(&self) -> Option<&str> {
        self.session.get("id")?.as_str()
    }
}

// ─── User Management ────────────────────────────────────────────────

/// Request body for `POST /update-user`.
///
/// Maps to TS `client.updateUser({...})`. Extra fields can be passed
/// via the `extra` map for plugin-specific fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Additional fields (from plugins like additional-fields).
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

/// Request body for `POST /delete-user`.
///
/// Maps to TS `client.deleteUser({...})`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteUserRequest {
    /// Password confirmation for account deletion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Callback URL after deletion.
    #[serde(skip_serializing_if = "Option::is_none", rename = "callbackURL")]
    pub callback_url: Option<String>,
}
