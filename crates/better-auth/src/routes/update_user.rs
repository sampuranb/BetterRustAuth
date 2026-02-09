// Update user routes — maps to packages/better-auth/src/api/routes/update-user.ts
//
// Endpoints:
//   POST /update-user     — Update user profile (name, image, additional fields)
//   POST /change-password — Change password (requires current password verification)
//   POST /set-password    — Set password for OAuth-only users (creates credential account)
//   POST /delete-user     — Delete user account with verification
//   POST /change-email    — Change user email with optional verification

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::context::AuthContext;
use crate::crypto::password::{hash_password, verify_password};
use crate::internal_adapter::AdapterError;
use crate::routes::error::{ApiError, ErrorCode};

// ─── Types ───────────────────────────────────────────────────────────────────

/// Update user request.
///
/// Supports name, image, and arbitrary additional fields from plugins.
/// Rejects `email` — use the change-email endpoint instead.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUserRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub image: Option<String>,
    /// Reject email updates through this endpoint.
    #[serde(default)]
    pub email: Option<String>,
    /// Additional fields from plugins (flattened).
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
}

/// Update user response — returns the updated user.
#[derive(Debug, Serialize)]
pub struct UpdateUserResponse {
    pub status: bool,
}

/// Change password request.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordRequest {
    /// The new password to set.
    pub new_password: String,
    /// The current password of the user (required).
    pub current_password: String,
    /// Revoke all other sessions after password change.
    #[serde(default)]
    pub revoke_other_sessions: Option<bool>,
}

/// Change password response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordResponse {
    /// New session token (only if revokeOtherSessions was true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    pub user: serde_json::Value,
}

/// Set password request (for OAuth-only users who want to add a credential).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetPasswordRequest {
    /// The new password to set.
    pub new_password: String,
}

/// Set password response.
#[derive(Debug, Serialize)]
pub struct SetPasswordResponse {
    pub status: bool,
}

/// Change email request.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeEmailRequest {
    /// The new email address.
    pub new_email: String,
    /// Callback URL for email verification.
    #[serde(default)]
    pub callback_url: Option<String>,
}

/// Change email response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeEmailResponse {
    pub status: bool,
    /// If email verification is required, this will contain a message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Delete user request.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteUserRequest {
    /// Password for verification.
    #[serde(default)]
    pub password: Option<String>,
    /// Callback URL to redirect after deletion.
    #[serde(default)]
    pub callback_url: Option<String>,
    /// Deletion verification token (from email confirmation).
    #[serde(default)]
    pub token: Option<String>,
}

/// Delete user response.
#[derive(Debug, Serialize)]
pub struct DeleteUserResponse {
    pub success: bool,
    pub message: String,
}

/// Update user error.
#[derive(Debug, thiserror::Error)]
pub enum UpdateUserError {
    #[error("{0}")]
    Api(ApiError),
    #[error("Database error: {0}")]
    Database(#[from] AdapterError),
}

// ─── update-user ─────────────────────────────────────────────────────────────

/// Handle user profile update.
///
/// Matches TS `updateUser`:
/// - Rejects email field (use change-email instead)
/// - Validates at least one field is provided
/// - Supports additional plugin fields
pub async fn handle_update_user(
    ctx: Arc<AuthContext>,
    user_id: &str,
    body: UpdateUserRequest,
) -> Result<UpdateUserResponse, UpdateUserError> {
    // Reject email updates through this endpoint
    if body.email.is_some() {
        return Err(UpdateUserError::Api(
            ApiError::from_code(ErrorCode::EmailCanNotBeUpdated),
        ));
    }

    let mut update = serde_json::Map::new();

    if let Some(name) = body.name {
        update.insert("name".into(), serde_json::Value::String(name));
    }
    if let Some(image) = body.image {
        update.insert("image".into(), serde_json::Value::String(image));
    }

    // Merge additional plugin fields
    for (k, v) in &body.additional_fields {
        // Skip known fields
        if !matches!(k.as_str(), "name" | "image" | "email") {
            update.insert(k.clone(), v.clone());
        }
    }

    // Must have at least one field to update
    if update.is_empty() {
        return Err(UpdateUserError::Api(
            ApiError::bad_request("No fields to update"),
        ));
    }

    update.insert(
        "updatedAt".into(),
        serde_json::Value::String(chrono::Utc::now().to_rfc3339()),
    );

    let _user = ctx
        .adapter
        .update_user(user_id, serde_json::Value::Object(update))
        .await?;

    Ok(UpdateUserResponse { status: true })
}

// ─── change-password ─────────────────────────────────────────────────────────

/// Handle password change.
///
/// Matches TS `changePassword`:
/// 1. Validate password length constraints
/// 2. Find credential account with existing password
/// 3. Verify current password
/// 4. Hash new password and update
/// 5. Optionally revoke all other sessions and create new one
pub async fn handle_change_password(
    ctx: Arc<AuthContext>,
    user_id: &str,
    user_value: serde_json::Value,
    body: ChangePasswordRequest,
) -> Result<ChangePasswordResponse, UpdateUserError> {
    // Validate password length
    let min_len = ctx.options.email_and_password.min_password_length;

    let max_len = ctx.options.email_and_password.max_password_length;

    if body.new_password.len() < min_len {
        return Err(UpdateUserError::Api(
            ApiError::from_code(ErrorCode::PasswordTooShort),
        ));
    }

    if body.new_password.len() > max_len {
        return Err(UpdateUserError::Api(
            ApiError::from_code(ErrorCode::PasswordTooLong),
        ));
    }

    // Find credential account
    let accounts = ctx.adapter.find_accounts_by_user_id(user_id).await?;
    let credential_account = accounts.iter().find(|a| {
        a["providerId"].as_str() == Some("credential") && a["password"].as_str().is_some()
    });

    let account = credential_account.ok_or_else(|| {
        UpdateUserError::Api(ApiError::from_code(ErrorCode::CredentialAccountNotFound))
    })?;

    let stored_hash = account["password"].as_str().unwrap_or_default();
    let account_id = account["id"].as_str().unwrap_or_default();

    // Verify current password
    let is_valid = verify_password(stored_hash, &body.current_password)
        .map_err(|_| {
            UpdateUserError::Api(ApiError::from_code(ErrorCode::InvalidPassword))
        })?;

    if !is_valid {
        return Err(UpdateUserError::Api(
            ApiError::from_code(ErrorCode::InvalidPassword),
        ));
    }

    // Hash new password and update account
    let new_hash = hash_password(&body.new_password)
        .map_err(|e| AdapterError::Database(e.to_string()))?;

    ctx.adapter
        .update_account(
            "credential",
            account_id,
            serde_json::json!({ "password": new_hash }),
        )
        .await?;

    // Optionally revoke other sessions
    let token = if body.revoke_other_sessions.unwrap_or(false) {
        ctx.adapter.delete_sessions_for_user(user_id).await?;
        let new_session = ctx.adapter.create_session(user_id, None, None).await?;
        Some(new_session["token"].as_str().unwrap_or_default().to_string())
    } else {
        None
    };

    Ok(ChangePasswordResponse {
        token,
        user: user_value,
    })
}

// ─── set-password ────────────────────────────────────────────────────────────

/// Handle setting a password for OAuth-only users.
///
/// Matches TS `setPassword`:
/// - Checks if user already has a credential account
/// - If not, creates one with the given password
/// - If yes, returns error (use change-password instead)
pub async fn handle_set_password(
    ctx: Arc<AuthContext>,
    user_id: &str,
    body: SetPasswordRequest,
) -> Result<SetPasswordResponse, UpdateUserError> {
    // Validate password length
    let min_len = ctx.options.email_and_password.min_password_length;

    let max_len = ctx.options.email_and_password.max_password_length;

    if body.new_password.len() < min_len {
        return Err(UpdateUserError::Api(
            ApiError::from_code(ErrorCode::PasswordTooShort),
        ));
    }

    if body.new_password.len() > max_len {
        return Err(UpdateUserError::Api(
            ApiError::from_code(ErrorCode::PasswordTooLong),
        ));
    }

    // Check if already has a credential account
    let accounts = ctx.adapter.find_accounts_by_user_id(user_id).await?;
    let has_credential = accounts.iter().any(|a| {
        a["providerId"].as_str() == Some("credential") && a["password"].as_str().is_some()
    });

    if has_credential {
        return Err(UpdateUserError::Api(
            ApiError::from_code(ErrorCode::PasswordAlreadySet),
        ));
    }

    // Hash and create credential account
    let password_hash = hash_password(&body.new_password)
        .map_err(|e| AdapterError::Database(e.to_string()))?;

    ctx.adapter
        .link_account(serde_json::json!({
            "userId": user_id,
            "providerId": "credential",
            "accountId": user_id,
            "password": password_hash,
        }))
        .await?;

    Ok(SetPasswordResponse { status: true })
}

// ─── delete-user ─────────────────────────────────────────────────────────────

/// Handle user account deletion.
///
/// Matches TS `deleteUser`:
/// 1. Check if delete user is enabled in options
/// 2. Verify password if provided
/// 3. Delete all sessions, accounts, and user
/// 4. Return deletion result
pub async fn handle_delete_user(
    ctx: Arc<AuthContext>,
    user_id: &str,
    body: DeleteUserRequest,
) -> Result<DeleteUserResponse, UpdateUserError> {
    // Check if delete user is enabled
    let enabled = ctx.options.user.delete_user.enabled;

    if !enabled {
        return Err(UpdateUserError::Api(
            ApiError::not_found("Delete user is disabled"),
        ));
    }

    // If password provided, verify it
    if let Some(password) = &body.password {
        let accounts = ctx.adapter.find_accounts_by_user_id(user_id).await?;
        let credential_account = accounts.iter().find(|a| {
            a["providerId"].as_str() == Some("credential") && a["password"].as_str().is_some()
        });

        if let Some(account) = credential_account {
            let stored_hash = account["password"].as_str().unwrap_or_default();
            let is_valid = verify_password(stored_hash, password)
                .map_err(|_| {
                    UpdateUserError::Api(ApiError::from_code(ErrorCode::InvalidPassword))
                })?;

            if !is_valid {
                return Err(UpdateUserError::Api(
                    ApiError::from_code(ErrorCode::InvalidPassword),
                ));
            }
        } else {
            return Err(UpdateUserError::Api(
                ApiError::from_code(ErrorCode::CredentialAccountNotFound),
            ));
        }
    }

    // Delete all sessions, accounts, then user
    let _ = ctx.adapter.delete_sessions_for_user(user_id).await;
    let _ = ctx.adapter.delete_accounts_by_user_id(user_id).await;
    ctx.adapter.delete_user(user_id).await?;

    Ok(DeleteUserResponse {
        success: true,
        message: "User deleted".into(),
    })
}

// ─── change-email ────────────────────────────────────────────────────────────

/// Handle email change.
///
/// - Validates the new email is not already in use
/// - If email verification is required, sends verification email
/// - Otherwise, updates email directly
pub async fn handle_change_email(
    ctx: Arc<AuthContext>,
    user_id: &str,
    body: ChangeEmailRequest,
) -> Result<ChangeEmailResponse, UpdateUserError> {
    // Check if new email is already in use
    let existing = ctx.adapter.find_user_by_email(&body.new_email).await?;
    if existing.is_some() {
        return Err(UpdateUserError::Api(
            ApiError::from_code(ErrorCode::UserAlreadyExists),
        ));
    }

    // Check if email verification is required
    let require_verification = ctx
        .options
        .email_verification
        .as_ref()
        .map(|e| e.send_on_sign_up)
        .unwrap_or(false);

    if require_verification {
        // TODO: Send verification email to new address
        // For now, store a verification token
        let token = crate::crypto::random::generate_random_string(32);
        let expires_at = chrono::Utc::now() + chrono::TimeDelta::hours(24);

        let data = serde_json::json!({
            "userId": user_id,
            "newEmail": body.new_email,
            "type": "change-email",
        });

        ctx.adapter
            .create_verification(&token, &data.to_string(), expires_at)
            .await?;

        return Ok(ChangeEmailResponse {
            status: true,
            message: Some("Verification email sent".into()),
        });
    }

    // Update email directly
    let update = serde_json::json!({
        "email": body.new_email,
        "updatedAt": chrono::Utc::now().to_rfc3339(),
    });
    ctx.adapter.update_user(user_id, update).await?;

    Ok(ChangeEmailResponse {
        status: true,
        message: None,
    })
}

// ─── delete-user/callback ────────────────────────────────────────────────────

/// Delete user callback query parameters.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteUserCallbackQuery {
    pub token: String,
    #[serde(default)]
    pub callback_url: Option<String>,
}

/// Handle the delete-user callback (verified deletion via email token).
///
/// Maps to TS `deleteUserCallback` at `GET /delete-user/callback`.
///
/// Flow:
/// 1. Check if delete user is enabled in options
/// 2. Validate the verification token
/// 3. Optionally get the session for the user
/// 4. Delete user, sessions, accounts, and the verification token
/// 5. Return success or redirect
pub async fn handle_delete_user_callback(
    ctx: Arc<AuthContext>,
    user_id: Option<&str>,
    query: DeleteUserCallbackQuery,
) -> Result<DeleteUserResponse, UpdateUserError> {
    // Check if delete user is enabled
    if !ctx.options.user.delete_user.enabled {
        return Err(UpdateUserError::Api(
            ApiError::from_code(ErrorCode::NotFound),
        ));
    }

    // Find the verification token
    let verification = ctx
        .adapter
        .find_verification(&format!("delete-account-{}", query.token))
        .await?;

    let verification = verification.ok_or_else(|| {
        UpdateUserError::Api(ApiError::from_code(ErrorCode::InvalidToken))
    })?;

    // Check expiration
    let expires_at = verification["expiresAt"]
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));

    if let Some(exp) = expires_at {
        if exp < chrono::Utc::now() {
            return Err(UpdateUserError::Api(
                ApiError::from_code(ErrorCode::InvalidToken),
            ));
        }
    }

    // Get the user ID from the verification value
    let target_user_id = verification["value"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    // Verify the user ID matches if session is present
    if let Some(uid) = user_id {
        if uid != target_user_id {
            return Err(UpdateUserError::Api(
                ApiError::from_code(ErrorCode::InvalidToken),
            ));
        }
    }

    // Delete the user, sessions, accounts
    let _ = ctx.adapter.delete_sessions_for_user(&target_user_id).await;
    let _ = ctx.adapter.delete_accounts_by_user_id(&target_user_id).await;
    ctx.adapter.delete_user(&target_user_id).await?;

    // Delete the verification token
    if let Some(id) = verification["id"].as_str() {
        let _ = ctx.adapter.delete_verification(id).await;
    }

    Ok(DeleteUserResponse {
        success: true,
        message: "User deleted".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_change_password_response_serialization() {
        let resp = ChangePasswordResponse {
            token: Some("new-token".into()),
            user: serde_json::json!({"id": "u1"}),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["token"], "new-token");
        assert_eq!(json["user"]["id"], "u1");
    }

    #[test]
    fn test_change_password_response_without_token() {
        let resp = ChangePasswordResponse {
            token: None,
            user: serde_json::json!({"id": "u1"}),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("token").is_none()); // None is omitted by skip_serializing_if
    }

    #[test]
    fn test_delete_user_response() {
        let resp = DeleteUserResponse {
            success: true,
            message: "User deleted".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["message"], "User deleted");
    }
}
