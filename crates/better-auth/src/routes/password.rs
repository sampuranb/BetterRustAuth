// Password routes — maps to packages/better-auth/src/api/routes/password.ts
//
// Handles change-password, forgot-password, reset-password, and verify-password
// with full validation matching the TS version.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::context::AuthContext;
use crate::internal_adapter::AdapterError;

/// Change password request.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// Forgot password request.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForgotPasswordRequest {
    pub email: String,
    #[serde(default)]
    pub redirect_to: Option<String>,
}

/// Reset password request.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

/// Verify password request (check user's current password).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyPasswordRequest {
    pub password: String,
}

/// Status response for password operations.
#[derive(Debug, Serialize)]
pub struct PasswordStatusResponse {
    pub status: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Handle password change for an authenticated user.
///
/// 1. Validate new password length (min/max)
/// 2. Find credential account for user
/// 3. Verify current password
/// 4. Hash new password
/// 5. Update account with new hash
pub async fn handle_change_password(
    ctx: Arc<AuthContext>,
    user_id: &str,
    body: ChangePasswordRequest,
) -> Result<(), AdapterError> {
    let ep = &ctx.options.email_and_password;

    // 1. Validate new password length
    if body.new_password.len() < ep.min_password_length {
        return Err(AdapterError::Database("Password is too short".into()));
    }
    if body.new_password.len() > ep.max_password_length {
        return Err(AdapterError::Database("Password is too long".into()));
    }

    // 2. Find credential account
    let accounts = ctx.adapter.find_accounts_by_user_id(user_id).await?;
    let credential = accounts
        .iter()
        .find(|a| a["providerId"].as_str() == Some("credential"))
        .ok_or_else(|| AdapterError::Database("No credential account found".into()))?;

    // 3. Verify current password
    let stored_hash = credential["password"]
        .as_str()
        .ok_or_else(|| AdapterError::Serialization("Account has no password hash".into()))?;

    let valid = crate::crypto::password::verify_password(stored_hash, &body.current_password)
        .map_err(|e| AdapterError::Database(format!("Password verification failed: {e}")))?;

    if !valid {
        return Err(AdapterError::Database("Current password is incorrect".into()));
    }

    // 4. Hash new password
    let new_hash = crate::crypto::password::hash_password(&body.new_password)
        .map_err(|e| AdapterError::Database(format!("Password hashing failed: {e}")))?;

    // 5. Update via updatePassword (matches TS)
    ctx.adapter.update_password(user_id, &new_hash).await?;

    Ok(())
}

/// Handle forgot password (creates a reset token).
///
/// Follows TS pattern:
/// 1. Find user by email (silently succeed if not found to prevent enumeration)
/// 2. Simulate timing attack protection if user not found
/// 3. Create verification token
/// 4. Return success message
pub async fn handle_forgot_password(
    ctx: Arc<AuthContext>,
    body: ForgotPasswordRequest,
) -> Result<PasswordStatusResponse, AdapterError> {
    // 1. Find user
    let user = match ctx.adapter.find_user_by_email(&body.email).await? {
        Some(u) => u,
        None => {
            // Simulate verification token and DB lookup to mitigate timing attacks
            let _ = crate::crypto::random::generate_random_string(24);
            let _ = ctx.adapter.find_verification("dummy-verification-token").await;
            return Ok(PasswordStatusResponse {
                status: true,
                message: Some("If this email exists in our system, check your email for the reset link".into()),
            });
        }
    };

    let user_id = user["id"].as_str().unwrap_or_default();

    // 2. Create verification token (default 1 hour expiry)
    let token = crate::crypto::random::generate_random_string(24);
    let expires_at = chrono::Utc::now() + chrono::TimeDelta::hours(1);

    ctx.adapter
        .create_verification(
            &format!("reset-password:{}", token),
            user_id, // Store userId as the value (matches TS)
            expires_at,
        )
        .await?;

    // In a real implementation, the caller would send an email with a URL like:
    // ${baseURL}/reset-password/${token}?callbackURL=${encodedCallbackURL}

    Ok(PasswordStatusResponse {
        status: true,
        message: Some("If this email exists in our system, check your email for the reset link".into()),
    })
}

/// Handle password reset.
///
/// Matches TS `resetPassword`:
/// 1. Validate new password length (min/max)
/// 2. Find and validate verification token
/// 3. Hash new password
/// 4. Update or create credential account
/// 5. Delete verification token
/// 6. Optionally invalidate sessions (controlled by `revokeSessionsOnPasswordReset`)
pub async fn handle_reset_password(
    ctx: Arc<AuthContext>,
    body: ResetPasswordRequest,
) -> Result<PasswordStatusResponse, AdapterError> {
    let ep = &ctx.options.email_and_password;

    // 1. Validate new password length
    if body.new_password.len() < ep.min_password_length {
        return Err(AdapterError::Database("Password is too short".into()));
    }
    if body.new_password.len() > ep.max_password_length {
        return Err(AdapterError::Database("Password is too long".into()));
    }

    let identifier = format!("reset-password:{}", body.token);

    // 2. Find verification
    let verification = ctx
        .adapter
        .find_verification(&identifier)
        .await?
        .ok_or_else(|| AdapterError::Database("Invalid or expired reset token".into()))?;

    // Check expiration
    if let Some(expires_str) = verification["expiresAt"].as_str() {
        if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(expires_str) {
            if expires < chrono::Utc::now() {
                ctx.adapter.delete_verification(&identifier).await?;
                return Err(AdapterError::Database("Reset token has expired".into()));
            }
        }
    }

    // Get userId from stored value
    let user_id = verification["value"]
        .as_str()
        .ok_or_else(|| AdapterError::Serialization("Invalid reset token data".into()))?;

    // 3. Hash new password
    let new_hash = crate::crypto::password::hash_password(&body.new_password)
        .map_err(|e| AdapterError::Database(format!("Password hashing failed: {e}")))?;

    // 4. Update or create credential account (matches TS logic)
    let accounts = ctx.adapter.find_accounts_by_user_id(user_id).await?;
    let has_credential = accounts.iter().any(|a| a["providerId"].as_str() == Some("credential"));

    if has_credential {
        ctx.adapter.update_password(user_id, &new_hash).await?;
    } else {
        // Create credential account if one doesn't exist (e.g., social-only user setting password)
        let now = chrono::Utc::now().to_rfc3339();
        let account_data = serde_json::json!({
            "id": uuid::Uuid::new_v4().to_string(),
            "userId": user_id,
            "accountId": user_id,
            "providerId": "credential",
            "password": new_hash,
            "createdAt": now,
            "updatedAt": now,
        });
        ctx.adapter.create_account(account_data).await?;
    }

    // 5. Delete verification token
    ctx.adapter.delete_verification(&identifier).await?;

    // 6. Conditionally revoke sessions — matches TS `revokeSessionsOnPasswordReset` option.
    // Default is false in both TS and Rust.
    if ep.revoke_sessions_on_password_reset {
        ctx.adapter.delete_sessions_for_user(user_id).await?;
    }

    Ok(PasswordStatusResponse {
        status: true,
        message: None,
    })
}

/// Handle verify password (check user's current password).
///
/// Matches TS `verifyPassword` endpoint.
pub async fn handle_verify_password(
    ctx: Arc<AuthContext>,
    user_id: &str,
    body: VerifyPasswordRequest,
) -> Result<PasswordStatusResponse, AdapterError> {
    // Find credential account
    let accounts = ctx.adapter.find_accounts_by_user_id(user_id).await?;
    let credential = accounts
        .iter()
        .find(|a| a["providerId"].as_str() == Some("credential"))
        .ok_or_else(|| AdapterError::Database("No credential account found".into()))?;

    let stored_hash = credential["password"]
        .as_str()
        .ok_or_else(|| AdapterError::Serialization("Account has no password hash".into()))?;

    let valid = crate::crypto::password::verify_password(stored_hash, &body.password)
        .map_err(|e| AdapterError::Database(format!("Password verification failed: {e}")))?;

    if !valid {
        return Err(AdapterError::Database("Invalid password".into()));
    }

    Ok(PasswordStatusResponse {
        status: true,
        message: None,
    })
}

// ─── reset-password/:token (callback) ───────────────────────────────────────

/// Query parameters for password reset callback.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordResetCallbackQuery {
    pub callback_url: String,
}

/// Result from password reset callback.
#[derive(Debug)]
pub enum PasswordResetCallbackResult {
    /// Redirect the user to the callback URL with the token.
    Redirect(String),
    /// Error redirect — redirect with an error parameter.
    ErrorRedirect(String),
}

/// Handle the password reset callback redirect.
///
/// Maps to TS `requestPasswordResetCallback` at `GET /reset-password/:token`.
///
/// Flow:
/// 1. Validate the token and callbackURL parameters
/// 2. Look up the verification token
/// 3. If valid and not expired, redirect to callbackURL with the token
/// 4. If invalid/expired, redirect to callbackURL with error
pub async fn handle_password_reset_callback(
    ctx: Arc<AuthContext>,
    token: &str,
    query: PasswordResetCallbackQuery,
) -> PasswordResetCallbackResult {
    let callback_url = &query.callback_url;

    if token.is_empty() || callback_url.is_empty() {
        return PasswordResetCallbackResult::ErrorRedirect(
            append_error_to_url(callback_url, "INVALID_TOKEN"),
        );
    }

    // Find the verification token
    let verification = ctx
        .adapter
        .find_verification(&format!("reset-password:{}", token))
        .await;

    match verification {
        Ok(Some(v)) => {
            // Check expiration
            let expired = v["expiresAt"]
                .as_str()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&chrono::Utc) < chrono::Utc::now())
                .unwrap_or(true);

            if expired {
                return PasswordResetCallbackResult::ErrorRedirect(
                    append_error_to_url(callback_url, "INVALID_TOKEN"),
                );
            }

            // Valid token — redirect to callback with token attached
            PasswordResetCallbackResult::Redirect(
                append_param_to_url(callback_url, "token", token),
            )
        }
        _ => {
            // Token not found — redirect with error
            PasswordResetCallbackResult::ErrorRedirect(
                append_error_to_url(callback_url, "INVALID_TOKEN"),
            )
        }
    }
}

/// Append an error query parameter to a URL.
fn append_error_to_url(base_url: &str, error: &str) -> String {
    append_param_to_url(base_url, "error", error)
}

/// Append a query parameter to a URL.
fn append_param_to_url(base_url: &str, key: &str, value: &str) -> String {
    if base_url.contains('?') {
        format!("{}&{}={}", base_url, key, urlencoding::encode(value))
    } else {
        format!("{}?{}={}", base_url, key, urlencoding::encode(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_param_to_clean_url() {
        let result = append_param_to_url("https://example.com/reset", "token", "abc123");
        assert_eq!(result, "https://example.com/reset?token=abc123");
    }

    #[test]
    fn test_append_param_to_url_with_existing_params() {
        let result = append_param_to_url("https://example.com/reset?existing=true", "token", "abc");
        assert_eq!(result, "https://example.com/reset?existing=true&token=abc");
    }

    #[test]
    fn test_append_error_with_encoding() {
        let result = append_error_to_url("https://example.com", "INVALID TOKEN");
        assert!(result.contains("error=INVALID%20TOKEN"));
    }
}
