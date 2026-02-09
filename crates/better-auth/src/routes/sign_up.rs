// Sign-up route — maps to packages/better-auth/src/api/routes/sign-up.ts
//
// Handles email/password user registration with full validation matching the TS version.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::context::AuthContext;
use crate::db::ModelName;
use crate::internal_adapter::AdapterError;

/// Sign-up error codes matching TS `BASE_ERROR_CODES`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SignUpError {
    EmailPasswordSignUpDisabled,
    InvalidEmail,
    InvalidPassword,
    PasswordTooShort,
    PasswordTooLong,
    UserAlreadyExists,
    FailedToCreateUser,
    FailedToCreateSession,
}

impl std::fmt::Display for SignUpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmailPasswordSignUpDisabled => write!(f, "Email and password sign up is not enabled"),
            Self::InvalidEmail => write!(f, "Invalid email address"),
            Self::InvalidPassword => write!(f, "Invalid password"),
            Self::PasswordTooShort => write!(f, "Password is too short"),
            Self::PasswordTooLong => write!(f, "Password is too long"),
            Self::UserAlreadyExists => write!(f, "User already exists. Please use a different email"),
            Self::FailedToCreateUser => write!(f, "Failed to create user"),
            Self::FailedToCreateSession => write!(f, "Failed to create session"),
        }
    }
}

/// Sign-up request body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignUpRequest {
    pub email: String,
    pub password: String,
    pub name: String,
    #[serde(default)]
    pub image: Option<String>,
    /// Callback URL for email verification redirect.
    #[serde(default)]
    pub callback_url: Option<String>,
    /// If false, session will not be remembered. Default = true.
    #[serde(default)]
    pub remember_me: Option<bool>,
    /// Additional fields from plugins (flattened into the struct).
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
}

/// Sign-up response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignUpResponse {
    pub user: serde_json::Value,
    /// null when autoSignIn is false or emailVerification is required.
    pub token: Option<String>,
}

/// Validate that a string looks like an email address.
///
/// Basic RFC 5322 check: contains exactly one @, non-empty local/domain parts.
fn is_valid_email(email: &str) -> bool {
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    let local = parts[0];
    let domain = parts[1];
    !local.is_empty() && !domain.is_empty() && domain.contains('.')
}

/// Handle email/password sign-up.
///
/// Matches the TS `signUpEmail` handler with full validation:
///
/// 1. Check emailAndPassword is enabled and signup not disabled
/// 2. Validate email format
/// 3. Validate password length (min/max)
/// 4. Check if user already exists
/// 5. Hash password
/// 6. Create user record (with lowercased email)
/// 7. Link credential account
/// 8. Optionally create session (unless autoSignIn=false or requireEmailVerification)
/// 9. Return user + token
pub async fn handle_sign_up(
    ctx: Arc<AuthContext>,
    body: SignUpRequest,
) -> Result<SignUpResponse, SignUpHandlerError> {
    let ep = &ctx.options.email_and_password;

    // 1. Check if email/password auth is enabled
    if !ep.enabled || ep.disable_signup {
        return Err(SignUpHandlerError::BadRequest(SignUpError::EmailPasswordSignUpDisabled));
    }

    // 2. Validate email format
    if !is_valid_email(&body.email) {
        return Err(SignUpHandlerError::BadRequest(SignUpError::InvalidEmail));
    }

    // 3. Validate password
    if body.password.is_empty() {
        return Err(SignUpHandlerError::BadRequest(SignUpError::InvalidPassword));
    }
    if body.password.len() < ep.min_password_length {
        return Err(SignUpHandlerError::BadRequest(SignUpError::PasswordTooShort));
    }
    if body.password.len() > ep.max_password_length {
        return Err(SignUpHandlerError::BadRequest(SignUpError::PasswordTooLong));
    }

    // 4. Check if user already exists
    let email = body.email.to_lowercase();
    if ctx.adapter.find_user_by_email(&email).await?.is_some() {
        return Err(SignUpHandlerError::UnprocessableEntity(SignUpError::UserAlreadyExists));
    }

    // 5. Hash the password (before creating user, so failures don't leave orphaned records)
    let password_hash = crate::crypto::password::hash_password(&body.password)
        .map_err(|e| SignUpHandlerError::Internal(format!("Password hashing failed: {e}")))?;

    // 6. Create user record
    let user_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let mut user_data = serde_json::json!({
        "id": user_id,
        "email": email,
        "name": body.name,
        "image": body.image,
        "emailVerified": false,
        "createdAt": now,
        "updatedAt": now,
    });

    // Merge any additional plugin fields
    if let Some(obj) = user_data.as_object_mut() {
        for (k, v) in &body.additional_fields {
            // Skip known fields that are already set
            if !matches!(k.as_str(), "email" | "password" | "name" | "image" | "callbackURL" | "rememberMe") {
                obj.insert(k.clone(), v.clone());
            }
        }
    }

    // Run before-create hooks
    let user_data = match ctx.hooks.run_before_create(ModelName::User, user_data).await {
        Some(data) => data,
        None => return Err(SignUpHandlerError::UnprocessableEntity(SignUpError::FailedToCreateUser)),
    };

    let user = ctx.adapter.create_user(user_data).await
        .map_err(|_| SignUpHandlerError::UnprocessableEntity(SignUpError::FailedToCreateUser))?;

    // Run after-create hooks
    ctx.hooks.run_after_create(ModelName::User, &user).await;

    // 7. Link credential account
    let account_data = serde_json::json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "userId": user_id,
        "accountId": user_id,
        "providerId": "credential",
        "password": password_hash,
        "createdAt": now,
        "updatedAt": now,
    });

    ctx.adapter.link_account(account_data).await
        .map_err(|_| SignUpHandlerError::UnprocessableEntity(SignUpError::FailedToCreateUser))?;

    // 8. Check if we should skip session creation
    // - autoSignIn is false
    // - requireEmailVerification is true
    if !ep.auto_sign_in || ep.require_email_verification {
        return Ok(SignUpResponse {
            user,
            token: None,
        });
    }

    // 9. Create session (adapter generates token, expiry, timestamps)
    let session = ctx.adapter.create_session(
        &user_id,
        None,
        Some(ctx.session_config.expires_in as i64),
    ).await
        .map_err(|_| SignUpHandlerError::Internal(SignUpError::FailedToCreateSession.to_string()))?;

    let session_token = session["token"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    Ok(SignUpResponse {
        user,
        token: Some(session_token),
    })
}

/// Typed error for sign-up handler.
///
/// Separates validation errors (400) from conflict errors (422) from internal errors (500).
#[derive(Debug)]
pub enum SignUpHandlerError {
    /// 400 Bad Request (validation failures).
    BadRequest(SignUpError),
    /// 422 Unprocessable Entity (user already exists, hook cancelled, etc.).
    UnprocessableEntity(SignUpError),
    /// 500 Internal Server Error.
    Internal(String),
    /// Database error pass-through.
    Adapter(AdapterError),
}

impl From<AdapterError> for SignUpHandlerError {
    fn from(e: AdapterError) -> Self {
        Self::Adapter(e)
    }
}

impl std::fmt::Display for SignUpHandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadRequest(e) => write!(f, "Bad Request: {e}"),
            Self::UnprocessableEntity(e) => write!(f, "Unprocessable Entity: {e}"),
            Self::Internal(e) => write!(f, "Internal Server Error: {e}"),
            Self::Adapter(e) => write!(f, "Adapter Error: {e}"),
        }
    }
}

impl std::error::Error for SignUpHandlerError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_validation() {
        assert!(is_valid_email("user@example.com"));
        assert!(is_valid_email("user+tag@example.com"));
        assert!(!is_valid_email("invalid"));
        assert!(!is_valid_email("@example.com"));
        assert!(!is_valid_email("user@"));
        assert!(!is_valid_email("user@example"));
        assert!(!is_valid_email(""));
    }
}
