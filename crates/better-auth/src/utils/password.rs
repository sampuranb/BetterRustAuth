// Password validation utilities — maps to packages/better-auth/src/utils/password.ts

use std::sync::Arc;

use crate::context::AuthContext;
use crate::internal_adapter::AdapterError;

/// Validate a password against the stored hash for a user.
///
/// Matches TS `validatePassword`:
/// 1. Find the credential account for the user
/// 2. Verify the password against the stored hash
/// 3. Return true if valid, false otherwise
pub async fn validate_password(
    ctx: Arc<AuthContext>,
    user_id: &str,
    password: &str,
) -> Result<bool, AdapterError> {
    let accounts = ctx.adapter.find_accounts_by_user_id(user_id).await?;

    let credential_account = accounts
        .iter()
        .find(|acc| acc["providerId"].as_str() == Some("credential"));

    match credential_account {
        Some(account) => {
            let stored_hash = match account["password"].as_str() {
                Some(h) if !h.is_empty() => h,
                _ => return Ok(false),
            };
            match crate::crypto::password::verify_password(stored_hash, password) {
                Ok(verified) => Ok(verified),
                Err(_) => Ok(false),
            }
        }
        None => Ok(false),
    }
}

/// Check if a credential account exists and has a password.
pub async fn has_credential_account(
    ctx: Arc<AuthContext>,
    user_id: &str,
) -> Result<bool, AdapterError> {
    let accounts = ctx.adapter.find_accounts_by_user_id(user_id).await?;
    Ok(accounts
        .iter()
        .any(|acc| {
            acc["providerId"].as_str() == Some("credential")
                && acc["password"].as_str().map_or(false, |p| !p.is_empty())
        }))
}

/// Validate password strength.
///
/// Returns `Ok(())` if the password meets requirements, or an error message.
pub fn check_password_strength(
    password: &str,
    min_length: usize,
    max_length: usize,
) -> Result<(), String> {
    if password.len() < min_length {
        return Err(format!(
            "Password must be at least {} characters",
            min_length
        ));
    }
    if password.len() > max_length {
        return Err(format!(
            "Password must be at most {} characters",
            max_length
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_password_strength_valid() {
        assert!(check_password_strength("password123", 8, 128).is_ok());
    }

    #[test]
    fn test_check_password_strength_too_short() {
        let result = check_password_strength("abc", 8, 128);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("at least 8"));
    }

    #[test]
    fn test_check_password_strength_too_long() {
        let long_pass = "a".repeat(200);
        let result = check_password_strength(&long_pass, 8, 128);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("at most 128"));
    }
}
