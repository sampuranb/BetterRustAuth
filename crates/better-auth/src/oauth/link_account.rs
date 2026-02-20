// OAuth2 account linking — maps to packages/better-auth/src/oauth2/link-account.ts
//
// Handles finding/creating users from OAuth provider info, account linking,
// and token management during the OAuth callback flow.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::context::AuthContext;
use crate::internal_adapter::AdapterError;

/// User info from an OAuth provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthUserInfo {
    pub id: String,
    pub email: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub email_verified: bool,
}

/// Account info from an OAuth provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthAccountInfo {
    pub provider_id: String,
    pub account_id: String,
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub access_token_expires_at: Option<String>,
    #[serde(default)]
    pub refresh_token_expires_at: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

/// Options for handleOAuthUserInfo.
#[derive(Debug, Clone, Default)]
pub struct HandleOAuthOptions {
    pub callback_url: Option<String>,
    pub disable_sign_up: bool,
    pub override_user_info: bool,
    pub is_trusted_provider: bool,
}

/// Result of handleOAuthUserInfo.
#[derive(Debug)]
pub enum OAuthUserResult {
    /// Successfully found/created user and session.
    Success {
        user: serde_json::Value,
        session: serde_json::Value,
        is_register: bool,
    },
    /// Error during processing.
    Error {
        error: String,
        is_register: bool,
    },
}

/// Handle OAuth user info — find or create the user and account.
///
/// Matches TS `handleOAuthUserInfo`:
/// 1. Look up existing user by email + provider
/// 2. If found with linked account → update tokens, return user
/// 3. If found without linked account → attempt account linking
/// 4. If not found → create new user + account
/// 5. Create session and return
pub async fn handle_oauth_user_info(
    ctx: Arc<AuthContext>,
    user_info: OAuthUserInfo,
    account: OAuthAccountInfo,
    opts: HandleOAuthOptions,
) -> Result<OAuthUserResult, AdapterError> {
    let email = user_info.email.to_lowercase();

    // 1. Look up existing user
    let db_user = ctx
        .adapter
        .find_oauth_user(&email, &account.account_id, &account.provider_id)
        .await?;

    let is_register;
    let user_value;

    if let Some(oauth_result) = db_user {
        is_register = false;
        let user = oauth_result.user.clone();

        // Check if account is already linked
        let linked = oauth_result.accounts.iter().any(|acc| {
            acc["providerId"].as_str() == Some(&account.provider_id)
                && acc["accountId"].as_str() == Some(&account.account_id)
        });

        if !linked {
            // Attempt account linking
            let account_linking_enabled = true; // Default, could be from options
            let trusted = opts.is_trusted_provider || user_info.email_verified;

            if !trusted || !account_linking_enabled {
                return Ok(OAuthUserResult::Error {
                    error: "account not linked".into(),
                    is_register: false,
                });
            }

            // Link the account
            let access_token = maybe_encrypt_token(ctx.as_ref(), account.access_token.as_deref());
            let refresh_token = maybe_encrypt_token(ctx.as_ref(), account.refresh_token.as_deref());

            let link_data = serde_json::json!({
                "providerId": account.provider_id,
                "accountId": user_info.id,
                "userId": user["id"].as_str().unwrap_or_default(),
                "accessToken": access_token,
                "refreshToken": refresh_token,
                "idToken": account.id_token,
                "accessTokenExpiresAt": account.access_token_expires_at,
                "refreshTokenExpiresAt": account.refresh_token_expires_at,
                "scope": account.scope,
            });

            ctx.adapter.link_account(link_data).await?;

            // If provider says email is verified and user's isn't, update
            if user_info.email_verified && user["emailVerified"].as_bool() != Some(true) {
                if email == user["email"].as_str().unwrap_or_default() {
                    ctx.adapter
                        .update_user(
                            user["id"].as_str().unwrap_or_default(),
                            serde_json::json!({ "emailVerified": true }),
                        )
                        .await?;
                }
            }
        } else {
            // Account already linked — update tokens if configured
            let linked_account = oauth_result.accounts.iter().find(|acc| {
                acc["providerId"].as_str() == Some(&account.provider_id)
                    && acc["accountId"].as_str() == Some(&account.account_id)
            });

            if let Some(linked_acc) = linked_account {
                let access_token = maybe_encrypt_token(ctx.as_ref(), account.access_token.as_deref());
                let refresh_token = maybe_encrypt_token(ctx.as_ref(), account.refresh_token.as_deref());

                let fresh_tokens = serde_json::json!({
                    "accessToken": access_token,
                    "refreshToken": refresh_token,
                    "idToken": account.id_token,
                    "accessTokenExpiresAt": account.access_token_expires_at,
                    "refreshTokenExpiresAt": account.refresh_token_expires_at,
                    "scope": account.scope,
                });

                if let Some(acc_id) = linked_acc["id"].as_str() {
                    ctx.adapter.update_account_by_id(acc_id, fresh_tokens).await?;
                }
            }

            // Update email verification if needed
            if user_info.email_verified && user["emailVerified"].as_bool() != Some(true) {
                if email == user["email"].as_str().unwrap_or_default() {
                    ctx.adapter
                        .update_user(
                            user["id"].as_str().unwrap_or_default(),
                            serde_json::json!({ "emailVerified": true }),
                        )
                        .await?;
                }
            }
        }

        // Override user info if requested
        if opts.override_user_info {
            let mut update = serde_json::json!({
                "email": email,
            });
            if let Some(name) = &user_info.name {
                update["name"] = serde_json::Value::String(name.clone());
            }
            if let Some(image) = &user_info.image {
                update["image"] = serde_json::Value::String(image.clone());
            }
            let updated = ctx
                .adapter
                .update_user(user["id"].as_str().unwrap_or_default(), update)
                .await?;
            user_value = updated;
        } else {
            user_value = user;
        }
    } else {
        // No existing user — create new
        is_register = true;

        if opts.disable_sign_up {
            return Ok(OAuthUserResult::Error {
                error: "signup disabled".into(),
                is_register: false,
            });
        }

        let access_token = maybe_encrypt_token(ctx.as_ref(), account.access_token.as_deref());
        let refresh_token = maybe_encrypt_token(ctx.as_ref(), account.refresh_token.as_deref());

        let user_data = serde_json::json!({
            "email": email,
            "name": user_info.name.unwrap_or_default(),
            "image": user_info.image,
            "emailVerified": user_info.email_verified,
        });

        let account_data = serde_json::json!({
            "accessToken": access_token,
            "refreshToken": refresh_token,
            "idToken": account.id_token,
            "accessTokenExpiresAt": account.access_token_expires_at,
            "refreshTokenExpiresAt": account.refresh_token_expires_at,
            "scope": account.scope,
            "providerId": account.provider_id,
            "accountId": user_info.id,
        });

        let created_user = ctx.adapter.create_oauth_user(user_data, account_data).await?;
        user_value = created_user;
    }

    // Create session (adapter generates token, expiry, timestamps)
    let user_id = user_value["id"].as_str().unwrap_or_default();
    let session = ctx.adapter.create_session(
        user_id,
        None,
        Some(ctx.session_config.expires_in as i64),
    ).await?;

    Ok(OAuthUserResult::Success {
        user: user_value,
        session,
        is_register,
    })
}

// ─── Token Encryption ───────────────────────────────────────────

/// Optionally encrypt an OAuth token.
///
/// Matches TS `setTokenUtil`: if `encryptOAuthTokens` is enabled, encrypt the token
/// using the auth secret. Otherwise, return as-is.
fn maybe_encrypt_token(_ctx: &AuthContext, token: Option<&str>) -> Option<String> {
    // Token encryption is available but currently returns plaintext.
    // Full encryption via symmetric_encrypt would be wired here when
    // options.account.encryptOAuthTokens is supported.
    token.map(|t| t.to_string())
}

/// Decrypt an OAuth token if it was encrypted.
///
/// Matches TS `decryptOAuthToken`.
pub fn maybe_decrypt_token(_ctx: &AuthContext, token: Option<&str>) -> Option<String> {
    token.map(|t| t.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth_user_info_serde() {
        let info = OAuthUserInfo {
            id: "123".into(),
            email: "test@example.com".into(),
            name: Some("Test User".into()),
            image: None,
            email_verified: true,
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["email"], "test@example.com");
        assert_eq!(json["emailVerified"], true);
    }

    #[test]
    fn test_oauth_account_info_serde() {
        let info = OAuthAccountInfo {
            provider_id: "google".into(),
            account_id: "goog-123".into(),
            access_token: Some("at-xxx".into()),
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: Some("email,profile".into()),
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["providerId"], "google");
        assert_eq!(json["scope"], "email,profile");
    }

    #[test]
    fn test_maybe_encrypt_token() {
        // Without encryption, tokens pass through as-is
        assert_eq!(maybe_encrypt_token(&make_dummy_ctx(), Some("abc")), Some("abc".into()));
        assert_eq!(maybe_encrypt_token(&make_dummy_ctx(), None), None);
    }

    fn make_dummy_ctx() -> AuthContext {
        use crate::internal_adapter::tests::MockInternalAdapter;
        let options = better_auth_core::options::BetterAuthOptions::new("test-secret-that-is-long-enough-32");
        // We can't call AuthContext::new (returns Arc), so build manually for test
        AuthContext {
            app_name: "Better Auth".into(),
            secret: "test-secret-that-is-long-enough-32".into(),
            base_url: None,
            base_path: "/api/auth".into(),
            auth_cookies: crate::cookies::get_cookies(&options),
            trusted_origins: vec![],
            session_config: crate::context::SessionConfig {
                expires_in: 3600,
                update_age: 86400,
                fresh_age: 300,
                cookie_cache_enabled: false,
                cookie_refresh_cache: better_auth_core::options::CookieRefreshCacheConfig::Disabled,
                defer_session_refresh: false,
            },
            oauth_config: crate::context::OAuthConfig {
                store_state_strategy: "database".into(),
                skip_state_cookie_check: false,
            },
            password_config: crate::context::PasswordConfig {
                min_password_length: 8,
                max_password_length: 128,
            },
            adapter: Arc::new(MockInternalAdapter),
            hooks: crate::db::HookRegistry::new(),
            origin_check_config: crate::middleware::origin_check::OriginCheckConfig::default(),
            skip_csrf_check: false,
            rate_limiter: Arc::new(crate::middleware::rate_limiter::RateLimiter::new(
                crate::middleware::rate_limiter::RateLimitConfig::default(),
            )),
            plugin_registry: crate::plugin_runtime::PluginRegistry::new(),
            logger: better_auth_core::logger::AuthLogger::default(),
            async_hooks: better_auth_core::hooks::AsyncHookRegistry::new(),
            email_verification_config: crate::routes::email_verification::EmailVerificationConfig::default(),
            social_providers: std::collections::HashMap::new(),
            options,
        }
    }
}
