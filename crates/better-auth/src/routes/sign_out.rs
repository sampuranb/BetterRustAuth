// Sign-out route — maps to packages/better-auth/src/api/routes/sign-out.ts
//
// POST /sign-out
// 1. Read session token from cookie
// 2. Delete session from database
// 3. Delete session cookie
// 4. Return { success: true }

use std::sync::Arc;

use serde::Serialize;

use crate::context::AuthContext;
use crate::internal_adapter::AdapterError;

/// Sign-out response.
#[derive(Debug, Serialize)]
pub struct SignOutResponse {
    pub success: bool,
}

/// Sign-out result including cookies to delete.
#[derive(Debug)]
pub struct SignOutResult {
    pub response: SignOutResponse,
    /// List of cookie names that should be cleared on the response.
    pub cookies_to_delete: Vec<String>,
}

/// Handle sign-out.
///
/// Matches TS `signOut` endpoint:
/// 1. Delete the session from the database (ignoring errors — session may already be gone)
/// 2. Return the list of cookies to clear
///
/// The caller (Axum handler or framework integration) is responsible for
/// actually clearing the cookies on the HTTP response.
pub async fn handle_sign_out(
    ctx: Arc<AuthContext>,
    session_token: Option<&str>,
) -> Result<SignOutResult, AdapterError> {
    // Delete session from DB if token is present
    if let Some(token) = session_token {
        if !token.is_empty() {
            // Ignore errors — the session may have already expired or been deleted
            let _ = ctx.adapter.delete_session(token).await;
        }
    }

    // Build list of cookies to clear
    let cookies_to_delete = vec![
        ctx.auth_cookies.session_token.name.clone(),
        ctx.auth_cookies.session_data.name.clone(),
        ctx.auth_cookies.dont_remember_token.name.clone(),
    ];

    Ok(SignOutResult {
        response: SignOutResponse { success: true },
        cookies_to_delete,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal_adapter::tests::MockInternalAdapter;

    fn make_ctx() -> Arc<AuthContext> {
        let options = better_auth_core::options::BetterAuthOptions::new("test-secret-32-chars-long-enough");
        let auth_cookies = crate::cookies::get_cookies(&options);
        let session_config = crate::context::SessionConfig {
            expires_in: options.session.expires_in,
            update_age: options.session.update_age,
            fresh_age: options.session.fresh_age,
            cookie_cache_enabled: options.session.cookie_cache.enabled,
            cookie_refresh_cache: better_auth_core::options::CookieRefreshCacheConfig::Disabled,
            defer_session_refresh: false,
        };
        Arc::new(AuthContext {
            app_name: "Better Auth".into(),
            options,
            secret: "test-secret".into(),
            base_url: None,
            base_path: "/api/auth".into(),
            auth_cookies,
            trusted_origins: vec![],
            session_config,
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
            origin_check_config: Default::default(),
            skip_csrf_check: false,
            rate_limiter: Arc::new(crate::middleware::rate_limiter::RateLimiter::new(Default::default())),
            plugin_registry: crate::plugin_runtime::PluginRegistry::new(),
            logger: better_auth_core::logger::AuthLogger::default(),
            async_hooks: better_auth_core::hooks::AsyncHookRegistry::new(),
            email_verification_config: crate::routes::email_verification::EmailVerificationConfig::default(),
            social_providers: std::collections::HashMap::new(),
        })
    }

    #[tokio::test]
    async fn test_sign_out_returns_cookies_to_delete() {
        let ctx = make_ctx();
        let result = handle_sign_out(ctx, Some("some-token")).await.unwrap();
        assert!(result.response.success);
        assert!(!result.cookies_to_delete.is_empty());
    }

    #[tokio::test]
    async fn test_sign_out_handles_no_token() {
        let ctx = make_ctx();
        let result = handle_sign_out(ctx, None).await.unwrap();
        assert!(result.response.success);
    }
}
