// OAuth2 token utilities — maps to packages/better-auth/src/oauth2/utils.ts
//
// Token encryption/decryption for OAuth access and refresh tokens.

use crate::context::AuthContext;

/// Check if a string looks like encrypted data (hex-encoded).
fn is_likely_encrypted(token: &str) -> bool {
    !token.is_empty() && token.len() % 2 == 0 && token.chars().all(|c| c.is_ascii_hexdigit())
}

/// Encrypt an OAuth token using the auth secret.
///
/// Matches TS `setTokenUtil`: if `encryptOAuthTokens` is enabled in options,
/// encrypt the token using symmetric encryption. Otherwise, return as-is.
pub fn set_token(token: Option<&str>, _ctx: &AuthContext) -> Option<String> {
    // When options.account.encryptOAuthTokens is implemented:
    // if ctx.options.account.encrypt_oauth_tokens && token.is_some() {
    //     return Some(symmetric_encrypt(&ctx.secret, token.unwrap()));
    // }
    token.map(|t| t.to_string())
}

/// Decrypt an OAuth token.
///
/// Matches TS `decryptOAuthToken`: if the token looks like encrypted hex data
/// and `encryptOAuthTokens` is enabled, decrypt it.
pub fn decrypt_token(token: &str, _ctx: &AuthContext) -> String {
    if token.is_empty() {
        return token.to_string();
    }
    // When options.account.encryptOAuthTokens is implemented:
    // if ctx.options.account.encrypt_oauth_tokens && is_likely_encrypted(token) {
    //     return symmetric_decrypt(&ctx.secret, token);
    // }
    token.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_likely_encrypted() {
        assert!(is_likely_encrypted("abcdef1234"));
        assert!(!is_likely_encrypted("not-hex!@#"));
        assert!(!is_likely_encrypted(""));
        assert!(!is_likely_encrypted("abc")); // odd length
    }

    #[test]
    fn test_set_token_passthrough() {
        assert_eq!(set_token(Some("my-token"), &make_ctx()), Some("my-token".into()));
        assert_eq!(set_token(None, &make_ctx()), None);
    }

    #[test]
    fn test_decrypt_token_passthrough() {
        assert_eq!(decrypt_token("my-token", &make_ctx()), "my-token");
        assert_eq!(decrypt_token("", &make_ctx()), "");
    }

    fn make_ctx() -> AuthContext {
        use std::sync::Arc;
        use crate::internal_adapter::tests::MockInternalAdapter;
        let options = better_auth_core::options::BetterAuthOptions::new("test-secret-that-is-long-enough-32");
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
            options,
        }
    }
}
