// Auth context — maps to packages/core/src/types/context.ts
//
// Holds the fully-initialized auth configuration for request processing.
// In Rust we use Arc<AuthContext> shared across request handlers.

use std::sync::Arc;

use better_auth_core::hooks::AsyncHookRegistry;
use better_auth_core::logger::AuthLogger;
use better_auth_core::options::{BetterAuthOptions, CookieRefreshCacheConfig};

use crate::cookies::BetterAuthCookies;
use crate::db::HookRegistry;
use crate::internal_adapter::InternalAdapter;
use crate::middleware::origin_check::OriginCheckConfig;
use crate::middleware::rate_limiter::{RateLimitConfig, RateLimiter};
use crate::middleware::trusted_origins::is_trusted_origin;
use crate::plugin_runtime::PluginRegistry;
use crate::routes::email_verification::EmailVerificationConfig;

/// The fully-initialized auth context, shared across all request handlers.
///
/// Created once at startup from `BetterAuthOptions` + an `InternalAdapter`.
/// Passed to route handlers as `Arc<AuthContext>`.
///
/// Mirrors the TS `AuthContext` type from `@better-auth/core`.
pub struct AuthContext {
    /// The original configuration options.
    pub options: BetterAuthOptions,

    /// Application name for branding (default: "Better Auth").
    pub app_name: String,

    /// The secret key for signing/encryption.
    pub secret: String,

    /// The base URL for this auth instance.
    pub base_url: Option<String>,

    /// The base path for auth routes (e.g., "/api/auth").
    pub base_path: String,

    /// Pre-computed auth cookies.
    pub auth_cookies: BetterAuthCookies,

    /// Trusted origins for CORS/CSRF.
    pub trusted_origins: Vec<String>,

    /// Session configuration.
    pub session_config: SessionConfig,

    /// OAuth configuration.
    pub oauth_config: OAuthConfig,

    /// Password configuration (min/max length).
    pub password_config: PasswordConfig,

    /// The database adapter for user/session/account CRUD.
    pub adapter: Arc<dyn InternalAdapter>,

    /// Database lifecycle hooks (before/after CRUD operations).
    pub hooks: HookRegistry,

    /// Origin/CSRF check configuration.
    pub origin_check_config: OriginCheckConfig,

    /// Whether to skip CSRF checks entirely (from `advanced.disableCSRFCheck`).
    pub skip_csrf_check: bool,

    /// Rate limiter instance (thread-safe).
    pub rate_limiter: Arc<RateLimiter>,

    /// Plugin registry — all enabled plugins and their merged config.
    pub plugin_registry: PluginRegistry,

    /// Structured auth logger with level filtering and ANSI formatting.
    pub logger: AuthLogger,

    /// Async hooks for auth lifecycle events.
    pub async_hooks: AsyncHookRegistry,

    /// Email verification configuration.
    pub email_verification_config: EmailVerificationConfig,
}

// Manual Debug impl because dyn InternalAdapter is not Debug
impl std::fmt::Debug for AuthContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthContext")
            .field("app_name", &self.app_name)
            .field("secret", &"[REDACTED]")
            .field("base_url", &self.base_url)
            .field("base_path", &self.base_path)
            .field("session_config", &self.session_config)
            .field("oauth_config", &self.oauth_config)
            .field("password_config", &self.password_config)
            .field("skip_csrf_check", &self.skip_csrf_check)
            .field("hooks", &self.hooks)
            .field("logger", &self.logger)
            .field("async_hooks", &self.async_hooks)
            .finish()
    }
}

/// Pre-computed session configuration.
///
/// Mirrors TS `sessionConfig` in `AuthContext`.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Session TTL in seconds (default: 604800 = 7 days).
    pub expires_in: u64,
    /// How often to refresh session expiry in seconds (default: 86400 = 1 day).
    pub update_age: u64,
    /// Fresh session window in seconds (default: 86400 = 1 day).
    /// Operations requiring a "fresh" session check this.
    pub fresh_age: u64,
    /// Whether cookie caching is enabled.
    pub cookie_cache_enabled: bool,
    /// Cookie refresh cache config (for stateless setups).
    pub cookie_refresh_cache: CookieRefreshCacheConfig,
}

/// OAuth configuration resolved from options.
///
/// Mirrors TS `oauthConfig` in `AuthContext`.
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// Strategy for storing OAuth state: "database" or "cookie".
    pub store_state_strategy: String,
    /// Skip state cookie verification (insecure, dev/staging only).
    pub skip_state_cookie_check: bool,
}

/// Password configuration resolved from options.
///
/// Mirrors TS `password.config` in `AuthContext`.
#[derive(Debug, Clone)]
pub struct PasswordConfig {
    /// Minimum password length (default: 8).
    pub min_password_length: usize,
    /// Maximum password length (default: 128).
    pub max_password_length: usize,
}

impl AuthContext {
    /// Check if a URL is a trusted origin.
    ///
    /// Mirrors TS `ctx.isTrustedOrigin(url, settings)`.
    pub fn is_trusted_origin(&self, url: &str, allow_relative_paths: bool) -> bool {
        is_trusted_origin(url, &self.trusted_origins, allow_relative_paths)
    }

    /// Check if a plugin is enabled by ID.
    ///
    /// Mirrors TS `ctx.hasPlugin(id)`.
    pub fn has_plugin(&self, plugin_id: &str) -> bool {
        self.plugin_registry.has_plugin(plugin_id)
    }

    /// Create a new `AuthContext` from options and a database adapter.
    pub fn new(
        options: BetterAuthOptions,
        adapter: Arc<dyn InternalAdapter>,
    ) -> Arc<Self> {
        let secret = options.secret.clone();
        let base_url = options.base_url.clone();
        let base_path = options.base_path.clone();
        let app_name = options.app_name.clone().unwrap_or_else(|| "Better Auth".to_string());
        let auth_cookies = crate::cookies::get_cookies(&options);

        // Build trusted origins list
        let mut trusted_origins = options.trusted_origins.clone();
        if let Some(ref url) = base_url {
            if let Ok(parsed) = url::Url::parse(url) {
                let origin = parsed.origin().ascii_serialization();
                if !trusted_origins.contains(&origin) {
                    trusted_origins.push(origin);
                }
            }
        }

        let session_config = SessionConfig {
            expires_in: options.session.expires_in,
            update_age: options.session.update_age,
            fresh_age: options.session.fresh_age,
            cookie_cache_enabled: options.session.cookie_cache.enabled,
            cookie_refresh_cache: CookieRefreshCacheConfig::Disabled,
        };

        let oauth_config = OAuthConfig {
            store_state_strategy: format!("{:?}", options.oauth.store_state_strategy).to_lowercase(),
            skip_state_cookie_check: options.oauth.skip_state_cookie_check,
        };

        let password_config = PasswordConfig {
            min_password_length: options.email_and_password.min_password_length,
            max_password_length: options.email_and_password.max_password_length,
        };

        let skip_csrf_check = options.advanced.disable_csrf_check;

        let origin_check_config = OriginCheckConfig::default();
        let rate_limiter = Arc::new(RateLimiter::new(RateLimitConfig::default()));

        Arc::new(Self {
            options,
            app_name,
            secret,
            base_url,
            base_path,
            auth_cookies,
            trusted_origins,
            session_config,
            oauth_config,
            password_config,
            adapter,
            hooks: HookRegistry::new(),
            origin_check_config,
            skip_csrf_check,
            rate_limiter,
            plugin_registry: PluginRegistry::new(),
            logger: AuthLogger::default(),
            async_hooks: AsyncHookRegistry::new(),
            email_verification_config: EmailVerificationConfig::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal_adapter::tests::MockInternalAdapter;

    #[test]
    fn test_context_creation() {
        let options = BetterAuthOptions::new("test-secret-that-is-long-enough-32");
        let adapter = Arc::new(MockInternalAdapter);
        let ctx = AuthContext::new(options, adapter);
        assert_eq!(ctx.secret, "test-secret-that-is-long-enough-32");
        assert_eq!(ctx.base_path, "/api/auth");
        assert_eq!(ctx.app_name, "Better Auth");
    }

    #[test]
    fn test_context_custom_app_name() {
        let mut options = BetterAuthOptions::new("test-secret-that-is-long-enough-32");
        options.app_name = Some("My App".into());
        let adapter = Arc::new(MockInternalAdapter);
        let ctx = AuthContext::new(options, adapter);
        assert_eq!(ctx.app_name, "My App");
    }

    #[test]
    fn test_context_trusted_origins() {
        let mut options = BetterAuthOptions::new("test-secret-that-is-long-enough-32");
        options.base_url = Some("https://example.com".into());
        options.trusted_origins.push("https://app.example.com".into());

        let adapter = Arc::new(MockInternalAdapter);
        let ctx = AuthContext::new(options, adapter);
        assert!(ctx.trusted_origins.contains(&"https://example.com".to_string()));
        assert!(ctx.trusted_origins.contains(&"https://app.example.com".to_string()));
    }

    #[test]
    fn test_is_trusted_origin() {
        let mut options = BetterAuthOptions::new("test-secret-that-is-long-enough-32");
        options.base_url = Some("https://example.com".into());
        options.trusted_origins.push("https://app.example.com".into());

        let adapter = Arc::new(MockInternalAdapter);
        let ctx = AuthContext::new(options, adapter);
        assert!(ctx.is_trusted_origin("https://example.com/api", false));
        assert!(ctx.is_trusted_origin("https://app.example.com/callback", false));
        assert!(!ctx.is_trusted_origin("https://evil.com/api", false));
    }

    #[test]
    fn test_context_oauth_config() {
        let options = BetterAuthOptions::new("test-secret-that-is-long-enough-32");
        let adapter = Arc::new(MockInternalAdapter);
        let ctx = AuthContext::new(options, adapter);
        assert_eq!(ctx.oauth_config.store_state_strategy, "database");
        assert!(!ctx.oauth_config.skip_state_cookie_check);
    }

    #[test]
    fn test_context_password_config() {
        let options = BetterAuthOptions::new("test-secret-that-is-long-enough-32");
        let adapter = Arc::new(MockInternalAdapter);
        let ctx = AuthContext::new(options, adapter);
        assert_eq!(ctx.password_config.min_password_length, 8);
        assert_eq!(ctx.password_config.max_password_length, 128);
    }

    #[test]
    fn test_context_skip_csrf_check() {
        let mut options = BetterAuthOptions::new("test-secret-that-is-long-enough-32");
        options.advanced.disable_csrf_check = true;
        let adapter = Arc::new(MockInternalAdapter);
        let ctx = AuthContext::new(options, adapter);
        assert!(ctx.skip_csrf_check);
    }
}
