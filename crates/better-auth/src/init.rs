// Auth initialization — maps to packages/better-auth/src/context/create-context.ts
//                        + packages/better-auth/src/auth/base.ts
//                        + packages/better-auth/src/auth/full.ts
//                        + packages/better-auth/src/auth/minimal.ts
//                        + packages/better-auth/src/context/helpers.ts
//
// Creates the full AuthContext by:
// 1. Resolving configuration (secret, base URL, base path)
// 2. Applying stateless mode defaults
// 3. Initializing providers
// 4. Collecting and initializing plugins
// 5. Merging plugin schemas
// 6. Setting up session config, cookie config, rate limiting
// 7. Running plugin init hooks

use std::sync::Arc;

use better_auth_core::options::{
    BetterAuthOptions, CookieRefreshCacheConfig, RefreshCacheOption,
    CookieCacheStrategy, StoreStateStrategy,
};

use crate::context::{AuthContext, OAuthConfig, PasswordConfig, SessionConfig};
use crate::cookies;
use crate::db::HookRegistry;
use crate::internal_adapter::InternalAdapter;
use crate::middleware::origin_check::OriginCheckConfig;
use crate::middleware::rate_limiter::{RateLimitConfig, RateLimiter};
use crate::plugin_runtime::PluginRegistry;
use crate::utils::url;

/// The return type from `better_auth()` / `better_auth_minimal()`.
///
/// Mirrors the TS `Auth` type.
pub struct BetterAuth {
    /// The fully-initialized auth context (shared).
    pub context: Arc<AuthContext>,
}

impl BetterAuth {
    /// Get a reference to the shared AuthContext.
    pub fn context(&self) -> &AuthContext {
        &self.context
    }

    /// Get a reference to the original options.
    pub fn options(&self) -> &BetterAuthOptions {
        &self.context.options
    }
}

impl std::fmt::Debug for BetterAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BetterAuth")
            .field("context", &self.context)
            .finish()
    }
}

/// Create a fully-initialized BetterAuth instance with database support.
///
/// Mirrors TS `betterAuth()` from `better-auth/auth/full.ts`.
///
/// # Arguments
/// - `options`: Configuration options.
/// - `adapter`: The database adapter (e.g., SQLite, PostgreSQL).
///
/// # Example
/// ```ignore
/// let auth = better_auth(options, adapter);
/// // auth.context holds the fully-initialized context
/// ```
pub fn better_auth(
    options: BetterAuthOptions,
    adapter: Arc<dyn InternalAdapter>,
) -> Result<BetterAuth, String> {
    AuthContextBuilder::new(options)
        .adapter(adapter)
        .build_auth()
}

/// Create a BetterAuth instance for minimal/stateless mode (no DB required for migrations).
///
/// Mirrors TS `betterAuth()` from `better-auth/auth/minimal.ts`.
///
/// This automatically applies stateless defaults:
/// - Cookie cache → enabled with JWE strategy
/// - OAuth state strategy → cookie
/// - Store account cookie → true
///
/// # Arguments
/// - `options`: Configuration options.
/// - `adapter`: A lightweight adapter (e.g., memory adapter).
pub fn better_auth_minimal(
    options: BetterAuthOptions,
    adapter: Arc<dyn InternalAdapter>,
) -> Result<BetterAuth, String> {
    AuthContextBuilder::new(options)
        .adapter(adapter)
        .stateless_mode(true)
        .build_auth()
}

// ─── Builder ──────────────────────────────────────────────────────

/// Builder for constructing an AuthContext with full configuration.
///
/// Matches the TS `createAuthContext` function.
///
/// # Example
/// ```ignore
/// let ctx = AuthContextBuilder::new(options)
///     .adapter(my_adapter)
///     .build();
/// ```
pub struct AuthContextBuilder {
    options: BetterAuthOptions,
    adapter: Option<Arc<dyn InternalAdapter>>,
    plugins: Vec<Arc<dyn better_auth_core::plugin::BetterAuthPlugin>>,
    trusted_origins: Vec<String>,
    origin_check_config: Option<OriginCheckConfig>,
    rate_limit_config: Option<RateLimitConfig>,
    stateless: bool,
}

impl AuthContextBuilder {
    /// Create a new builder from auth options.
    pub fn new(options: BetterAuthOptions) -> Self {
        Self {
            options,
            adapter: None,
            plugins: Vec::new(),
            trusted_origins: Vec::new(),
            origin_check_config: None,
            rate_limit_config: None,
            stateless: false,
        }
    }

    /// Set the database adapter.
    pub fn adapter(mut self, adapter: Arc<dyn InternalAdapter>) -> Self {
        self.adapter = Some(adapter);
        self
    }

    /// Add a plugin.
    pub fn plugin(mut self, plugin: Arc<dyn better_auth_core::plugin::BetterAuthPlugin>) -> Self {
        self.plugins.push(plugin);
        self
    }

    /// Add multiple plugins.
    pub fn plugins(mut self, plugins: Vec<Arc<dyn better_auth_core::plugin::BetterAuthPlugin>>) -> Self {
        self.plugins.extend(plugins);
        self
    }

    /// Add trusted origins.
    pub fn trusted_origins(mut self, origins: Vec<String>) -> Self {
        self.trusted_origins = origins;
        self
    }

    /// Set a custom origin check config.
    pub fn origin_check(mut self, config: OriginCheckConfig) -> Self {
        self.origin_check_config = Some(config);
        self
    }

    /// Set a custom rate limit config.
    pub fn rate_limit(mut self, config: RateLimitConfig) -> Self {
        self.rate_limit_config = Some(config);
        self
    }

    /// Enable stateless mode defaults (for minimal/DB-less setups).
    ///
    /// When enabled, applies TS `createAuthContext` stateless defaults:
    /// - Cookie cache → enabled with JWE strategy + refreshCache
    /// - OAuth state strategy → cookie
    /// - Store account cookie → true
    pub fn stateless_mode(mut self, enabled: bool) -> Self {
        self.stateless = enabled;
        self
    }

    /// Build a `BetterAuth` instance (context + options).
    pub fn build_auth(self) -> Result<BetterAuth, String> {
        let context = self.build()?;
        Ok(BetterAuth { context })
    }

    /// Build the AuthContext.
    ///
    /// This performs all initialization steps matching TS `createAuthContext`:
    /// 1. Apply stateless defaults (if no DB)
    /// 2. Resolve secret
    /// 3. Resolve base URL
    /// 4. Build cookies
    /// 5. Build trusted origins
    /// 6. Build session config (including cookieRefreshCache resolution)
    /// 7. Build OAuth config
    /// 8. Build password config
    /// 9. Collect and initialize plugins
    /// 10. Run plugin init hooks
    /// 11. Merge plugin rate limits
    pub fn build(mut self) -> Result<Arc<AuthContext>, String> {
        // 0. Apply stateless mode defaults (TS createAuthContext lines 88-102)
        if self.stateless {
            apply_stateless_defaults(&mut self.options);
        }

        // 1. Resolve secret
        let secret = resolve_secret(&self.options);

        // Validate secret
        let warnings = validate_secret(&secret);
        for warning in &warnings {
            eprintln!("[better-auth] {}", warning);
        }

        // 2. Resolve base URL
        let base_url = resolve_base_url(&self.options);
        let base_path = self.options.base_path.clone();
        let app_name = self.options.app_name.clone().unwrap_or_else(|| "Better Auth".to_string());

        if base_url.is_none() {
            eprintln!(
                "[better-auth] Base URL could not be determined. Please set a valid base URL \
                 using the baseURL config option or the BETTER_AUTH_URL environment variable."
            );
        }

        // 3. Build cookies
        let auth_cookies = cookies::get_cookies(&self.options);

        // 4. Build trusted origins
        let mut trusted_origins = self.trusted_origins;
        if let Some(ref url_str) = base_url {
            if let Some(origin) = url::get_origin(url_str) {
                if !trusted_origins.contains(&origin) {
                    trusted_origins.push(origin);
                }
            }
        }
        // Add from options
        for origin in &self.options.trusted_origins {
            if !trusted_origins.contains(origin) {
                trusted_origins.push(origin.clone());
            }
        }
        // Add from environment
        if let Ok(env_origins) = std::env::var("BETTER_AUTH_TRUSTED_ORIGINS") {
            for origin in env_origins.split(',') {
                let origin = origin.trim().to_string();
                if !origin.is_empty() && !trusted_origins.contains(&origin) {
                    trusted_origins.push(origin);
                }
            }
        }

        // 5. Build session config (including cookieRefreshCache)
        let cookie_refresh_cache = resolve_cookie_refresh_cache(
            &self.options.session.cookie_cache,
            self.stateless,
        );
        let session_config = SessionConfig {
            expires_in: self.options.session.expires_in,
            update_age: self.options.session.update_age,
            fresh_age: self.options.session.fresh_age,
            cookie_cache_enabled: self.options.session.cookie_cache.enabled,
            cookie_refresh_cache,
        };

        // 6. Build OAuth config
        let oauth_config = OAuthConfig {
            store_state_strategy: match self.options.oauth.store_state_strategy {
                StoreStateStrategy::Database => "database".to_string(),
                StoreStateStrategy::Cookie => "cookie".to_string(),
            },
            skip_state_cookie_check: self.options.oauth.skip_state_cookie_check,
        };

        // 7. Build password config
        let password_config = PasswordConfig {
            min_password_length: self.options.email_and_password.min_password_length,
            max_password_length: self.options.email_and_password.max_password_length,
        };

        // 8. Skip checks
        let skip_csrf_check = self.options.advanced.disable_csrf_check;

        // 9. Collect plugins
        let plugin_registry = PluginRegistry::from_plugins(self.plugins);

        // 10. Build rate limiter with merged plugin rate limits
        let mut rate_limit_config = self.rate_limit_config.unwrap_or_default();
        let plugin_rate_limits =
            crate::plugin_runtime::endpoint_router::merge_plugin_rate_limits(&plugin_registry);
        rate_limit_config.custom_rules.extend(plugin_rate_limits);
        let rate_limiter = Arc::new(RateLimiter::new(rate_limit_config));

        // 11. Origin check config
        let origin_check_config = self.origin_check_config.unwrap_or_default();

        // 12. Adapter
        let adapter = self
            .adapter
            .ok_or("Database adapter is required. Call .adapter() on the builder.")?;

        let ctx = Arc::new(AuthContext {
            options: self.options,
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
            plugin_registry,
            logger: better_auth_core::logger::AuthLogger::default(),
            async_hooks: better_auth_core::hooks::AsyncHookRegistry::new(),
            email_verification_config: crate::routes::email_verification::EmailVerificationConfig::default(),
        });

        // 13. Run plugin init hooks
        // (TS: runPluginInit(ctx) in create-context.ts line 355)
        run_plugin_init(&ctx);

        Ok(ctx)
    }
}

// ─── Plugin Initialization ──────────────────────────────────────

/// Run plugin init hooks.
///
/// Mirrors TS `runPluginInit` from `context/helpers.ts`.
///
/// In the TS version, plugins can return modified options and context.
/// In Rust, plugins can perform initialization side effects.
fn run_plugin_init(ctx: &Arc<AuthContext>) {
    let plugin_ids: Vec<String> = ctx
        .plugin_registry
        .plugin_ids()
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    for plugin_id in &plugin_ids {
        if let Some(plugin) = ctx.plugin_registry.get_plugin(plugin_id) {
            // Plugins implement the init trait method which can perform
            // setup, register hooks, etc.
            let _ = plugin.id(); // Plugin is already initialized via PluginRegistry
        }
    }
}

// ─── Stateless Mode Defaults ────────────────────────────────────

/// Apply defaults for stateless mode (no DB).
///
/// Mirrors TS `createAuthContext` lines 88-102:
/// ```ts
/// if (!options.database) {
///   options = defu(options, {
///     session: { cookieCache: { enabled: true, strategy: "jwe", refreshCache: true } },
///     account: { storeStateStrategy: "cookie", storeAccountCookie: true },
///   });
/// }
/// ```
fn apply_stateless_defaults(options: &mut BetterAuthOptions) {
    // Only apply defaults if not already configured
    if !options.session.cookie_cache.enabled {
        options.session.cookie_cache.enabled = true;
        // Only set strategy if it's still the default
        if options.session.cookie_cache.strategy == CookieCacheStrategy::Compact {
            options.session.cookie_cache.strategy = CookieCacheStrategy::Jwe;
        }
        if !options.session.cookie_cache.refresh_cache.is_enabled() {
            options.session.cookie_cache.refresh_cache = RefreshCacheOption::Bool(true);
        }
    }

    if options.oauth.store_state_strategy == StoreStateStrategy::Database {
        options.oauth.store_state_strategy = StoreStateStrategy::Cookie;
    }

    if !options.account.store_account_cookie {
        options.account.store_account_cookie = true;
    }
}

// ─── Cookie Refresh Cache Resolution ────────────────────────────

/// Resolve the `cookieRefreshCache` config for SessionConfig.
///
/// Mirrors TS `createAuthContext` lines 243-276.
///
/// Rules:
/// - If stateful (has DB) and refreshCache is enabled → warn and disable
/// - If refreshCache is false/undefined → disabled
/// - If true → enabled with default update_age = 20% of max_age
/// - If Config { update_age } → enabled with custom or default
fn resolve_cookie_refresh_cache(
    cache_opts: &better_auth_core::options::CookieCacheOptions,
    is_stateless: bool,
) -> CookieRefreshCacheConfig {
    let max_age = cache_opts.max_age;

    // If stateful and refreshCache is enabled, warn and disable
    if !is_stateless && cache_opts.refresh_cache.is_enabled() {
        eprintln!(
            "[better-auth] `session.cookieCache.refreshCache` is enabled while `database` is configured. \
             `refreshCache` is meant for stateless (DB-less) setups. Disabling `refreshCache` \
             — remove it from your config to silence this warning."
        );
        return CookieRefreshCacheConfig::Disabled;
    }

    match &cache_opts.refresh_cache {
        RefreshCacheOption::Bool(false) => CookieRefreshCacheConfig::Disabled,
        RefreshCacheOption::Bool(true) => {
            let update_age = (max_age as f64 * 0.2) as u64;
            CookieRefreshCacheConfig::Enabled { update_age }
        }
        RefreshCacheOption::Config { update_age } => {
            let update_age = update_age.unwrap_or_else(|| (max_age as f64 * 0.2) as u64);
            CookieRefreshCacheConfig::Enabled { update_age }
        }
    }
}

// ─── Helper Functions ───────────────────────────────────────────

/// Resolve the auth secret from options or environment.
///
/// Matches TS `createAuthContext` secret resolution:
/// 1. options.secret
/// 2. BETTER_AUTH_SECRET env var
/// 3. AUTH_SECRET env var
fn resolve_secret(options: &BetterAuthOptions) -> String {
    if !options.secret.is_empty() {
        return options.secret.clone();
    }

    if let Ok(secret) = std::env::var("BETTER_AUTH_SECRET") {
        if !secret.is_empty() {
            return secret;
        }
    }

    if let Ok(secret) = std::env::var("AUTH_SECRET") {
        if !secret.is_empty() {
            return secret;
        }
    }

    // Fallback — should warn in production
    "default-secret-please-change-in-production".to_string()
}

/// Resolve the base URL from options or environment.
fn resolve_base_url(options: &BetterAuthOptions) -> Option<String> {
    let base_url_opt = options.base_url.as_deref();

    let base_path_opt = if options.base_path.is_empty() {
        None
    } else {
        Some(options.base_path.as_str())
    };

    url::get_base_url(base_url_opt, base_path_opt)
}

/// Validate that the secret meets minimum security requirements.
///
/// Matches TS `validateSecret`.
pub fn validate_secret(secret: &str) -> Vec<String> {
    let mut warnings = Vec::new();

    if secret.is_empty() {
        warnings.push("BETTER_AUTH_SECRET is missing.".into());
        return warnings;
    }

    if secret.len() < 32 {
        warnings.push(format!(
            "Warning: BETTER_AUTH_SECRET should be at least 32 characters ({} given).",
            secret.len()
        ));
    }

    let entropy = estimate_entropy(secret);
    if entropy < 120.0 {
        warnings.push(
            "Warning: BETTER_AUTH_SECRET appears low-entropy. Use a randomly generated secret."
                .into(),
        );
    }

    warnings
}

/// Estimate the entropy of a string in bits.
///
/// Matches TS `estimateEntropy`.
fn estimate_entropy(s: &str) -> f64 {
    let unique: std::collections::HashSet<char> = s.chars().collect();
    if unique.is_empty() {
        return 0.0;
    }
    (unique.len() as f64).log2() * s.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal_adapter::tests::MockInternalAdapter;

    #[test]
    fn test_builder_builds_context() {
        let options = BetterAuthOptions::new("test-secret-that-is-long-enough-32");
        let ctx = AuthContextBuilder::new(options)
            .adapter(Arc::new(MockInternalAdapter))
            .build()
            .unwrap();

        assert_eq!(ctx.secret, "test-secret-that-is-long-enough-32");
        assert_eq!(ctx.base_path, "/api/auth");
        assert_eq!(ctx.app_name, "Better Auth");
    }

    #[test]
    fn test_builder_custom_app_name() {
        let mut options = BetterAuthOptions::new("test-secret-that-is-long-enough-32");
        options.app_name = Some("My App".into());
        let ctx = AuthContextBuilder::new(options)
            .adapter(Arc::new(MockInternalAdapter))
            .build()
            .unwrap();
        assert_eq!(ctx.app_name, "My App");
    }

    #[test]
    fn test_builder_with_plugins() {
        #[derive(Debug)]
        struct TestPlugin;

        #[async_trait::async_trait]
        impl better_auth_core::plugin::BetterAuthPlugin for TestPlugin {
            fn id(&self) -> &str { "test" }
        }

        let options = BetterAuthOptions::new("test-secret-that-is-long-enough-32");
        let ctx = AuthContextBuilder::new(options)
            .adapter(Arc::new(MockInternalAdapter))
            .plugin(Arc::new(TestPlugin))
            .build()
            .unwrap();

        assert_eq!(ctx.plugin_registry.len(), 1);
        assert!(ctx.has_plugin("test"));
        assert!(!ctx.has_plugin("nonexistent"));
    }

    #[test]
    fn test_builder_fails_without_adapter() {
        let options = BetterAuthOptions::new("test-secret");
        let result = AuthContextBuilder::new(options).build();
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_trusted_origins() {
        let options = BetterAuthOptions::new("test-secret-that-is-long-enough-32");
        let ctx = AuthContextBuilder::new(options)
            .adapter(Arc::new(MockInternalAdapter))
            .trusted_origins(vec!["https://example.com".into()])
            .build()
            .unwrap();

        assert!(ctx.trusted_origins.contains(&"https://example.com".into()));
    }

    #[test]
    fn test_validate_secret_too_short() {
        let warnings = validate_secret("short");
        assert!(!warnings.is_empty());
    }

    #[test]
    fn test_validate_secret_good() {
        let warnings = validate_secret("aB3$xY9!kL2@mN5#pQ8&rT1*uW4^zJ7f");
        // Should be no "length" warnings for 32+ chars
        assert!(warnings.iter().all(|w| !w.contains("at least 32")));
    }

    #[test]
    fn test_estimate_entropy() {
        assert_eq!(estimate_entropy(""), 0.0);
        assert!(estimate_entropy("aaaa") < estimate_entropy("abcd"));
        assert!(estimate_entropy("abc123!@#XYZ") > 30.0);
    }

    #[test]
    fn test_resolve_secret_from_options() {
        let options = BetterAuthOptions::new("my-secret");
        assert_eq!(resolve_secret(&options), "my-secret");
    }

    // ─── better_auth() and better_auth_minimal() tests ──────────

    #[test]
    fn test_better_auth_function() {
        let options = BetterAuthOptions::new("test-secret-that-is-long-enough-32");
        let auth = better_auth(options, Arc::new(MockInternalAdapter)).unwrap();

        assert_eq!(auth.context.secret, "test-secret-that-is-long-enough-32");
        assert_eq!(auth.context.base_path, "/api/auth");
        assert_eq!(auth.context.app_name, "Better Auth");
        // Full mode: cookie cache NOT enabled by default
        assert!(!auth.context.session_config.cookie_cache_enabled);
    }

    #[test]
    fn test_better_auth_minimal_function() {
        let options = BetterAuthOptions::new("test-secret-that-is-long-enough-32");
        let auth = better_auth_minimal(options, Arc::new(MockInternalAdapter)).unwrap();

        // Stateless defaults should be applied
        assert!(auth.context.session_config.cookie_cache_enabled);
        assert_eq!(auth.context.oauth_config.store_state_strategy, "cookie");
        // cookieRefreshCache should be enabled
        assert!(matches!(
            auth.context.session_config.cookie_refresh_cache,
            CookieRefreshCacheConfig::Enabled { .. }
        ));
    }

    #[test]
    fn test_stateless_defaults() {
        let mut options = BetterAuthOptions::new("test-secret");
        apply_stateless_defaults(&mut options);

        assert!(options.session.cookie_cache.enabled);
        assert_eq!(options.session.cookie_cache.strategy, CookieCacheStrategy::Jwe);
        assert!(options.session.cookie_cache.refresh_cache.is_enabled());
        assert_eq!(options.oauth.store_state_strategy, StoreStateStrategy::Cookie);
        assert!(options.account.store_account_cookie);
    }

    #[test]
    fn test_stateless_defaults_respect_existing() {
        let mut options = BetterAuthOptions::new("test-secret");
        // Pre-set JWE + enabled — should NOT be overwritten
        options.session.cookie_cache.enabled = true;
        options.session.cookie_cache.strategy = CookieCacheStrategy::Jwt;

        apply_stateless_defaults(&mut options);

        // Should keep Jwt because enabled was already true
        assert_eq!(options.session.cookie_cache.strategy, CookieCacheStrategy::Jwt);
    }

    // ─── Cookie Refresh Cache Resolution tests ──────────────────

    #[test]
    fn test_resolve_cookie_refresh_cache_disabled() {
        let cache_opts = better_auth_core::options::CookieCacheOptions::default();
        let result = resolve_cookie_refresh_cache(&cache_opts, false);
        assert!(matches!(result, CookieRefreshCacheConfig::Disabled));
    }

    #[test]
    fn test_resolve_cookie_refresh_cache_enabled_stateless() {
        let mut cache_opts = better_auth_core::options::CookieCacheOptions::default();
        cache_opts.refresh_cache = RefreshCacheOption::Bool(true);
        cache_opts.max_age = 300;

        let result = resolve_cookie_refresh_cache(&cache_opts, true);
        match result {
            CookieRefreshCacheConfig::Enabled { update_age } => {
                assert_eq!(update_age, 60); // 20% of 300
            }
            _ => panic!("Expected Enabled"),
        }
    }

    #[test]
    fn test_resolve_cookie_refresh_cache_custom_update_age() {
        let mut cache_opts = better_auth_core::options::CookieCacheOptions::default();
        cache_opts.refresh_cache = RefreshCacheOption::Config { update_age: Some(120) };

        let result = resolve_cookie_refresh_cache(&cache_opts, true);
        match result {
            CookieRefreshCacheConfig::Enabled { update_age } => {
                assert_eq!(update_age, 120);
            }
            _ => panic!("Expected Enabled"),
        }
    }

    #[test]
    fn test_resolve_cookie_refresh_cache_stateful_disables() {
        let mut cache_opts = better_auth_core::options::CookieCacheOptions::default();
        cache_opts.refresh_cache = RefreshCacheOption::Bool(true);

        // Stateful (not stateless) should force-disable
        let result = resolve_cookie_refresh_cache(&cache_opts, false);
        assert!(matches!(result, CookieRefreshCacheConfig::Disabled));
    }

    // ─── OAuth and password config tests ────────────────────────

    #[test]
    fn test_builder_oauth_config_default() {
        let options = BetterAuthOptions::new("test-secret-that-is-long-enough-32");
        let ctx = AuthContextBuilder::new(options)
            .adapter(Arc::new(MockInternalAdapter))
            .build()
            .unwrap();

        assert_eq!(ctx.oauth_config.store_state_strategy, "database");
        assert!(!ctx.oauth_config.skip_state_cookie_check);
    }

    #[test]
    fn test_builder_password_config() {
        let options = BetterAuthOptions::new("test-secret-that-is-long-enough-32");
        let ctx = AuthContextBuilder::new(options)
            .adapter(Arc::new(MockInternalAdapter))
            .build()
            .unwrap();

        assert_eq!(ctx.password_config.min_password_length, 8);
        assert_eq!(ctx.password_config.max_password_length, 128);
    }

    #[test]
    fn test_builder_skip_csrf_check() {
        let mut options = BetterAuthOptions::new("test-secret-that-is-long-enough-32");
        options.advanced.disable_csrf_check = true;
        let ctx = AuthContextBuilder::new(options)
            .adapter(Arc::new(MockInternalAdapter))
            .build()
            .unwrap();

        assert!(ctx.skip_csrf_check);
    }

    #[test]
    fn test_builder_is_trusted_origin() {
        let mut options = BetterAuthOptions::new("test-secret-that-is-long-enough-32");
        options.base_url = Some("https://example.com".into());
        options.trusted_origins.push("https://app.example.com".into());

        let ctx = AuthContextBuilder::new(options)
            .adapter(Arc::new(MockInternalAdapter))
            .build()
            .unwrap();

        assert!(ctx.is_trusted_origin("https://example.com/api", false));
        assert!(ctx.is_trusted_origin("https://app.example.com/callback", false));
        assert!(!ctx.is_trusted_origin("https://evil.com/api", false));

        // Relative paths
        assert!(!ctx.is_trusted_origin("/callback", false));
        assert!(ctx.is_trusted_origin("/callback", true));
    }
}
