// BetterAuthOptions — the main configuration struct.
//
// Maps to: packages/core/src/types/init-options.ts (1440 lines)
// This is a comprehensive builder capturing every configurable option
// from the TypeScript version.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Top-level configuration for Better Auth.
///
/// Mirrors the TypeScript `BetterAuthOptions` interface exactly.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BetterAuthOptions {
    /// Secret key for signing JWTs, cookies, etc. (min 32 chars in production).
    pub secret: String,

    /// Base URL of the auth server (e.g., "https://example.com").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,

    /// Path prefix for all auth routes (default: "/api/auth").
    #[serde(default = "default_base_path")]
    pub base_path: String,

    /// App name for branding in emails etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,

    /// Email and password authentication configuration.
    #[serde(default)]
    pub email_and_password: EmailAndPasswordOptions,

    /// Session management configuration.
    #[serde(default)]
    pub session: SessionOptions,

    /// Account linking and management configuration.
    #[serde(default)]
    pub account: AccountOptions,

    /// Email verification configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verification: Option<EmailVerificationOptions>,

    /// Rate limiting configuration.
    #[serde(default)]
    pub rate_limit: RateLimitOptions,

    /// User management configuration.
    #[serde(default)]
    pub user: UserOptions,

    /// Trusted origins for CORS/CSRF validation.
    /// Can be a list of origins, supporting wildcards (e.g., "*.example.com").
    #[serde(default)]
    pub trusted_origins: Vec<String>,

    /// Advanced configuration options.
    #[serde(default)]
    pub advanced: AdvancedOptions,

    /// Social provider configurations.
    /// Key is the provider ID (e.g., "google", "github").
    #[serde(default)]
    pub social_providers: HashMap<String, serde_json::Value>,

    /// Plugin instances (registered at runtime).
    #[serde(skip)]
    pub plugins: Vec<Box<dyn crate::plugin::BetterAuthPlugin>>,

    /// Error handling configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_api_error: Option<OnApiErrorOptions>,

    /// OAuth2 configuration.
    #[serde(default)]
    pub oauth: OAuthOptions,
}

fn default_base_path() -> String {
    "/api/auth".to_string()
}

impl Default for BetterAuthOptions {
    fn default() -> Self {
        Self {
            secret: String::new(),
            base_url: None,
            base_path: default_base_path(),
            app_name: None,
            email_and_password: EmailAndPasswordOptions::default(),
            session: SessionOptions::default(),
            account: AccountOptions::default(),
            email_verification: None,
            rate_limit: RateLimitOptions::default(),
            user: UserOptions::default(),
            trusted_origins: Vec::new(),
            advanced: AdvancedOptions::default(),
            social_providers: HashMap::new(),
            plugins: Vec::new(),
            on_api_error: None,
            oauth: OAuthOptions::default(),
        }
    }
}

impl BetterAuthOptions {
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            ..Default::default()
        }
    }

    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    pub fn base_path(mut self, path: impl Into<String>) -> Self {
        self.base_path = path.into();
        self
    }

    pub fn enable_email_password(mut self) -> Self {
        self.email_and_password.enabled = true;
        self
    }

    pub fn add_plugin(mut self, plugin: Box<dyn crate::plugin::BetterAuthPlugin>) -> Self {
        self.plugins.push(plugin);
        self
    }
}

// ─── Email & Password Options ────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailAndPasswordOptions {
    /// Enable email/password authentication (default: false).
    #[serde(default)]
    pub enabled: bool,

    /// Minimum password length (default: 8).
    #[serde(default = "default_min_password_length")]
    pub min_password_length: usize,

    /// Maximum password length (default: 128).
    #[serde(default = "default_max_password_length")]
    pub max_password_length: usize,

    /// Auto sign-in after successful signup (default: true).
    #[serde(default = "default_true")]
    pub auto_sign_in: bool,

    /// Require email verification before allowing sign-in (default: false).
    #[serde(default)]
    pub require_email_verification: bool,

    /// Send email verification on sign-in if not verified (default: false).
    #[serde(default)]
    pub send_on_sign_in: bool,

    /// Disable signup (only allow sign-in for existing users).
    #[serde(default)]
    pub disable_signup: bool,
}

fn default_min_password_length() -> usize { 8 }
fn default_max_password_length() -> usize { 128 }
fn default_true() -> bool { true }

impl Default for EmailAndPasswordOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            min_password_length: default_min_password_length(),
            max_password_length: default_max_password_length(),
            auto_sign_in: true,
            require_email_verification: false,
            send_on_sign_in: false,
            disable_signup: false,
        }
    }
}

// ─── Session Options ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionOptions {
    /// Session TTL in seconds (default: 604800 = 7 days).
    #[serde(default = "default_session_expires_in")]
    pub expires_in: u64,

    /// How often to refresh session expiry in seconds (default: 86400 = 1 day).
    #[serde(default = "default_session_update_age")]
    pub update_age: u64,

    /// Fresh session window in seconds (default: 600 = 10 minutes).
    /// Operations requiring a "fresh" session check this.
    #[serde(default = "default_session_fresh_age")]
    pub fresh_age: u64,

    /// Cookie cache configuration for stateless session reads.
    #[serde(default)]
    pub cookie_cache: CookieCacheOptions,
}

fn default_session_expires_in() -> u64 { 604_800 } // 7 days
fn default_session_update_age() -> u64 { 86_400 } // 1 day
fn default_session_fresh_age() -> u64 { 600 } // 10 minutes

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            expires_in: default_session_expires_in(),
            update_age: default_session_update_age(),
            fresh_age: default_session_fresh_age(),
            cookie_cache: CookieCacheOptions::default(),
        }
    }
}

/// Cookie cache configuration — allows caching session data in a cookie
/// to avoid DB lookups on every request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CookieCacheOptions {
    /// Enable cookie caching (default: false).
    #[serde(default)]
    pub enabled: bool,

    /// Cookie cache TTL in seconds (default: 300 = 5 minutes).
    #[serde(default = "default_cookie_cache_max_age")]
    pub max_age: u64,

    /// Strategy for encoding session data in the cookie.
    #[serde(default)]
    pub strategy: CookieCacheStrategy,

    /// Version string for cache invalidation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Whether to refresh the cookie cache (for stateless/DB-less setups).
    /// When true, uses default update_age = 20% of max_age.
    /// When an object, allows custom update_age.
    #[serde(default)]
    pub refresh_cache: RefreshCacheOption,
}

fn default_cookie_cache_max_age() -> u64 { 300 }

impl Default for CookieCacheOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            max_age: default_cookie_cache_max_age(),
            strategy: CookieCacheStrategy::default(),
            version: None,
            refresh_cache: RefreshCacheOption::default(),
        }
    }
}

/// Configuration for refresh cache behavior.
/// Mirrors TS `refreshCache` option which can be bool | { updateAge?: number }.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RefreshCacheOption {
    /// Simple boolean toggle.
    Bool(bool),
    /// Custom config with update_age.
    Config { update_age: Option<u64> },
}

impl Default for RefreshCacheOption {
    fn default() -> Self {
        Self::Bool(false)
    }
}

impl RefreshCacheOption {
    /// Whether refresh cache is enabled (any non-false value).
    pub fn is_enabled(&self) -> bool {
        match self {
            Self::Bool(b) => *b,
            Self::Config { .. } => true,
        }
    }
}

/// Resolved cookie refresh cache configuration for runtime use.
/// Matches TS `sessionConfig.cookieRefreshCache`.
#[derive(Debug, Clone)]
pub enum CookieRefreshCacheConfig {
    /// Disabled.
    Disabled,
    /// Enabled with a specific update_age.
    Enabled { update_age: u64 },
}

/// Strategy for encoding session data in cookies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CookieCacheStrategy {
    /// Base64url + HMAC-SHA256 signature (most compact, default).
    #[default]
    Compact,
    /// JWT with HS256 signature (no encryption).
    Jwt,
    /// JWE with A256CBC-HS512 encryption via HKDF.
    Jwe,
}

// ─── Account Options ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountOptions {
    /// Account linking configuration.
    #[serde(default)]
    pub account_linking: AccountLinkingOptions,

    /// Update OAuth tokens on each sign-in (default: true).
    #[serde(default = "default_true")]
    pub update_account_on_sign_in: bool,

    /// Encrypt stored OAuth tokens with symmetric encryption (default: false).
    #[serde(default)]
    pub encrypt_o_auth_tokens: bool,

    /// Store current account data in a cookie (default: false).
    #[serde(default)]
    pub store_account_cookie: bool,

    /// Allow unlinking all accounts (leaving user with no login method).
    #[serde(default)]
    pub allow_unlinking_all: bool,
}

impl Default for AccountOptions {
    fn default() -> Self {
        Self {
            account_linking: AccountLinkingOptions::default(),
            update_account_on_sign_in: true,
            encrypt_o_auth_tokens: false,
            store_account_cookie: false,
            allow_unlinking_all: false,
        }
    }
}

/// Account linking configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountLinkingOptions {
    /// Enable automatic account linking (default: true).
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Providers whose email claims are trusted for auto-linking.
    #[serde(default)]
    pub trusted_providers: Vec<String>,

    /// Disable implicit (auto) linking — require explicit user action.
    #[serde(default)]
    pub disable_implicit_linking: bool,

    /// Allow linking accounts with different emails.
    #[serde(default)]
    pub allow_different_emails: bool,
}

impl Default for AccountLinkingOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            trusted_providers: Vec::new(),
            disable_implicit_linking: false,
            allow_different_emails: false,
        }
    }
}

// ─── Email Verification Options ──────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailVerificationOptions {
    /// Whether to send verification email on signup (default: false).
    #[serde(default)]
    pub send_on_sign_up: bool,

    /// Auto-sign-in after email verification (default: false).
    #[serde(default)]
    pub auto_sign_in_after_verification: bool,

    /// Verification token expiry in seconds (default: 3600 = 1 hour).
    #[serde(default = "default_verification_expiry")]
    pub expires_in: u64,
}

fn default_verification_expiry() -> u64 { 3600 }

// ─── Rate Limit Options ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitOptions {
    /// Enable rate limiting (default: true).
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Time window in seconds (default: 60).
    #[serde(default = "default_rate_limit_window")]
    pub window: u64,

    /// Maximum requests per window (default: 100).
    #[serde(default = "default_rate_limit_max")]
    pub max: u64,
}

fn default_rate_limit_window() -> u64 { 60 }
fn default_rate_limit_max() -> u64 { 100 }

impl Default for RateLimitOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            window: default_rate_limit_window(),
            max: default_rate_limit_max(),
        }
    }
}

// ─── User Options ────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserOptions {
    /// Delete user configuration.
    #[serde(default)]
    pub delete_user: DeleteUserOptions,

    /// Change email configuration.
    #[serde(default)]
    pub change_email: ChangeEmailOptions,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteUserOptions {
    /// Enable user self-deletion (default: false).
    #[serde(default)]
    pub enabled: bool,

    /// Require password confirmation for deletion.
    #[serde(default)]
    pub require_password: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeEmailOptions {
    /// Enable email change (default: false).
    #[serde(default)]
    pub enabled: bool,
}

// ─── Advanced Options ────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvancedOptions {
    /// Use __Secure- prefix for cookies (auto-detected from baseURL).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_secure_cookies: Option<bool>,

    /// Custom cookie name prefix (default: "better-auth").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookie_prefix: Option<String>,

    /// Cross-subdomain cookie configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_sub_domain_cookies: Option<CrossSubDomainCookieOptions>,

    /// Disable CSRF protection (not recommended in production).
    #[serde(default)]
    pub disable_csrf_check: bool,

    /// Disable origin validation (or specify paths to skip).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_origin_check: Option<serde_json::Value>,

    /// Default attributes applied to all cookies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_cookie_attributes: Option<CookieAttributes>,

    /// Custom cookie configurations per cookie name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookies: Option<HashMap<String, CustomCookieConfig>>,

    /// Whether to trust proxy headers (`X-Forwarded-Host`, `X-Forwarded-Proto`)
    /// to infer the base URL when running behind a reverse proxy.
    ///
    /// ⚠️ This may expose your application to security vulnerabilities if not
    /// used correctly. Use with caution.
    ///
    /// Maps to TS `trustedProxyHeaders`.
    #[serde(default)]
    pub trusted_proxy_headers: bool,

    /// Paths you want to disable. Matching requests will return 404.
    ///
    /// Maps to TS `disabledPaths`.
    #[serde(default)]
    pub disabled_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrossSubDomainCookieOptions {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CookieAttributes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub same_site: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomCookieConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<CookieAttributes>,
}

// ─── OAuth Options ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthOptions {
    /// Strategy for storing OAuth state (default: "database").
    #[serde(default = "default_state_strategy")]
    pub store_state_strategy: StoreStateStrategy,

    /// Skip state cookie verification (insecure, use only in dev/staging).
    #[serde(default)]
    pub skip_state_cookie_check: bool,
}

fn default_state_strategy() -> StoreStateStrategy {
    StoreStateStrategy::Database
}

impl Default for OAuthOptions {
    fn default() -> Self {
        Self {
            store_state_strategy: StoreStateStrategy::Database,
            skip_state_cookie_check: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StoreStateStrategy {
    #[default]
    Database,
    Cookie,
}

// ─── Error Handling Options ──────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnApiErrorOptions {
    /// Custom error page URL (default: "{baseURL}/error").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_url: Option<String>,
}
