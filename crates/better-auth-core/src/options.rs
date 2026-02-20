// BetterAuthOptions — the main configuration struct.
//
// Maps to: packages/core/src/types/init-options.ts (1440 lines)
// This is a comprehensive builder capturing every configurable option
// from the TypeScript version.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::db::secondary_storage::SecondaryStorage;

// ─── Email Callback Types ───────────────────────────────────────

/// Data passed to email callback functions.
#[derive(Debug, Clone)]
pub struct EmailCallbackData {
    /// The user record (as a JSON value for flexibility across plugins).
    pub user: serde_json::Value,
    /// The action URL (e.g., password reset link, verification link).
    pub url: String,
    /// The raw token associated with the action.
    pub token: String,
}

/// Type alias for async email callback functions.
///
/// These callbacks are used to send transactional emails (password reset,
/// email verification, account deletion, email change). The implementation
/// is responsible for actually dispatching the email via whichever provider
/// the application uses (SMTP, SendGrid, Resend, etc.).
pub type EmailCallback = Arc<
    dyn Fn(&EmailCallbackData) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send>>
        + Send
        + Sync,
>;

/// Lifecycle callback — receives a user JSON value.
///
/// Used for `beforeEmailVerification`, `afterEmailVerification`,
/// `onPasswordReset`, `beforeDelete`, `afterDelete`, etc.
pub type LifecycleCallback = Arc<
    dyn Fn(&serde_json::Value) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send>>
        + Send
        + Sync,
>;

/// Error handler callback — receives the error as a string.
///
/// Maps to TS `onAPIError.onError`.
pub type ErrorHandlerCallback = Arc<
    dyn Fn(&str) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

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

    /// Secondary storage for fast session/rate-limit caching (e.g., Redis).
    ///
    /// Maps to TS `secondaryStorage` option. When set, sessions, rate-limit
    /// counters, and verification tokens are stored in this fast KV store
    /// instead of (or in addition to) the primary database.
    #[serde(skip)]
    pub secondary_storage: Option<Arc<dyn SecondaryStorage>>,

    /// Verification table configuration.
    ///
    /// Maps to TS `verification` option.
    #[serde(default)]
    pub verification: VerificationOptions,

    /// Request lifecycle hooks.
    ///
    /// Maps to TS `hooks` option with `before`/`after` middleware.
    #[serde(skip)]
    pub hooks: HooksOptions,

    /// Database lifecycle hooks.
    ///
    /// Maps to TS `databaseHooks` option.
    #[serde(skip)]
    pub database_hooks: DatabaseHooksOptions,

    /// Logger configuration.
    ///
    /// Maps to TS `logger` option.
    #[serde(default)]
    pub logger_config: LoggerOptions,

    /// Telemetry configuration.
    ///
    /// Maps to TS `telemetry` option.
    #[serde(default)]
    pub telemetry: TelemetryOptions,

    /// Experimental features.
    ///
    /// Maps to TS `experimental` option.
    #[serde(default)]
    pub experimental: ExperimentalOptions,
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
            verification: VerificationOptions::default(),
            hooks: HooksOptions::default(),
            database_hooks: DatabaseHooksOptions::default(),
            logger_config: LoggerOptions::default(),
            telemetry: TelemetryOptions::default(),
            experimental: ExperimentalOptions::default(),
            secondary_storage: None,
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

    pub fn secondary_storage(mut self, storage: Arc<dyn SecondaryStorage>) -> Self {
        self.secondary_storage = Some(storage);
        self
    }
}

// ─── Email & Password Options ────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
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

    /// Disable signup (only allow sign-in for existing users).
    #[serde(default)]
    pub disable_signup: bool,

    /// Whether to revoke all other sessions when resetting password.
    ///
    /// Maps to TS `emailAndPassword.revokeSessionsOnPasswordReset`.
    ///
    /// @default false
    #[serde(default)]
    pub revoke_sessions_on_password_reset: bool,

    /// Reset password token expiry in seconds.
    ///
    /// Maps to TS `emailAndPassword.resetPasswordTokenExpiresIn`.
    ///
    /// @default 3600 (1 hour)
    #[serde(default = "default_reset_password_token_expires_in")]
    pub reset_password_token_expires_in: u64,

    /// Callback to send password reset emails.
    /// Receives the user, reset URL, and token.
    ///
    /// Maps to TS `emailAndPassword.sendResetPassword`.
    #[serde(skip)]
    pub send_reset_password: Option<EmailCallback>,

    /// Callback triggered after a user's password is successfully reset.
    ///
    /// Maps to TS `emailAndPassword.onPasswordReset`.
    #[serde(skip)]
    pub on_password_reset: Option<LifecycleCallback>,
}

fn default_min_password_length() -> usize { 8 }
fn default_max_password_length() -> usize { 128 }
fn default_true() -> bool { true }
fn default_reset_password_token_expires_in() -> u64 { 3600 }

impl fmt::Debug for EmailAndPasswordOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmailAndPasswordOptions")
            .field("enabled", &self.enabled)
            .field("min_password_length", &self.min_password_length)
            .field("max_password_length", &self.max_password_length)
            .field("auto_sign_in", &self.auto_sign_in)
            .field("require_email_verification", &self.require_email_verification)
            .field("disable_signup", &self.disable_signup)
            .field("revoke_sessions_on_password_reset", &self.revoke_sessions_on_password_reset)
            .field("reset_password_token_expires_in", &self.reset_password_token_expires_in)
            .field("send_reset_password", &self.send_reset_password.as_ref().map(|_| "<callback>"))
            .field("on_password_reset", &self.on_password_reset.as_ref().map(|_| "<callback>"))
            .finish()
    }
}

impl Default for EmailAndPasswordOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            min_password_length: default_min_password_length(),
            max_password_length: default_max_password_length(),
            auto_sign_in: true,
            require_email_verification: false,
            disable_signup: false,
            revoke_sessions_on_password_reset: false,
            reset_password_token_expires_in: default_reset_password_token_expires_in(),
            send_reset_password: None,
            on_password_reset: None,
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

    /// Fresh session window in seconds (default: 86400 = 1 day).
    /// Operations requiring a "fresh" session check this.
    #[serde(default = "default_session_fresh_age")]
    pub fresh_age: u64,

    /// Cookie cache configuration for stateless session reads.
    #[serde(default)]
    pub cookie_cache: CookieCacheOptions,

    /// Defer session refresh to a POST request instead of refreshing on every GET.
    /// When enabled, GET /get-session returns a `needsRefresh` flag, and the client
    /// sends a POST to trigger the actual DB update.
    ///
    /// Maps to TS `session.deferSessionRefresh`.
    ///
    /// @default false
    #[serde(default)]
    pub defer_session_refresh: bool,

    /// Store sessions in both secondary storage and the database.
    ///
    /// When `secondary_storage` is configured, sessions are stored in the
    /// fast KV store by default. Enable this to also persist session records
    /// in the primary database for durability / audit purposes.
    ///
    /// Maps to TS `session.storeSessionInDatabase`.
    ///
    /// @default false
    #[serde(default)]
    pub store_session_in_database: bool,

    /// Preserve session records in the database when revoked from secondary storage.
    ///
    /// When a session is revoked (e.g., user signs out) and secondary storage
    /// is active, this keeps the session row in the database instead of deleting it.
    /// Useful for audit trails.
    ///
    /// Maps to TS `session.preserveSessionInDatabase`.
    ///
    /// @default false
    #[serde(default)]
    pub preserve_session_in_database: bool,

    /// Globally disable session refresh/extension.
    ///
    /// Maps to TS `session.disableSessionRefresh`.
    ///
    /// @default false
    #[serde(default)]
    pub disable_session_refresh: bool,
}

fn default_session_expires_in() -> u64 { 604_800 } // 7 days
fn default_session_update_age() -> u64 { 86_400 } // 1 day
fn default_session_fresh_age() -> u64 { 86_400 } // 1 day (matches TS)

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            expires_in: default_session_expires_in(),
            update_age: default_session_update_age(),
            fresh_age: default_session_fresh_age(),
            cookie_cache: CookieCacheOptions::default(),
            defer_session_refresh: false,
            store_session_in_database: false,
            preserve_session_in_database: false,
            disable_session_refresh: false,
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

    /// Allow unlinking all accounts (even the last one).
    ///
    /// Maps to TS `account.accountLinking.allowUnlinkingAll`.
    ///
    /// @default false
    #[serde(default)]
    pub allow_unlinking_all: bool,

    /// Update user info (name, image) when a new account is linked.
    ///
    /// Maps to TS `account.accountLinking.updateUserInfoOnLink`.
    ///
    /// @default false
    #[serde(default)]
    pub update_user_info_on_link: bool,
}

impl Default for AccountLinkingOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            trusted_providers: Vec::new(),
            disable_implicit_linking: false,
            allow_different_emails: false,
            allow_unlinking_all: false,
            update_user_info_on_link: false,
        }
    }
}

// ─── Email Verification Options ──────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailVerificationOptions {
    /// Whether to send verification email on signup (default: false).
    #[serde(default)]
    pub send_on_sign_up: bool,

    /// Send a verification email automatically on sign in when the user's
    /// email is not verified.
    ///
    /// Maps to TS `emailVerification.sendOnSignIn`.
    ///
    /// @default false
    #[serde(default)]
    pub send_on_sign_in: bool,

    /// Auto-sign-in after email verification (default: false).
    #[serde(default)]
    pub auto_sign_in_after_verification: bool,

    /// Verification token expiry in seconds (default: 3600 = 1 hour).
    #[serde(default = "default_verification_expiry")]
    pub expires_in: u64,

    /// Callback to send email verification emails.
    /// Receives the user, verification URL, and token.
    ///
    /// Maps to TS `emailVerification.sendVerificationEmail`.
    #[serde(skip)]
    pub send_verification_email: Option<EmailCallback>,

    /// Called before a user verifies their email.
    ///
    /// Maps to TS `emailVerification.beforeEmailVerification`.
    #[serde(skip)]
    pub before_email_verification: Option<LifecycleCallback>,

    /// Called after a user's email is verified.
    ///
    /// Maps to TS `emailVerification.afterEmailVerification`.
    #[serde(skip)]
    pub after_email_verification: Option<LifecycleCallback>,
}

impl fmt::Debug for EmailVerificationOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmailVerificationOptions")
            .field("send_on_sign_up", &self.send_on_sign_up)
            .field("send_on_sign_in", &self.send_on_sign_in)
            .field("auto_sign_in_after_verification", &self.auto_sign_in_after_verification)
            .field("expires_in", &self.expires_in)
            .field("send_verification_email", &self.send_verification_email.as_ref().map(|_| "<callback>"))
            .field("before_email_verification", &self.before_email_verification.as_ref().map(|_| "<callback>"))
            .field("after_email_verification", &self.after_email_verification.as_ref().map(|_| "<callback>"))
            .finish()
    }
}

impl Default for EmailVerificationOptions {
    fn default() -> Self {
        Self {
            send_on_sign_up: false,
            send_on_sign_in: false,
            auto_sign_in_after_verification: false,
            expires_in: default_verification_expiry(),
            send_verification_email: None,
            before_email_verification: None,
            after_email_verification: None,
        }
    }
}

fn default_verification_expiry() -> u64 { 3600 }

// ─── Rate Limit Options ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitOptions {
    /// Enable rate limiting (default: true).
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Time window in seconds (default: 10).
    #[serde(default = "default_rate_limit_window")]
    pub window: u64,

    /// Maximum requests per window (default: 100).
    #[serde(default = "default_rate_limit_max")]
    pub max: u64,
}

fn default_rate_limit_window() -> u64 { 10 } // 10 seconds (matches TS)
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

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteUserOptions {
    /// Enable user self-deletion (default: false).
    #[serde(default)]
    pub enabled: bool,

    /// Require password confirmation for deletion.
    #[serde(default)]
    pub require_password: bool,

    /// Callback to send account deletion verification emails.
    /// Receives the user, verification URL, and token.
    ///
    /// Maps to TS `user.deleteUser.sendDeleteAccountVerification`.
    #[serde(skip)]
    pub send_delete_account_verification: Option<EmailCallback>,

    /// Called before a user is deleted.
    /// To interrupt, return an error.
    ///
    /// Maps to TS `user.deleteUser.beforeDelete`.
    #[serde(skip)]
    pub before_delete: Option<LifecycleCallback>,

    /// Called after a user is deleted. Useful for cleanup.
    ///
    /// Maps to TS `user.deleteUser.afterDelete`.
    #[serde(skip)]
    pub after_delete: Option<LifecycleCallback>,

    /// Expiration time for the delete verification token in seconds.
    ///
    /// Maps to TS `user.deleteUser.deleteTokenExpiresIn`.
    ///
    /// @default 86400 (1 day)
    #[serde(default = "default_delete_token_expires_in")]
    pub delete_token_expires_in: u64,
}

fn default_delete_token_expires_in() -> u64 { 86400 }

impl fmt::Debug for DeleteUserOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeleteUserOptions")
            .field("enabled", &self.enabled)
            .field("require_password", &self.require_password)
            .field("send_delete_account_verification", &self.send_delete_account_verification.as_ref().map(|_| "<callback>"))
            .field("before_delete", &self.before_delete.as_ref().map(|_| "<callback>"))
            .field("after_delete", &self.after_delete.as_ref().map(|_| "<callback>"))
            .field("delete_token_expires_in", &self.delete_token_expires_in)
            .finish()
    }
}

impl Default for DeleteUserOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            require_password: false,
            send_delete_account_verification: None,
            before_delete: None,
            after_delete: None,
            delete_token_expires_in: default_delete_token_expires_in(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeEmailOptions {
    /// Enable email change (default: false).
    #[serde(default)]
    pub enabled: bool,

    /// Callback to send email change confirmation emails.
    /// Receives the user, confirmation URL, and token.
    ///
    /// Maps to TS `user.changeEmail.sendChangeEmailConfirmation`.
    #[serde(skip)]
    pub send_change_email_confirmation: Option<EmailCallback>,

    /// Update the email without verification if the user is not verified.
    ///
    /// Maps to TS `user.changeEmail.updateEmailWithoutVerification`.
    ///
    /// @default false
    #[serde(default)]
    pub update_email_without_verification: bool,
}

impl fmt::Debug for ChangeEmailOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChangeEmailOptions")
            .field("enabled", &self.enabled)
            .field("send_change_email_confirmation", &self.send_change_email_confirmation.as_ref().map(|_| "<callback>"))
            .field("update_email_without_verification", &self.update_email_without_verification)
            .finish()
    }
}

impl Default for ChangeEmailOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            send_change_email_confirmation: None,
            update_email_without_verification: false,
        }
    }
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

    /// Skip trailing slashes in API routes.
    ///
    /// When enabled, requests with trailing slashes (e.g., `/api/auth/session/`)
    /// will be handled the same as requests without (e.g., `/api/auth/session`).
    ///
    /// Maps to TS `advanced.skipTrailingSlashes`.
    ///
    /// @default false
    #[serde(default)]
    pub skip_trailing_slashes: bool,

    /// Enable background task processing.
    ///
    /// When enabled, non-critical operations (like timing-attack mitigation
    /// dummy hashes, analytics, cleanup) will be spawned as background
    /// tokio tasks instead of being awaited in the request path.
    ///
    /// This is the Rust equivalent of TS `backgroundTasks.handler` which
    /// accepts Vercel's `waitUntil` or Cloudflare's `ctx.waitUntil`.
    /// In Rust, we use `tokio::spawn` natively.
    ///
    /// @default false
    #[serde(default)]
    pub enable_background_tasks: bool,

    /// How to store verification identifiers (tokens, OTPs, etc.)
    ///
    /// Maps to TS `advanced.verification.storeIdentifier`.
    ///
    /// - `"plain"` — store identifiers as-is (default)
    /// - `"hashed"` — hash identifiers with SHA-256 before storing
    ///
    /// @default "plain"
    #[serde(default)]
    pub store_identifier: StoreIdentifierOption,

    /// IP address configuration for rate limiting and session tracking.
    ///
    /// Maps to TS `advanced.ipAddress`.
    #[serde(default)]
    pub ip_address: IpAddressOptions,

    /// Database configuration (findMany limits, ID generation strategy).
    ///
    /// Maps to TS `advanced.database`.
    #[serde(default)]
    pub database: AdvancedDatabaseOptions,
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

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnApiErrorOptions {
    /// Custom error page URL (default: "{baseURL}/error").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_url: Option<String>,

    /// Throw errors instead of returning error responses.
    ///
    /// Maps to TS `onAPIError.throw`.
    ///
    /// @default false
    #[serde(default)]
    pub throw: bool,

    /// Custom error handler callback.
    ///
    /// Maps to TS `onAPIError.onError`.
    #[serde(skip)]
    pub on_error: Option<ErrorHandlerCallback>,

    /// Customize the default error page styling.
    ///
    /// Maps to TS `onAPIError.customizeDefaultErrorPage`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customize_default_error_page: Option<ErrorPageCustomization>,
}

impl fmt::Debug for OnApiErrorOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnApiErrorOptions")
            .field("error_url", &self.error_url)
            .field("throw", &self.throw)
            .field("on_error", &self.on_error.as_ref().map(|_| "<callback>"))
            .field("customize_default_error_page", &self.customize_default_error_page)
            .finish()
    }
}

/// Customization options for the default error page.
///
/// Maps to TS `onAPIError.customizeDefaultErrorPage`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorPageCustomization {
    /// Custom color overrides.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub colors: Option<HashMap<String, String>>,
    /// Custom size overrides.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<HashMap<String, String>>,
    /// Custom font overrides.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub font: Option<HashMap<String, String>>,
    /// Disable the title border decoration.
    #[serde(default)]
    pub disable_title_border: bool,
    /// Disable corner decorations.
    #[serde(default)]
    pub disable_corner_decorations: bool,
    /// Disable the background grid.
    #[serde(default)]
    pub disable_background_grid: bool,
}

// ─── Store Identifier Option ─────────────────────────────────────

/// How to store verification identifiers (tokens, OTPs, etc.)
///
/// Maps to TS `StoreIdentifierOption` type:
/// - `"plain"` — store identifiers as-is
/// - `"hashed"` — hash identifiers with SHA-256 before storing
///
/// The TS version also supports a custom hash function via
/// `{ hash: (identifier: string) => Promise<string> }`, but we
/// don't replicate that in Rust — use `hashed` with SHA-256 instead.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StoreIdentifierOption {
    /// Store identifiers in plain text (default).
    #[default]
    Plain,
    /// Hash identifiers with SHA-256 before storing.
    Hashed,
}

// ─── IP Address Options ──────────────────────────────────────────

/// IP address configuration for rate limiting and session tracking.
///
/// Maps to TS `advanced.ipAddress`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpAddressOptions {
    /// Custom headers to check for IP address.
    ///
    /// @example ["x-client-ip", "x-forwarded-for", "cf-connecting-ip"]
    #[serde(default)]
    pub ip_address_headers: Vec<String>,

    /// Disable IP tracking entirely.
    ///
    /// ⚠️ Security risk — may expose your application to abuse.
    ///
    /// @default false
    #[serde(default)]
    pub disable_ip_tracking: bool,

    /// IPv6 subnet prefix length for rate limiting.
    /// IPv6 addresses will be normalized to this subnet.
    ///
    /// @default 64
    #[serde(default = "default_ipv6_subnet")]
    pub ipv6_subnet: u8,
}

fn default_ipv6_subnet() -> u8 { 64 }

// ─── Advanced Database Options ───────────────────────────────────

/// Database configuration within advanced options.
///
/// Maps to TS `advanced.database`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvancedDatabaseOptions {
    /// Default number of records to return from findMany.
    ///
    /// @default 100
    #[serde(default = "default_find_many_limit")]
    pub default_find_many_limit: usize,

    /// ID generation strategy.
    ///
    /// - `"random"` — generate random IDs (default)
    /// - `"uuid"` — generate UUIDs
    /// - `"serial"` — use database auto-increment
    ///
    /// Maps to TS `advanced.database.generateId`.
    #[serde(default)]
    pub generate_id: GenerateIdStrategy,
}

fn default_find_many_limit() -> usize { 100 }

impl Default for AdvancedDatabaseOptions {
    fn default() -> Self {
        Self {
            default_find_many_limit: default_find_many_limit(),
            generate_id: GenerateIdStrategy::default(),
        }
    }
}

/// ID generation strategy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GenerateIdStrategy {
    /// Generate random IDs (default).
    #[default]
    Random,
    /// Generate UUIDs.
    Uuid,
    /// Use database auto-increment.
    Serial,
}

// ─── Verification Options ────────────────────────────────────────

/// Verification table configuration.
///
/// Maps to TS `verification` top-level option.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationOptions {
    /// Disable cleanup of expired verification records on fetch.
    ///
    /// @default false
    #[serde(default)]
    pub disable_cleanup: bool,

    /// Store verification data in the database even when secondary storage is configured.
    ///
    /// @default false
    #[serde(default)]
    pub store_in_database: bool,
}

// ─── Hooks Options ───────────────────────────────────────────────

/// Request lifecycle hooks.
///
/// Maps to TS `hooks` option with `before`/`after` middleware.
///
/// In TS, these are `AuthMiddleware` functions. In Rust, we represent
/// them as optional async callbacks.
#[derive(Default)]
pub struct HooksOptions {
    /// Called before each request is processed.
    pub before: Option<LifecycleCallback>,
    /// Called after each request is processed.
    pub after: Option<LifecycleCallback>,
}

impl fmt::Debug for HooksOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HooksOptions")
            .field("before", &self.before.as_ref().map(|_| "<callback>"))
            .field("after", &self.after.as_ref().map(|_| "<callback>"))
            .finish()
    }
}

// ─── Database Hooks Options ──────────────────────────────────────

/// Database lifecycle hooks for model operations.
///
/// Maps to TS `databaseHooks` option.
#[derive(Default)]
pub struct DatabaseHooksOptions {
    /// Hooks for the `user` model.
    pub user: Option<ModelHooks>,
    /// Hooks for the `session` model.
    pub session: Option<ModelHooks>,
    /// Hooks for the `account` model.
    pub account: Option<ModelHooks>,
    /// Hooks for the `verification` model.
    pub verification: Option<ModelHooks>,
}

impl fmt::Debug for DatabaseHooksOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseHooksOptions")
            .field("user", &self.user.as_ref().map(|_| "<hooks>"))
            .field("session", &self.session.as_ref().map(|_| "<hooks>"))
            .field("account", &self.account.as_ref().map(|_| "<hooks>"))
            .field("verification", &self.verification.as_ref().map(|_| "<hooks>"))
            .finish()
    }
}

/// Hooks for a specific database model (before/after create, update).
pub struct ModelHooks {
    pub before_create: Option<LifecycleCallback>,
    pub after_create: Option<LifecycleCallback>,
    pub before_update: Option<LifecycleCallback>,
    pub after_update: Option<LifecycleCallback>,
}

impl fmt::Debug for ModelHooks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModelHooks").finish()
    }
}

// ─── Logger Options ──────────────────────────────────────────────

/// Logger configuration.
///
/// Maps to TS `logger` option.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoggerOptions {
    /// Disable logging entirely.
    ///
    /// @default false
    #[serde(default)]
    pub disabled: bool,

    /// Log level: "error", "warn", "info", "debug".
    ///
    /// @default "error"
    #[serde(default = "default_log_level")]
    pub level: String,
}

fn default_log_level() -> String { "error".to_string() }

// ─── Telemetry Options ───────────────────────────────────────────

/// Telemetry configuration.
///
/// Maps to TS `telemetry` option.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryOptions {
    /// Enable telemetry collection.
    ///
    /// @default false
    #[serde(default)]
    pub enabled: bool,

    /// Enable debug mode for telemetry.
    ///
    /// @default false
    #[serde(default)]
    pub debug: bool,
}

// ─── Experimental Options ────────────────────────────────────────

/// Experimental features.
///
/// Maps to TS `experimental` option.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExperimentalOptions {
    /// Enable experimental joins for database adapters.
    /// Not all adapters support joins.
    ///
    /// @default false
    #[serde(default)]
    pub joins: bool,
}
