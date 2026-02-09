// Last Login Method plugin — tracks authentication method used.
//
// Maps to: packages/better-auth/src/plugins/last-login-method/index.ts
//
// After a session is created, this plugin:
// 1. Sets a cookie with the last used login method
// 2. Optionally stores the method in the user table via database hook
//
// The login method is resolved from the request path:
// - /callback/{provider} → provider name
// - /sign-in/email → "email"
// - /sign-in/username → "username"
// - etc.

use std::collections::HashMap;

use async_trait::async_trait;

use better_auth_core::db::schema::SchemaField;
use better_auth_core::plugin::{BetterAuthPlugin, HookOperation, HookTiming, PluginHook};

/// Options for the last login method plugin.
#[derive(Debug, Clone)]
pub struct LastLoginMethodOptions {
    /// Name of the cookie to store the last login method.
    pub cookie_name: String,
    /// Cookie expiration time in seconds (default: 30 days).
    pub max_age: u64,
    /// Whether to store the last login method in the database user table.
    pub store_in_database: bool,
}

impl Default for LastLoginMethodOptions {
    fn default() -> Self {
        Self {
            cookie_name: "better-auth.last_used_login_method".into(),
            max_age: 60 * 60 * 24 * 30,
            store_in_database: false,
        }
    }
}

// ─── Core handler logic ─────────────────────────────────────────────────

/// Resolve the login method from the request path.
///
/// Maps to TS `defaultResolveMethod(ctx)`.
pub fn resolve_login_method(path: &str) -> Option<&str> {
    // OAuth callbacks
    if path.starts_with("/callback/") || path.starts_with("/oauth2/callback/") {
        return path.rsplit('/').next();
    }
    // Email sign-in/sign-up
    if path == "/sign-in/email" || path == "/sign-up/email" {
        return Some("email");
    }
    // Username sign-in
    if path == "/sign-in/username" {
        return Some("username");
    }
    // Magic link
    if path.contains("magic-link") {
        return Some("magic-link");
    }
    // Passkey
    if path.contains("/passkey/verify-authentication") {
        return Some("passkey");
    }
    // SIWE (Sign In With Ethereum)
    if path.contains("siwe") {
        return Some("siwe");
    }
    // Phone number
    if path.contains("phone-number") {
        return Some("phone");
    }
    // Anonymous
    if path == "/sign-in/anonymous" {
        return Some("anonymous");
    }
    None
}

/// Build the Set-Cookie header for the last login method.
///
/// Maps to the after-hook in TS that calls `ctx.setCookie(...)`.
/// The cookie inherits session cookie attributes but is NOT httpOnly.
pub fn build_last_login_cookie(
    cookie_name: &str,
    method: &str,
    max_age: u64,
    path: &str,
    secure: bool,
    same_site: &str,
) -> String {
    let mut parts = vec![
        format!("{cookie_name}={method}"),
        format!("Max-Age={max_age}"),
        format!("Path={path}"),
    ];

    if secure {
        parts.push("Secure".to_string());
    }

    parts.push(format!("SameSite={same_site}"));

    // Explicitly NOT httpOnly — client JS needs to read this cookie
    parts.join("; ")
}

/// Check if a response's Set-Cookie header contains the session token.
///
/// Maps to TS `setCookie && setCookie.includes(sessionTokenName)`.
pub fn response_has_session_cookie(set_cookie: &str, session_cookie_name: &str) -> bool {
    set_cookie.contains(session_cookie_name)
}

// ─── Plugin trait ───────────────────────────────────────────────────────

/// Last Login Method plugin.
#[derive(Debug)]
pub struct LastLoginMethodPlugin {
    options: LastLoginMethodOptions,
}

impl LastLoginMethodPlugin {
    pub fn new(options: LastLoginMethodOptions) -> Self {
        Self { options }
    }

    /// Access the options (for handler integration).
    pub fn options(&self) -> &LastLoginMethodOptions {
        &self.options
    }
}

impl Default for LastLoginMethodPlugin {
    fn default() -> Self {
        Self::new(LastLoginMethodOptions::default())
    }
}

#[async_trait]
impl BetterAuthPlugin for LastLoginMethodPlugin {
    fn id(&self) -> &str {
        "last-login-method"
    }

    fn name(&self) -> &str {
        "Last Login Method"
    }

    fn additional_fields(&self) -> HashMap<String, HashMap<String, SchemaField>> {
        if !self.options.store_in_database {
            return HashMap::new();
        }
        let mut user_fields = HashMap::new();
        user_fields.insert("lastLoginMethod".to_string(), SchemaField::optional_string());

        let mut fields = HashMap::new();
        fields.insert("user".to_string(), user_fields);
        fields
    }

    fn hooks(&self) -> Vec<PluginHook> {
        vec![PluginHook {
            model: "session".to_string(),
            timing: HookTiming::After,
            operation: HookOperation::Create,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_id() {
        let plugin = LastLoginMethodPlugin::default();
        assert_eq!(plugin.id(), "last-login-method");
    }

    #[test]
    fn test_resolve_login_method() {
        assert_eq!(resolve_login_method("/sign-in/email"), Some("email"));
        assert_eq!(resolve_login_method("/callback/google"), Some("google"));
        assert_eq!(resolve_login_method("/oauth2/callback/github"), Some("github"));
        assert_eq!(resolve_login_method("/sign-in/username"), Some("username"));
        assert_eq!(resolve_login_method("/sign-in/anonymous"), Some("anonymous"));
        assert_eq!(resolve_login_method("/sign-in/magic-link"), Some("magic-link"));
        assert_eq!(resolve_login_method("/passkey/verify-authentication"), Some("passkey"));
        assert_eq!(resolve_login_method("/siwe/sign-in"), Some("siwe"));
        assert_eq!(resolve_login_method("/phone-number/verify"), Some("phone"));
        assert_eq!(resolve_login_method("/some-random-path"), None);
    }

    #[test]
    fn test_no_schema_without_store_in_database() {
        let plugin = LastLoginMethodPlugin::default();
        assert!(plugin.additional_fields().is_empty());
    }

    #[test]
    fn test_schema_with_store_in_database() {
        let plugin = LastLoginMethodPlugin::new(LastLoginMethodOptions {
            store_in_database: true,
            ..Default::default()
        });
        let fields = plugin.additional_fields();
        assert!(fields.contains_key("user"));
        assert!(fields["user"].contains_key("lastLoginMethod"));
    }

    #[test]
    fn test_build_last_login_cookie() {
        let cookie = build_last_login_cookie(
            "better-auth.last_used_login_method",
            "google",
            2592000,
            "/",
            true,
            "Lax",
        );
        assert!(cookie.contains("better-auth.last_used_login_method=google"));
        assert!(cookie.contains("Max-Age=2592000"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(!cookie.contains("HttpOnly"));
    }

    #[test]
    fn test_response_has_session_cookie() {
        let set_cookie = "better-auth.session_token=abc; Path=/; HttpOnly";
        assert!(response_has_session_cookie(set_cookie, "better-auth.session_token"));
        assert!(!response_has_session_cookie(set_cookie, "other-cookie"));
    }
}
