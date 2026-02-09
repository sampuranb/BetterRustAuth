// better-auth-electron — mirrors packages/electron/src
//
// Server-side plugin for Electron apps using Better Auth.
// Provides:
// - PKCE-based token exchange flow for desktop apps
// - OAuth proxy initialization for social login
// - Transfer cookie management for cross-process auth
// - Origin override for Electron requests

pub mod error_codes;
pub mod routes;
pub mod types;

use crate::error_codes::ELECTRON_ERROR_CODES;
use crate::types::ElectronOptions;

/// Create the Electron plugin.
///
/// Maps to TS `electron(options?)`.
pub fn electron(options: Option<ElectronOptions>) -> ElectronPlugin {
    let opts = options.unwrap_or_default();
    ElectronPlugin { options: opts }
}

/// The Electron server-side plugin.
///
/// Matches TS `satisfies BetterAuthPlugin`:
/// - id: "electron"
/// - onRequest: origin override from `electron-origin` header
/// - hooks.after: transfer cookie management + PKCE code generation
/// - endpoints: electronToken, electronInitOAuthProxy
#[derive(Debug)]
pub struct ElectronPlugin {
    pub options: ElectronOptions,
}

impl ElectronPlugin {
    /// Plugin ID — matches TS `id: "electron"`.
    pub fn id(&self) -> &str {
        "electron"
    }

    /// Plugin name.
    pub fn name(&self) -> &str {
        "Electron"
    }

    /// Check if origin override should be applied.
    ///
    /// Maps to TS `onRequest(request, ctx)`.
    pub fn should_override_origin(&self, has_origin: bool, electron_origin: Option<&str>) -> Option<String> {
        if self.options.disable_origin_override || has_origin {
            return None;
        }

        electron_origin.map(|o| o.to_string())
    }

    /// Check if a path matches the hook patterns for auth endpoints.
    ///
    /// Maps to TS `hookMatcher(ctx)`.
    pub fn is_auth_path(&self, path: &str) -> bool {
        path.starts_with("/sign-in")
            || path.starts_with("/sign-up")
            || path.starts_with("/callback")
            || path.starts_with("/oauth2/callback")
            || path.starts_with("/magic-link/verify")
            || path.starts_with("/email-otp/verify-email")
            || path.starts_with("/verify-email")
            || path.starts_with("/one-tap/callback")
            || path.starts_with("/passkey/verify-authentication")
            || path.starts_with("/phone-number/verify")
    }

    /// Get the transfer cookie name.
    pub fn transfer_cookie_name(&self) -> String {
        format!("{}.transfer_token", self.options.cookie_prefix)
    }

    /// Get the redirect cookie name.
    pub fn redirect_cookie_name(&self) -> String {
        format!("{}.{}", self.options.cookie_prefix, self.options.client_id)
    }

    /// Get the PKCE code expiration in seconds.
    pub fn code_expires_in(&self) -> u64 {
        self.options.code_expires_in
    }

    /// Get the redirect cookie expiration in seconds.
    pub fn redirect_cookie_expires_in(&self) -> u64 {
        self.options.redirect_cookie_expires_in
    }

    /// Get error codes for this plugin.
    pub fn error_codes(&self) -> &error_codes::ElectronErrorCodes {
        &ELECTRON_ERROR_CODES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_electron_plugin_id() {
        let plugin = electron(None);
        assert_eq!(plugin.id(), "electron");
        assert_eq!(plugin.name(), "Electron");
    }

    #[test]
    fn test_default_options() {
        let plugin = electron(None);
        assert_eq!(plugin.options.code_expires_in, 300);
        assert_eq!(plugin.options.redirect_cookie_expires_in, 120);
        assert_eq!(plugin.options.cookie_prefix, "better-auth");
        assert_eq!(plugin.options.client_id, "electron");
        assert!(!plugin.options.disable_origin_override);
    }

    #[test]
    fn test_origin_override() {
        let plugin = electron(None);

        // No origin, with electron-origin → should override
        assert_eq!(
            plugin.should_override_origin(false, Some("https://electron.app")),
            Some("https://electron.app".to_string())
        );

        // Has origin → should not override
        assert_eq!(
            plugin.should_override_origin(true, Some("https://electron.app")),
            None
        );

        // No electron-origin → should not override
        assert_eq!(plugin.should_override_origin(false, None), None);

        // Disabled → should not override
        let disabled_plugin = electron(Some(ElectronOptions {
            disable_origin_override: true,
            ..Default::default()
        }));
        assert_eq!(
            disabled_plugin.should_override_origin(false, Some("https://electron.app")),
            None
        );
    }

    #[test]
    fn test_auth_path_matching() {
        let plugin = electron(None);

        assert!(plugin.is_auth_path("/sign-in/email"));
        assert!(plugin.is_auth_path("/sign-up/email"));
        assert!(plugin.is_auth_path("/callback/github"));
        assert!(plugin.is_auth_path("/oauth2/callback"));
        assert!(plugin.is_auth_path("/magic-link/verify"));
        assert!(plugin.is_auth_path("/verify-email"));
        assert!(plugin.is_auth_path("/passkey/verify-authentication"));
        assert!(!plugin.is_auth_path("/session"));
        assert!(!plugin.is_auth_path("/user"));
    }

    #[test]
    fn test_cookie_names() {
        let plugin = electron(None);
        assert_eq!(plugin.transfer_cookie_name(), "better-auth.transfer_token");
        assert_eq!(plugin.redirect_cookie_name(), "better-auth.electron");

        let custom = electron(Some(ElectronOptions {
            cookie_prefix: "myapp".to_string(),
            client_id: "desktop".to_string(),
            ..Default::default()
        }));
        assert_eq!(custom.transfer_cookie_name(), "myapp.transfer_token");
        assert_eq!(custom.redirect_cookie_name(), "myapp.desktop");
    }
}
