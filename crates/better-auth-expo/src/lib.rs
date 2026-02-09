// better-auth-expo — mirrors packages/expo/src
//
// Server-side plugin for Expo / React Native apps using Better Auth.
// Provides:
// - Origin override for mobile requests (via `expo-origin` header)
// - OAuth callback redirects with cookie data in URL params
// - OAuth authorization proxy endpoint
// - Development trusted origins for `exp://` scheme

pub mod routes;

/// Options for the Expo plugin.
///
/// Maps to TS `ExpoOptions` interface.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpoOptions {
    /// Disable origin override for Expo API routes.
    /// When set to true, the `expo-origin` header will not be used
    /// to override the request origin.
    #[serde(default)]
    pub disable_origin_override: bool,
}

/// Create the Expo plugin.
///
/// Maps to TS `expo(options?)`.
pub fn expo(options: Option<ExpoOptions>) -> ExpoPlugin {
    let opts = options.unwrap_or_default();
    ExpoPlugin { options: opts }
}

/// The Expo server-side plugin.
///
/// Matches TS `satisfies BetterAuthPlugin`:
/// - id: "expo"
/// - init: adds `exp://` to trusted origins in development
/// - onRequest: origin override from `expo-origin` header
/// - hooks.after: callback redirect with cookie data in URL params
/// - endpoints: expoAuthorizationProxy
#[derive(Debug)]
pub struct ExpoPlugin {
    pub options: ExpoOptions,
}

impl ExpoPlugin {
    /// Plugin ID — matches TS `id: "expo"`.
    pub fn id(&self) -> &str {
        "expo"
    }

    /// Plugin name.
    pub fn name(&self) -> &str {
        "Expo"
    }

    /// Get additional trusted origins for development mode.
    ///
    /// Maps to TS `init(ctx) { return { options: { trustedOrigins: ["exp://"] } } }`.
    pub fn init_trusted_origins(&self, is_development: bool) -> Vec<String> {
        if is_development {
            vec!["exp://".to_string()]
        } else {
            vec![]
        }
    }

    /// Check if origin override should be applied.
    ///
    /// Maps to TS `onRequest(request, ctx)`.
    pub fn should_override_origin(
        &self,
        has_origin: bool,
        expo_origin: Option<&str>,
    ) -> Option<String> {
        if self.options.disable_origin_override || has_origin {
            return None;
        }

        expo_origin.map(|o| o.to_string())
    }

    /// Check if a path matches the hook patterns.
    ///
    /// Maps to TS `hooks.after[0].matcher(context)`.
    pub fn is_callback_path(&self, path: &str) -> bool {
        path.starts_with("/callback")
            || path.starts_with("/oauth2/callback")
            || path.starts_with("/magic-link/verify")
            || path.starts_with("/verify-email")
    }

    /// Process a callback redirect for Expo.
    ///
    /// When a redirect location targets a non-HTTP trusted origin (e.g., `exp://...`),
    /// this appends the `set-cookie` header value as a URL query parameter so the
    /// Expo client can extract it.
    ///
    /// Maps to TS `hooks.after[0].handler`.
    pub fn process_callback_redirect(
        &self,
        location: Option<&str>,
        set_cookie: Option<&str>,
        trusted_origins: &[String],
    ) -> Option<String> {
        let location = location?;

        // Skip if this is an OAuth proxy callback URL
        if location.contains("/oauth-proxy-callback") {
            return None;
        }

        // Filter trusted origins to non-HTTP ones (e.g., "exp://")
        let non_http_origins: Vec<&String> = trusted_origins
            .iter()
            .filter(|o| !o.starts_with("http"))
            .collect();

        // Check if the redirect targets a non-HTTP trusted origin
        let is_trusted = non_http_origins
            .iter()
            .any(|o| location.starts_with(o.as_str()));

        if !is_trusted {
            return None;
        }

        // Append cookie to URL if present
        let cookie = set_cookie?;
        if let Ok(mut url) = url::Url::parse(location) {
            url.query_pairs_mut().append_pair("cookie", cookie);
            Some(url.to_string())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expo_plugin_id() {
        let plugin = expo(None);
        assert_eq!(plugin.id(), "expo");
        assert_eq!(plugin.name(), "Expo");
    }

    #[test]
    fn test_default_options() {
        let plugin = expo(None);
        assert!(!plugin.options.disable_origin_override);
    }

    #[test]
    fn test_init_trusted_origins_development() {
        let plugin = expo(None);
        let origins = plugin.init_trusted_origins(true);
        assert_eq!(origins, vec!["exp://"]);
    }

    #[test]
    fn test_init_trusted_origins_production() {
        let plugin = expo(None);
        let origins = plugin.init_trusted_origins(false);
        assert!(origins.is_empty());
    }

    #[test]
    fn test_origin_override() {
        let plugin = expo(None);

        // No origin, with expo-origin → should override
        assert_eq!(
            plugin.should_override_origin(false, Some("exp://localhost:19000")),
            Some("exp://localhost:19000".to_string())
        );

        // Has origin → should not override
        assert_eq!(
            plugin.should_override_origin(true, Some("exp://localhost:19000")),
            None
        );

        // No expo-origin → should not override
        assert_eq!(plugin.should_override_origin(false, None), None);
    }

    #[test]
    fn test_callback_path_matching() {
        let plugin = expo(None);

        assert!(plugin.is_callback_path("/callback/github"));
        assert!(plugin.is_callback_path("/oauth2/callback"));
        assert!(plugin.is_callback_path("/magic-link/verify"));
        assert!(plugin.is_callback_path("/verify-email"));
        assert!(!plugin.is_callback_path("/sign-in/email"));
        assert!(!plugin.is_callback_path("/session"));
    }

    #[test]
    fn test_process_callback_redirect() {
        let plugin = expo(None);
        let trusted = vec!["exp://".to_string(), "https://example.com".to_string()];

        // Non-HTTP origin with cookie → should append cookie
        let result = plugin.process_callback_redirect(
            Some("exp://localhost:19000/auth"),
            Some("session=abc123"),
            &trusted,
        );
        assert!(result.is_some());
        let url = result.unwrap();
        assert!(url.contains("cookie=session%3Dabc123"));

        // HTTP origin → should not modify
        let result = plugin.process_callback_redirect(
            Some("https://example.com/auth"),
            Some("session=abc123"),
            &trusted,
        );
        assert!(result.is_none());

        // OAuth proxy callback → should skip
        let result = plugin.process_callback_redirect(
            Some("exp://localhost:19000/oauth-proxy-callback"),
            Some("session=abc123"),
            &trusted,
        );
        assert!(result.is_none());

        // No cookie → should return None
        let result = plugin.process_callback_redirect(
            Some("exp://localhost:19000/auth"),
            None,
            &trusted,
        );
        assert!(result.is_none());

        // No location → should return None
        let result = plugin.process_callback_redirect(None, Some("session=abc123"), &trusted);
        assert!(result.is_none());
    }
}
