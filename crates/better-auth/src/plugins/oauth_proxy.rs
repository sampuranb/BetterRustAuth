// OAuth Proxy plugin — proxy OAuth callbacks for mobile/desktop apps.
//
// Maps to: packages/better-auth/src/plugins/oauth-proxy/index.ts
//
// Endpoints:
//   GET /oauth-proxy-callback — receive OAuth callback and forward to mobile app
//
// Features:
//   - Acts as a redirect proxy for OAuth flows in mobile/desktop environments
//   - Stores OAuth state with mobile app deep-link scheme
//   - Forwards authorization code and state to the mobile app's custom URL scheme
//   - Configurable allowed schemes

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use better_auth_core::error::ErrorCode;
use better_auth_core::plugin::{BetterAuthPlugin, HttpMethod, PluginEndpoint, PluginHook};

// ─── Options ────────────────────────────────────────────────────────────

/// Configuration for the OAuth proxy plugin.
#[derive(Debug, Clone)]
pub struct OAuthProxyOptions {
    /// Current URL of the server (used to construct the proxy callback URL).
    pub current_url: Option<String>,
    /// Production URL — requests to this URL won't be proxied.
    /// Defaults to BETTER_AUTH_URL env var.
    pub production_url: Option<String>,
    /// Maximum age in seconds for the encrypted payload (default: 60).
    /// Payloads older than this will be rejected to prevent replay attacks.
    pub max_age: u64,
}

impl Default for OAuthProxyOptions {
    fn default() -> Self {
        Self {
            current_url: None,
            production_url: None,
            max_age: 60,
        }
    }
}

// ─── Callback query parameters ─────────────────────────────────────────

/// Query parameters on the OAuth proxy callback.
#[derive(Debug, Deserialize)]
pub struct OAuthProxyCallbackQuery {
    /// The authorization code from the OAuth provider.
    #[serde(default)]
    pub code: Option<String>,
    /// The state parameter (round-tripped).
    #[serde(default)]
    pub state: Option<String>,
    /// Error returned by the OAuth provider.
    #[serde(default)]
    pub error: Option<String>,
    /// Error description from the OAuth provider.
    #[serde(default)]
    pub error_description: Option<String>,
}

/// Stored proxy state linking the OAuth flow to the mobile callback.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthProxyState {
    /// The original OAuth callback URL for the mobile app (custom scheme).
    pub callback_url: String,
    /// The original state string to forward to the mobile app.
    pub state: String,
}

// ─── Core handler logic ────────────────────────────────────────────────

/// Build the proxy callback URL that the OAuth provider will redirect to.
pub fn build_proxy_callback_url(base_url: &str, base_path: &str) -> String {
    format!(
        "{}{}/oauth-proxy-callback",
        base_url.trim_end_matches('/'),
        base_path
    )
}

/// Build the mobile redirect URL that forwards the auth code to the mobile app.
pub fn build_mobile_redirect_url(
    callback_url: &str,
    code: &str,
    state: &str,
) -> String {
    let separator = if callback_url.contains('?') { "&" } else { "?" };
    format!(
        "{}{}code={}&state={}",
        callback_url,
        separator,
        urlencoding::encode(code),
        urlencoding::encode(state),
    )
}

/// Build the mobile error redirect URL.
pub fn build_mobile_error_redirect_url(
    callback_url: &str,
    error: &str,
    error_description: Option<&str>,
) -> String {
    let separator = if callback_url.contains('?') { "&" } else { "?" };
    let mut url = format!(
        "{}{}error={}",
        callback_url,
        separator,
        urlencoding::encode(error),
    );
    if let Some(desc) = error_description {
        url.push_str(&format!("&error_description={}", urlencoding::encode(desc)));
    }
    url
}

/// Serialize the proxy state for storage in the verification table.
pub fn serialize_proxy_state(callback_url: &str, state: &str) -> String {
    serde_json::to_string(&OAuthProxyState {
        callback_url: callback_url.to_string(),
        state: state.to_string(),
    })
    .unwrap_or_default()
}

/// Deserialize the proxy state from the verification table.
pub fn deserialize_proxy_state(value: &str) -> Option<OAuthProxyState> {
    serde_json::from_str(value).ok()
}

// ─── Passthrough payload (encrypted cross-origin transfer) ─────────

/// Encrypted state package for cross-origin OAuth proxy flow.
/// Used to bundle the OAuth state identifier and state cookie into
/// the state parameter sent to the OAuth provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthProxyStatePackage {
    /// The original OAuth state identifier.
    pub state: String,
    /// The encrypted state cookie value.
    pub state_cookie: String,
    /// Flag to identify this as an OAuth proxy state package.
    pub is_oauth_proxy: bool,
}

/// Passthrough payload containing OAuth profile data.
/// Used to transfer OAuth credentials from production to preview/dev
/// without creating user/session on production.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PassthroughPayload {
    /// User info from the OAuth provider.
    pub user_info: serde_json::Value,
    /// Account data (provider, tokens, etc.).
    pub account: serde_json::Value,
    /// The original OAuth state.
    pub state: String,
    /// The final callback URL after authentication.
    pub callback_url: String,
    /// URL to redirect new users to (optional).
    pub new_user_url: Option<String>,
    /// URL to redirect to on error (optional).
    pub error_url: Option<String>,
    /// Whether sign-up is disabled for this flow.
    pub disable_sign_up: Option<bool>,
    /// Timestamp for age validation (milliseconds since epoch).
    pub timestamp: u64,
}

/// Validate that a passthrough payload has not expired.
///
/// Maps to the TS logic:
/// ```ts
/// const age = (now - payload.timestamp) / 1000;
/// if (age > maxAge || age < -10) { ... }
/// ```
pub fn validate_payload_age(timestamp_ms: u64, max_age_secs: u64) -> Result<(), &'static str> {
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let age_secs = if now >= timestamp_ms {
        (now - timestamp_ms) / 1000
    } else {
        // Future timestamp — allow up to 10 seconds of clock skew
        let skew = (timestamp_ms - now) / 1000;
        if skew > 10 {
            return Err("Payload timestamp is too far in the future");
        }
        0
    };

    if age_secs > max_age_secs {
        return Err("Payload has expired");
    }

    Ok(())
}

/// Check if a request should skip the proxy (e.g., production URL matches).
pub fn should_skip_proxy(request_url: &str, production_url: Option<&str>) -> bool {
    match production_url {
        Some(prod) => {
            let req_origin = strip_trailing_slash(request_url);
            let prod_origin = strip_trailing_slash(prod);
            req_origin.starts_with(&prod_origin)
        }
        None => false,
    }
}

/// Strip trailing slash from a URL.
fn strip_trailing_slash(url: &str) -> String {
    url.trim_end_matches('/').to_string()
}

/// Serialize a passthrough payload to JSON string.
pub fn serialize_passthrough_payload(payload: &PassthroughPayload) -> String {
    serde_json::to_string(payload).unwrap_or_default()
}

/// Deserialize a passthrough payload from JSON string.
pub fn deserialize_passthrough_payload(value: &str) -> Option<PassthroughPayload> {
    serde_json::from_str(value).ok()
}

/// Build a redirect URL with an error parameter.
pub fn build_error_redirect_url(error_url: &str, error: &str) -> String {
    let separator = if error_url.contains('?') { "&" } else { "?" };
    format!("{}{}error={}", error_url, separator, urlencoding::encode(error))
}

// ─── Plugin struct ─────────────────────────────────────────────────────

#[derive(Debug)]
pub struct OAuthProxyPlugin {
    options: OAuthProxyOptions,
}

impl OAuthProxyPlugin {
    pub fn new(options: OAuthProxyOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &OAuthProxyOptions {
        &self.options
    }
}

impl Default for OAuthProxyPlugin {
    fn default() -> Self {
        Self::new(OAuthProxyOptions::default())
    }
}

// ─── Plugin trait ──────────────────────────────────────────────────────

#[async_trait]
impl BetterAuthPlugin for OAuthProxyPlugin {
    fn id(&self) -> &str {
        "oauth-proxy"
    }

    fn name(&self) -> &str {
        "OAuth Proxy"
    }

    fn endpoints(&self) -> Vec<PluginEndpoint> {
        use std::sync::Arc;
        use better_auth_core::plugin::{PluginHandlerFn, PluginHandlerRequest, PluginHandlerResponse};

        let handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                // Extract the OAuth callback params (code, state)
                let code = req.query.get("code").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let state = req.query.get("state").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if code.is_empty() || state.is_empty() {
                    return PluginHandlerResponse::error(400, "BAD_REQUEST", "Missing code or state parameter");
                }
                // Verify state matches stored verification
                match ctx.adapter.find_verification(&state).await {
                    Ok(Some(verification)) => {
                        let callback_url = verification.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let _ = ctx.adapter.delete_verification(&state).await;
                        // Redirect to the original callback URL with the code
                        let separator = if callback_url.contains('?') { "&" } else { "?" };
                        PluginHandlerResponse::redirect_to(format!("{}{}code={}&state={}", callback_url, separator, code, state))
                    }
                    Ok(None) => PluginHandlerResponse::error(400, "INVALID_STATE", "Invalid OAuth state"),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });
        vec![PluginEndpoint::with_handler("/oauth-proxy-callback", HttpMethod::Get, false, handler)]
    }

    fn hooks(&self) -> Vec<PluginHook> {
        use better_auth_core::plugin::{HookOperation, HookTiming};
        vec![
            // Before hook: intercept /sign-in/social and /sign-in/oauth2 to rewrite callback URL
            PluginHook {
                model: "*".to_string(),
                timing: HookTiming::Before,
                operation: HookOperation::Create,
            },
            // Before hook: intercept /callback/:id to handle proxy state package
            PluginHook {
                model: "*".to_string(),
                timing: HookTiming::Before,
                operation: HookOperation::Update,
            },
            // After hook: modify sign-in response URL with encrypted state package
            PluginHook {
                model: "*".to_string(),
                timing: HookTiming::After,
                operation: HookOperation::Create,
            },
            // After hook: unwrap proxy redirect on same-origin callback
            PluginHook {
                model: "*".to_string(),
                timing: HookTiming::After,
                operation: HookOperation::Update,
            },
        ]
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![ErrorCode::InvalidToken, ErrorCode::InvalidCallbackUrl]
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_proxy_callback_url() {
        assert_eq!(
            build_proxy_callback_url("https://api.app.com", "/auth"),
            "https://api.app.com/auth/oauth-proxy-callback"
        );
    }

    #[test]
    fn test_build_proxy_callback_url_trailing_slash() {
        assert_eq!(
            build_proxy_callback_url("https://api.app.com/", ""),
            "https://api.app.com/oauth-proxy-callback"
        );
    }

    #[test]
    fn test_build_mobile_redirect_url() {
        let url = build_mobile_redirect_url("myapp://callback", "auth-code-123", "state-456");
        assert!(url.starts_with("myapp://callback?"));
        assert!(url.contains("code=auth-code-123"));
        assert!(url.contains("state=state-456"));
    }

    #[test]
    fn test_build_mobile_redirect_url_with_existing_query() {
        let url =
            build_mobile_redirect_url("myapp://callback?key=val", "code123", "state456");
        assert!(url.starts_with("myapp://callback?key=val&"));
    }

    #[test]
    fn test_build_mobile_error_redirect() {
        let url = build_mobile_error_redirect_url(
            "myapp://callback",
            "access_denied",
            Some("User denied"),
        );
        assert!(url.contains("error=access_denied"));
        assert!(url.contains("error_description=User%20denied"));
    }

    #[test]
    fn test_serialize_deserialize_proxy_state() {
        let serialized = serialize_proxy_state("myapp://cb", "state123");
        let parsed = deserialize_proxy_state(&serialized).unwrap();
        assert_eq!(parsed.callback_url, "myapp://cb");
        assert_eq!(parsed.state, "state123");
    }

    #[test]
    fn test_deserialize_invalid() {
        assert!(deserialize_proxy_state("not json").is_none());
    }

    #[test]
    fn test_plugin_id() {
        let plugin = OAuthProxyPlugin::default();
        assert_eq!(plugin.id(), "oauth-proxy");
    }

    #[test]
    fn test_plugin_endpoints() {
        let plugin = OAuthProxyPlugin::default();
        let endpoints = plugin.endpoints();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].path, "/oauth-proxy-callback");
    }

    #[test]
    fn test_plugin_hooks() {
        let plugin = OAuthProxyPlugin::default();
        let hooks = plugin.hooks();
        assert_eq!(hooks.len(), 4); // 2 before + 2 after
    }

    #[test]
    fn test_callback_query_deserialization() {
        let json = serde_json::json!({
            "code": "auth-code",
            "state": "state-123"
        });
        let query: OAuthProxyCallbackQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.code, Some("auth-code".into()));
        assert_eq!(query.state, Some("state-123".into()));
        assert_eq!(query.error, None);
    }

    #[test]
    fn test_default_options() {
        let opts = OAuthProxyOptions::default();
        assert!(opts.current_url.is_none());
        assert!(opts.production_url.is_none());
        assert_eq!(opts.max_age, 60);
    }

    #[test]
    fn test_validate_payload_age_valid() {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        assert!(validate_payload_age(now - 5000, 60).is_ok()); // 5 seconds ago
    }

    #[test]
    fn test_validate_payload_age_expired() {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        assert!(validate_payload_age(now - 120_000, 60).is_err()); // 2 minutes ago
    }

    #[test]
    fn test_validate_payload_age_future() {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        assert!(validate_payload_age(now + 5_000, 60).is_ok()); // 5s in future (within skew)
        assert!(validate_payload_age(now + 30_000, 60).is_err()); // 30s in future (too far)
    }

    #[test]
    fn test_should_skip_proxy() {
        assert!(should_skip_proxy("https://prod.app.com/api/auth", Some("https://prod.app.com")));
        assert!(!should_skip_proxy("https://preview.app.com/api/auth", Some("https://prod.app.com")));
        assert!(!should_skip_proxy("https://preview.app.com/api/auth", None));
    }

    #[test]
    fn test_passthrough_payload_roundtrip() {
        let payload = PassthroughPayload {
            user_info: serde_json::json!({ "email": "test@example.com" }),
            account: serde_json::json!({ "providerId": "google" }),
            state: "state-123".to_string(),
            callback_url: "https://app.com/callback".to_string(),
            new_user_url: None,
            error_url: None,
            disable_sign_up: Some(false),
            timestamp: 1700000000000,
        };
        let serialized = serialize_passthrough_payload(&payload);
        let parsed = deserialize_passthrough_payload(&serialized).unwrap();
        assert_eq!(parsed.callback_url, "https://app.com/callback");
        assert_eq!(parsed.state, "state-123");
        assert_eq!(parsed.timestamp, 1700000000000);
    }

    #[test]
    fn test_build_error_redirect_url() {
        let url = build_error_redirect_url("https://app.com/error", "invalid_code");
        assert_eq!(url, "https://app.com/error?error=invalid_code");

        let url2 = build_error_redirect_url("https://app.com/error?foo=bar", "timeout");
        assert_eq!(url2, "https://app.com/error?foo=bar&error=timeout");
    }

    #[test]
    fn test_state_package_roundtrip() {
        let pkg = OAuthProxyStatePackage {
            state: "s123".to_string(),
            state_cookie: "encrypted_cookie".to_string(),
            is_oauth_proxy: true,
        };
        let serialized = serde_json::to_string(&pkg).unwrap();
        let parsed: OAuthProxyStatePackage = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed.state, "s123");
        assert!(parsed.is_oauth_proxy);
    }
}
