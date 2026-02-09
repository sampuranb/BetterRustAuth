// Bearer plugin — converts Authorization: Bearer tokens to session cookies.
//
// Maps to: packages/better-auth/src/plugins/bearer/index.ts
//
// Before hook: extracts bearer token from Authorization header, verifies HMAC
// signature, and injects it as a session cookie so the session middleware
// can resolve it normally.
//
// After hook: emits a `set-auth-token` response header containing the session
// token whenever a session cookie is set, allowing non-browser clients to
// capture the token.

use async_trait::async_trait;

use better_auth_core::plugin::{BetterAuthPlugin, HookOperation, HookTiming, PluginHook};

/// Bearer plugin options.
#[derive(Debug, Clone, Default)]
pub struct BearerOptions {
    /// If true, only signed tokens will be accepted.
    /// Unsigned tokens will be silently ignored.
    pub require_signature: bool,
}

/// Bearer plugin — converts bearer tokens to session cookies.
#[derive(Debug)]
pub struct BearerPlugin {
    options: BearerOptions,
}

impl BearerPlugin {
    pub fn new(options: BearerOptions) -> Self {
        Self { options }
    }
}

impl Default for BearerPlugin {
    fn default() -> Self {
        Self::new(BearerOptions::default())
    }
}

// ─── Core handler logic ─────────────────────────────────────────────────

/// Extract the bearer token from an Authorization header value.
///
/// Returns `None` if the header doesn't start with "Bearer ".
pub fn extract_bearer_token(authorization: &str) -> Option<&str> {
    authorization.strip_prefix("Bearer ").or_else(|| authorization.strip_prefix("bearer "))
}

/// Sign a raw token using HMAC-SHA256 and return "{token}.{signature}".
///
/// Maps to TS `serializeSignedCookie`.
pub fn sign_token(token: &str, secret: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use base64::Engine;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(token.as_bytes());
    let sig = mac.finalize().into_bytes();

    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);
    format!("{token}.{sig_b64}")
}

/// Verify an HMAC-SHA256 signed token of the form "{token}.{signature}".
///
/// Returns `Some(raw_token)` if valid, `None` otherwise.
/// Maps to TS `createHMAC("SHA-256", "base64urlnopad").verify(...)`.
pub fn verify_signed_token(signed: &str, secret: &str) -> Option<String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use base64::Engine;

    type HmacSha256 = Hmac<Sha256>;

    let (token, sig_b64) = signed.rsplit_once('.')?;

    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64)
        .ok()?;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(token.as_bytes());
    mac.verify_slice(&sig_bytes).ok()?;

    Some(token.to_string())
}

/// Process the bearer token from the Authorization header.
///
/// - If the token contains a `.`, it's already signed — verify the HMAC.
/// - Otherwise, sign it using the secret (unless `require_signature` is set).
///
/// Returns the signed cookie value to inject, or `None` if invalid/rejected.
pub fn process_bearer_token(
    raw_token: &str,
    secret: &str,
    require_signature: bool,
) -> Option<String> {
    if raw_token.contains('.') {
        // Token appears to be signed — verify it
        let verified = verify_signed_token(raw_token, secret);
        if verified.is_some() {
            // Return the full signed form for cookie injection
            Some(raw_token.to_string())
        } else {
            None // Invalid signature
        }
    } else {
        // Unsigned token
        if require_signature {
            None // Reject unsigned tokens when signature is required
        } else {
            // Sign it ourselves
            Some(sign_token(raw_token, secret))
        }
    }
}

/// Parse the `set-auth-token` value from a Set-Cookie header.
///
/// Looks for the session token cookie and returns its value.
pub fn extract_session_token_from_set_cookie(
    set_cookie: &str,
    cookie_name: &str,
) -> Option<String> {
    // Each Set-Cookie entry is semicolon-delimited; the first part is name=value
    for cookie in set_cookie.split(',') {
        let cookie = cookie.trim();
        if let Some(rest) = cookie.strip_prefix(&format!("{cookie_name}=")) {
            // Value is everything up to the first semicolon
            let value = rest.split(';').next().unwrap_or(rest);
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Build the set-auth-token response header and update Access-Control-Expose-Headers.
///
/// Returns `(token_header_value, expose_headers_value)`.
pub fn build_auth_token_headers(
    session_token: &str,
    existing_expose_headers: Option<&str>,
) -> (String, String) {
    let mut headers_set: Vec<String> = existing_expose_headers
        .map(|h| {
            h.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    if !headers_set.iter().any(|h| h.eq_ignore_ascii_case("set-auth-token")) {
        headers_set.push("set-auth-token".to_string());
    }

    (session_token.to_string(), headers_set.join(", "))
}

// ─── Plugin trait ───────────────────────────────────────────────────────

#[async_trait]
impl BetterAuthPlugin for BearerPlugin {
    fn id(&self) -> &str {
        "bearer"
    }

    fn name(&self) -> &str {
        "Bearer Token"
    }

    fn hooks(&self) -> Vec<PluginHook> {
        vec![
            // Before: convert Authorization header to cookie
            PluginHook {
                model: "*".to_string(),
                timing: HookTiming::Before,
                operation: HookOperation::Create,
            },
            // After: emit set-auth-token header
            PluginHook {
                model: "*".to_string(),
                timing: HookTiming::After,
                operation: HookOperation::Create,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bearer_plugin_id() {
        let plugin = BearerPlugin::default();
        assert_eq!(plugin.id(), "bearer");
    }

    #[test]
    fn test_bearer_plugin_options() {
        let plugin = BearerPlugin::new(BearerOptions {
            require_signature: true,
        });
        assert!(plugin.options.require_signature);
    }

    #[test]
    fn test_bearer_hooks() {
        let plugin = BearerPlugin::default();
        assert_eq!(plugin.hooks().len(), 2);
    }

    #[test]
    fn test_extract_bearer_token() {
        assert_eq!(extract_bearer_token("Bearer abc123"), Some("abc123"));
        assert_eq!(extract_bearer_token("bearer token"), Some("token"));
        assert_eq!(extract_bearer_token("Basic abc123"), None);
    }

    #[test]
    fn test_sign_and_verify() {
        let secret = "my-secret-key";
        let token = "session-token-123";
        let signed = sign_token(token, secret);

        assert!(signed.contains('.'));
        let verified = verify_signed_token(&signed, secret);
        assert_eq!(verified, Some(token.to_string()));
    }

    #[test]
    fn test_verify_invalid_signature() {
        let signed = "token.invalid-signature";
        assert!(verify_signed_token(signed, "secret").is_none());
    }

    #[test]
    fn test_process_bearer_unsigned() {
        let result = process_bearer_token("plain-token", "secret", false);
        assert!(result.is_some());
        assert!(result.unwrap().contains('.'));
    }

    #[test]
    fn test_process_bearer_unsigned_rejected() {
        let result = process_bearer_token("plain-token", "secret", true);
        assert!(result.is_none());
    }

    #[test]
    fn test_process_bearer_signed_valid() {
        let signed = sign_token("my-token", "secret");
        let result = process_bearer_token(&signed, "secret", true);
        assert!(result.is_some());
    }

    #[test]
    fn test_build_auth_token_headers() {
        let (token, expose) = build_auth_token_headers("tok123", None);
        assert_eq!(token, "tok123");
        assert_eq!(expose, "set-auth-token");
    }

    #[test]
    fn test_build_auth_token_headers_existing() {
        let (_, expose) = build_auth_token_headers("tok", Some("X-Custom, Content-Type"));
        assert!(expose.contains("set-auth-token"));
        assert!(expose.contains("X-Custom"));
    }

    #[test]
    fn test_extract_session_token() {
        let cookie = "better-auth.session_token=abc123; Path=/; HttpOnly";
        let result = extract_session_token_from_set_cookie(cookie, "better-auth.session_token");
        assert_eq!(result, Some("abc123".to_string()));
    }
}
