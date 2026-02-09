// Origin check and CSRF middleware — maps to packages/better-auth/src/api/middlewares/origin-check.ts
//
// Validates request origins against trusted origins list and provides CSRF
// protection using Fetch Metadata headers (Sec-Fetch-Site/Mode/Dest).

use super::MiddlewareError;
use super::trusted_origins::is_trusted_origin;

/// Origin check configuration.
#[derive(Debug, Clone)]
pub struct OriginCheckConfig {
    /// Skip all origin checks (for development/testing).
    pub skip_origin_check: bool,
    /// Skip CSRF checks specifically.
    pub skip_csrf_check: bool,
    /// Paths to skip origin checks for (e.g., webhooks).
    pub skip_paths: Vec<String>,
}

impl Default for OriginCheckConfig {
    fn default() -> Self {
        Self {
            skip_origin_check: false,
            skip_csrf_check: false,
            skip_paths: Vec::new(),
        }
    }
}

/// Validate that the request origin is trusted.
///
/// Matches TS `validateOrigin`:
/// - Skips GET/OPTIONS/HEAD methods
/// - Checks Origin/Referer header against trusted origins
/// - Respects skip flags and skip paths
pub fn validate_origin(
    method: &str,
    headers: &HeaderMap,
    request_path: &str,
    trusted_origins: &[String],
    config: &OriginCheckConfig,
) -> Result<(), MiddlewareError> {
    // Skip for safe methods
    if matches!(method, "GET" | "OPTIONS" | "HEAD") {
        return Ok(());
    }

    if config.skip_csrf_check {
        return Ok(());
    }

    // Check if the current path should be skipped
    if config.skip_origin_check {
        return Ok(());
    }

    // Check skip paths
    for skip_path in &config.skip_paths {
        if request_path.starts_with(skip_path) {
            return Ok(());
        }
    }

    // Only validate if cookies are present (cookie-based auth)
    let has_cookies = headers.contains_key("cookie");
    if !has_cookies {
        // No cookie-based session — try CSRF via Fetch Metadata
        return validate_csrf_fetch_metadata(headers, trusted_origins);
    }

    // Get origin from Origin or Referer header
    let origin = headers
        .get("origin")
        .or_else(|| headers.get("referer"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if origin.is_empty() || origin == "null" {
        return Err(MiddlewareError::Forbidden {
            code: "MISSING_OR_NULL_ORIGIN",
            message: "Origin header is missing or null".into(),
        });
    }

    if !is_trusted_origin(origin, trusted_origins, false) {
        return Err(MiddlewareError::Forbidden {
            code: "INVALID_ORIGIN",
            message: format!("Origin '{}' is not trusted. Add it to trustedOrigins.", origin),
        });
    }

    Ok(())
}

/// Validate CSRF using Fetch Metadata headers.
///
/// Matches TS `validateFormCsrf`:
/// - Blocks cross-site navigation requests (Sec-Fetch-Site: cross-site + Sec-Fetch-Mode: navigate)
/// - Falls back to origin validation when Fetch Metadata is present
fn validate_csrf_fetch_metadata(
    headers: &HeaderMap,
    trusted_origins: &[String],
) -> Result<(), MiddlewareError> {
    let site = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok());
    let mode = headers.get("sec-fetch-mode").and_then(|v| v.to_str().ok());
    let dest = headers.get("sec-fetch-dest").and_then(|v| v.to_str().ok());

    let has_metadata = site.map_or(false, |s| !s.trim().is_empty())
        || mode.map_or(false, |s| !s.trim().is_empty())
        || dest.map_or(false, |s| !s.trim().is_empty());

    if !has_metadata {
        // No cookies, no Fetch Metadata → no validation needed
        return Ok(());
    }

    // Block cross-site navigation requests (classic CSRF attack)
    if site == Some("cross-site") && mode == Some("navigate") {
        return Err(MiddlewareError::Forbidden {
            code: "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED",
            message: "Cross-site navigation login attempt blocked (CSRF protection)".into(),
        });
    }

    // Fetch Metadata present — validate origin
    let origin = headers
        .get("origin")
        .or_else(|| headers.get("referer"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if origin.is_empty() || origin == "null" {
        // Metadata present but no origin — this is suspicious but allow if same-origin
        if site == Some("same-origin") || site == Some("none") {
            return Ok(());
        }
        return Err(MiddlewareError::Forbidden {
            code: "MISSING_OR_NULL_ORIGIN",
            message: "Origin header missing with cross-site Fetch Metadata".into(),
        });
    }

    if !is_trusted_origin(origin, trusted_origins, false) {
        return Err(MiddlewareError::Forbidden {
            code: "INVALID_ORIGIN",
            message: format!("Origin '{}' is not trusted.", origin),
        });
    }

    Ok(())
}

/// Validate callback/redirect URLs against trusted origins.
///
/// Matches TS origin check for callbackURL, redirectTo, errorCallbackURL.
pub fn validate_callback_url(
    url: &str,
    trusted_origins: &[String],
    label: &str,
) -> Result<(), MiddlewareError> {
    if url.is_empty() {
        return Ok(());
    }

    if !is_trusted_origin(url, trusted_origins, true) {
        let code = match label {
            "callbackURL" => "INVALID_CALLBACK_URL",
            "redirectURL" => "INVALID_REDIRECT_URL",
            "errorCallbackURL" => "INVALID_ERROR_CALLBACK_URL",
            "newUserCallbackURL" => "INVALID_NEW_USER_CALLBACK_URL",
            _ => "INVALID_ORIGIN",
        };
        return Err(MiddlewareError::Forbidden {
            code,
            message: format!("Invalid {}: '{}'. Add it to trustedOrigins.", label, url),
        });
    }

    Ok(())
}

/// Re-export for convenience.
type HeaderMap = std::collections::HashMap<String, HeaderValue>;

/// Simple header value wrapper.
#[derive(Debug, Clone)]
pub struct HeaderValue(String);

impl HeaderValue {
    pub fn new(s: &str) -> Self {
        Self(s.to_string())
    }

    pub fn to_str(&self) -> Result<&str, ()> {
        Ok(&self.0)
    }
}


/// Trait for header map access.
trait HeaderMapExt {
    fn get(&self, key: &str) -> Option<&HeaderValue>;
    fn contains_key(&self, key: &str) -> bool;
}

impl HeaderMapExt for HeaderMap {
    fn get(&self, key: &str) -> Option<&HeaderValue> {
        std::collections::HashMap::get(self, key)
    }

    fn contains_key(&self, key: &str) -> bool {
        std::collections::HashMap::contains_key(self, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.insert(k.to_string(), HeaderValue::new(v));
        }
        map
    }

    #[test]
    fn test_skip_safe_methods() {
        let config = OriginCheckConfig::default();
        let headers = make_headers(&[]);
        let origins = vec!["https://example.com".into()];

        assert!(validate_origin("GET", &headers, "/api", &origins, &config).is_ok());
        assert!(validate_origin("OPTIONS", &headers, "/api", &origins, &config).is_ok());
        assert!(validate_origin("HEAD", &headers, "/api", &origins, &config).is_ok());
    }

    #[test]
    fn test_valid_origin_with_cookie() {
        let config = OriginCheckConfig::default();
        let headers = make_headers(&[
            ("cookie", "session=abc"),
            ("origin", "https://example.com"),
        ]);
        let origins = vec!["https://example.com".into()];

        assert!(validate_origin("POST", &headers, "/api", &origins, &config).is_ok());
    }

    #[test]
    fn test_invalid_origin_with_cookie() {
        let config = OriginCheckConfig::default();
        let headers = make_headers(&[
            ("cookie", "session=abc"),
            ("origin", "https://evil.com"),
        ]);
        let origins = vec!["https://example.com".into()];

        let result = validate_origin("POST", &headers, "/api", &origins, &config);
        assert!(result.is_err());
        match result.unwrap_err() {
            MiddlewareError::Forbidden { code, .. } => assert_eq!(code, "INVALID_ORIGIN"),
            _ => panic!("Expected Forbidden"),
        }
    }

    #[test]
    fn test_missing_origin_with_cookie() {
        let config = OriginCheckConfig::default();
        let headers = make_headers(&[("cookie", "session=abc")]);
        let origins = vec!["https://example.com".into()];

        let result = validate_origin("POST", &headers, "/api", &origins, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_csrf_cross_site_navigate_blocked() {
        let headers = make_headers(&[
            ("sec-fetch-site", "cross-site"),
            ("sec-fetch-mode", "navigate"),
        ]);
        let origins = vec!["https://example.com".into()];

        let result = validate_csrf_fetch_metadata(&headers, &origins);
        assert!(result.is_err());
        match result.unwrap_err() {
            MiddlewareError::Forbidden { code, .. } => {
                assert_eq!(code, "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED");
            }
            _ => panic!("Expected Forbidden"),
        }
    }

    #[test]
    fn test_csrf_same_origin_allowed() {
        let headers = make_headers(&[
            ("sec-fetch-site", "same-origin"),
            ("sec-fetch-mode", "cors"),
        ]);
        let origins = vec!["https://example.com".into()];

        assert!(validate_csrf_fetch_metadata(&headers, &origins).is_ok());
    }

    #[test]
    fn test_skip_origin_check() {
        let config = OriginCheckConfig {
            skip_origin_check: true,
            ..Default::default()
        };
        let headers = make_headers(&[
            ("cookie", "session=abc"),
            ("origin", "https://evil.com"),
        ]);
        let origins = vec!["https://example.com".into()];

        assert!(validate_origin("POST", &headers, "/api", &origins, &config).is_ok());
    }

    #[test]
    fn test_validate_callback_url() {
        let origins = vec!["https://example.com".into()];

        assert!(validate_callback_url("https://example.com/callback", &origins, "callbackURL").is_ok());
        assert!(validate_callback_url("/callback", &origins, "callbackURL").is_ok());

        let result = validate_callback_url("https://evil.com/callback", &origins, "callbackURL");
        assert!(result.is_err());
        match result.unwrap_err() {
            MiddlewareError::Forbidden { code, .. } => assert_eq!(code, "INVALID_CALLBACK_URL"),
            _ => panic!("Expected Forbidden"),
        }
    }
}
