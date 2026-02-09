// URL parsing utilities — maps to packages/better-auth/src/utils/url.ts
//
// URL validation, base URL resolution, origin extraction, and proxy header validation.

/// Check if a URL has a non-root path.
pub fn has_path(url_str: &str) -> Result<bool, String> {
    let parsed = url::Url::parse(url_str)
        .map_err(|_| format!("Invalid base URL: {}. Please provide a valid base URL.", url_str))?;
    let path = parsed.path().trim_end_matches('/');
    Ok(!path.is_empty() && path != "/")
}

/// Assert that a URL has a valid protocol (http or https).
pub fn assert_has_protocol(url_str: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url_str)
        .map_err(|_| format!("Invalid base URL: {}", url_str))?;
    match parsed.scheme() {
        "http" | "https" => Ok(()),
        _ => Err(format!(
            "Invalid base URL: {}. URL must include 'http://' or 'https://'",
            url_str
        )),
    }
}

/// Append a path to a URL if it doesn't already have one.
///
/// Matches TS `withPath`.
pub fn with_path(url_str: &str, path: &str) -> Result<String, String> {
    assert_has_protocol(url_str)?;

    if has_path(url_str)? {
        return Ok(url_str.to_string());
    }

    let trimmed = url_str.trim_end_matches('/');

    if path.is_empty() || path == "/" {
        return Ok(trimmed.to_string());
    }

    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    };

    Ok(format!("{}{}", trimmed, path))
}

/// Get the base URL from options, environment, or request.
///
/// Matches TS `getBaseURL`.
pub fn get_base_url(
    url: Option<&str>,
    path: Option<&str>,
) -> Option<String> {
    let default_path = "/api/auth";
    let path = path.unwrap_or(default_path);

    if let Some(url) = url {
        return with_path(url, path).ok();
    }

    // Check environment variables
    if let Ok(env_url) = std::env::var("BETTER_AUTH_URL") {
        if !env_url.is_empty() {
            return with_path(&env_url, path).ok();
        }
    }

    None
}

/// Extract the origin from a URL.
///
/// Matches TS `getOrigin`.
pub fn get_origin(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .map(|parsed| {
            let origin = parsed.origin().ascii_serialization();
            if origin == "null" { None } else { Some(origin) }
        })
        .flatten()
}

/// Extract the protocol from a URL.
pub fn get_protocol(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .map(|parsed| parsed.scheme().to_string())
}

/// Extract the host from a URL.
pub fn get_host(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(|h| {
            match parsed.port() {
                Some(port) => format!("{}:{}", h, port),
                None => h.to_string(),
            }
        }))
}

/// Validate a proxy header value.
///
/// Matches TS `validateProxyHeader`.
pub fn validate_proxy_header(header: &str, header_type: ProxyHeaderType) -> bool {
    let header = header.trim();
    if header.is_empty() {
        return false;
    }

    match header_type {
        ProxyHeaderType::Proto => header == "http" || header == "https",
        ProxyHeaderType::Host => {
            // Check for suspicious patterns
            if header.contains("..")
                || header.contains('\0')
                || header.contains('<')
                || header.contains('>')
                || header.contains('\'')
                || header.contains('"')
                || header.starts_with('.')
            {
                return false;
            }

            // Check for protocol injection
            let lower = header.to_lowercase();
            if lower.contains("javascript:")
                || lower.contains("file:")
                || lower.contains("data:")
            {
                return false;
            }

            // Basic hostname validation
            let hostname_re = regex::Regex::new(
                r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*(:[0-9]{1,5})?$"
            ).unwrap();

            let ipv4_re = regex::Regex::new(
                r"^(\d{1,3}\.){3}\d{1,3}(:[0-9]{1,5})?$"
            ).unwrap();

            let localhost_re = regex::Regex::new(
                r"(?i)^localhost(:[0-9]{1,5})?$"
            ).unwrap();

            hostname_re.is_match(header)
                || ipv4_re.is_match(header)
                || localhost_re.is_match(header)
        }
    }
}

/// Proxy header type for validation.
#[derive(Debug, Clone, Copy)]
pub enum ProxyHeaderType {
    Host,
    Proto,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_path() {
        assert!(has_path("https://example.com/api/auth").unwrap());
        assert!(!has_path("https://example.com").unwrap());
        assert!(!has_path("https://example.com/").unwrap());
    }

    #[test]
    fn test_assert_has_protocol() {
        assert!(assert_has_protocol("https://example.com").is_ok());
        assert!(assert_has_protocol("http://localhost").is_ok());
        assert!(assert_has_protocol("ftp://example.com").is_err());
    }

    #[test]
    fn test_with_path() {
        assert_eq!(
            with_path("https://example.com", "/api/auth").unwrap(),
            "https://example.com/api/auth"
        );
        // Already has a path — return as-is
        assert_eq!(
            with_path("https://example.com/existing", "/api/auth").unwrap(),
            "https://example.com/existing"
        );
    }

    #[test]
    fn test_get_origin() {
        assert_eq!(
            get_origin("https://example.com/path"),
            Some("https://example.com".into())
        );
        assert_eq!(get_origin("invalid"), None);
    }

    #[test]
    fn test_get_host() {
        assert_eq!(
            get_host("https://example.com:8080/path"),
            Some("example.com:8080".into())
        );
        assert_eq!(
            get_host("https://example.com/path"),
            Some("example.com".into())
        );
    }

    #[test]
    fn test_validate_proxy_header_proto() {
        assert!(validate_proxy_header("https", ProxyHeaderType::Proto));
        assert!(validate_proxy_header("http", ProxyHeaderType::Proto));
        assert!(!validate_proxy_header("ftp", ProxyHeaderType::Proto));
        assert!(!validate_proxy_header("", ProxyHeaderType::Proto));
    }

    #[test]
    fn test_validate_proxy_header_host() {
        assert!(validate_proxy_header("example.com", ProxyHeaderType::Host));
        assert!(validate_proxy_header("localhost:3000", ProxyHeaderType::Host));
        assert!(validate_proxy_header("192.168.1.1", ProxyHeaderType::Host));
        assert!(!validate_proxy_header("../evil", ProxyHeaderType::Host));
        assert!(!validate_proxy_header("<script>", ProxyHeaderType::Host));
    }
}
