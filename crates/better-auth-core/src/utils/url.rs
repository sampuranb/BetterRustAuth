// URL utility functions — maps to packages/core/src/utils/url.ts + better-auth/src/utils/url.ts
//
// Provides URL parsing helpers used by trusted origin matching, callback
// validation, and base path normalization.

/// Extract the origin (scheme + host + port) from a URL.
/// Returns `None` for invalid URLs.
///
/// Examples:
///   "https://example.com/path" → "https://example.com"
///   "http://localhost:3000/api" → "http://localhost:3000"
pub fn get_origin(url: &str) -> Option<String> {
    // Handle relative URLs
    if url.starts_with('/') {
        return None;
    }

    // Find the scheme separator
    let scheme_end = url.find("://")?;
    let after_scheme = &url[scheme_end + 3..];

    // Find the end of the host (first / or end of string)
    let host_end = after_scheme.find('/').unwrap_or(after_scheme.len());
    let origin = &url[..scheme_end + 3 + host_end];

    Some(origin.to_string())
}

/// Extract the host (domain + port) from a URL, without the scheme.
///
/// Examples:
///   "https://example.com/path" → "example.com"
///   "http://localhost:3000/api" → "localhost:3000"
pub fn get_host(url: &str) -> Option<String> {
    let scheme_end = url.find("://")?;
    let after_scheme = &url[scheme_end + 3..];
    let host_end = after_scheme.find('/').unwrap_or(after_scheme.len());
    Some(after_scheme[..host_end].to_string())
}

/// Extract the protocol (scheme + colon) from a URL.
///
/// Examples:
///   "https://example.com" → "https:"
///   "http://localhost" → "http:"
pub fn get_protocol(url: &str) -> Option<String> {
    let scheme_end = url.find("://")?;
    Some(format!("{}:", &url[..scheme_end]))
}

/// Normalize a pathname by removing the base path prefix.
///
/// Example:
///   url = "https://example.com/api/auth/sign-in", base_path = "/api/auth"
///   → "/sign-in"
pub fn normalize_pathname(url: &str, base_path: &str) -> String {
    // Extract path from URL
    let path = if let Some(scheme_pos) = url.find("://") {
        let after_scheme = &url[scheme_pos + 3..];
        let path_start = after_scheme.find('/').unwrap_or(after_scheme.len());
        &after_scheme[path_start..]
    } else {
        url
    };

    // Strip query string
    let path = path.split('?').next().unwrap_or(path);

    // Remove base path prefix
    let normalized_base = base_path.trim_end_matches('/');
    if let Some(remainder) = path.strip_prefix(normalized_base) {
        if remainder.is_empty() {
            "/".to_string()
        } else {
            remainder.to_string()
        }
    } else {
        path.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_origin() {
        assert_eq!(get_origin("https://example.com/path"), Some("https://example.com".to_string()));
        assert_eq!(get_origin("http://localhost:3000/api"), Some("http://localhost:3000".to_string()));
        assert_eq!(get_origin("/relative/path"), None);
    }

    #[test]
    fn test_get_host() {
        assert_eq!(get_host("https://example.com/path"), Some("example.com".to_string()));
        assert_eq!(get_host("http://localhost:3000/api"), Some("localhost:3000".to_string()));
    }

    #[test]
    fn test_get_protocol() {
        assert_eq!(get_protocol("https://example.com"), Some("https:".to_string()));
        assert_eq!(get_protocol("http://localhost"), Some("http:".to_string()));
    }

    #[test]
    fn test_normalize_pathname() {
        assert_eq!(normalize_pathname("https://example.com/api/auth/sign-in", "/api/auth"), "/sign-in");
        assert_eq!(normalize_pathname("https://example.com/api/auth", "/api/auth"), "/");
        assert_eq!(normalize_pathname("/api/auth/sign-in?foo=bar", "/api/auth"), "/sign-in");
    }
}
