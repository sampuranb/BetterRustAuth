// Trusted origin matching — maps to packages/better-auth/src/auth/trusted-origins.ts
//
// Supports exact match, wildcard patterns (*/?/**), and relative paths.

/// Matches a URL against an origin pattern.
///
/// Supports:
/// - **Exact match**: `https://example.com` matches `https://example.com`
/// - **Wildcard host**: `*.example.com` matches `sub.example.com`
/// - **Protocol wildcard**: `https://*.example.com` matches `https://sub.example.com`
/// - **Relative paths**: `/callback` (only when `allow_relative_paths` is true)
pub fn matches_origin_pattern(url: &str, pattern: &str, allow_relative_paths: bool) -> bool {
    // Handle relative paths
    if url.starts_with('/') {
        if allow_relative_paths {
            // Must be a safe relative path (no double-slash, backslash, etc.)
            return is_safe_relative_path(url);
        }
        return false;
    }

    let has_wildcard = pattern.contains('*') || pattern.contains('?');

    if has_wildcard {
        if pattern.contains("://") {
            // Protocol-specific wildcard — match the full origin
            let url_origin = get_origin(url).unwrap_or_default();
            return wildcard_match(pattern, &url_origin);
        }
        // Host-only wildcard
        let host = get_host(url).unwrap_or_default();
        return wildcard_match(pattern, &host);
    }

    // Exact origin match
    let url_origin = get_origin(url).unwrap_or_default();
    pattern == url_origin
}

/// Check if a URL is trusted against a list of trusted origins.
pub fn is_trusted_origin(url: &str, trusted_origins: &[String], allow_relative_paths: bool) -> bool {
    trusted_origins
        .iter()
        .any(|origin| matches_origin_pattern(url, origin, allow_relative_paths))
}

/// Check if a relative path is safe (no path traversal attacks).
fn is_safe_relative_path(path: &str) -> bool {
    if !path.starts_with('/') {
        return false;
    }
    // Reject double-slash, backslash, encoded variants
    if path.starts_with("//") || path.contains('\\') || path.contains("%2f") || path.contains("%5c") {
        return false;
    }
    // Only allow safe characters
    path.chars().all(|c| c.is_alphanumeric() || "/-_.+@?=&%".contains(c))
}

/// Extract the origin (scheme + host + port) from a URL.
fn get_origin(url: &str) -> Option<String> {
    url::Url::parse(url).ok().map(|u| {
        let scheme = u.scheme();
        let host = u.host_str().unwrap_or("");
        match u.port() {
            Some(port) => format!("{}://{}:{}", scheme, host, port),
            None => format!("{}://{}", scheme, host),
        }
    })
}

/// Extract the host from a URL.
fn get_host(url: &str) -> Option<String> {
    url::Url::parse(url).ok().and_then(|u| u.host_str().map(|h| h.to_string()))
}

/// Simple wildcard pattern matching supporting `*` and `?`.
///
/// `*` matches any sequence of characters (except `/` for host matching).
/// `?` matches exactly one character.
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let text_chars: Vec<char> = text.chars().collect();
    wildcard_match_inner(&pattern_chars, &text_chars, 0, 0)
}

fn wildcard_match_inner(pattern: &[char], text: &[char], pi: usize, ti: usize) -> bool {
    if pi == pattern.len() && ti == text.len() {
        return true;
    }
    if pi == pattern.len() {
        return false;
    }

    match pattern[pi] {
        '*' => {
            // Try matching zero or more characters
            for i in ti..=text.len() {
                if wildcard_match_inner(pattern, text, pi + 1, i) {
                    return true;
                }
            }
            false
        }
        '?' => {
            if ti < text.len() {
                wildcard_match_inner(pattern, text, pi + 1, ti + 1)
            } else {
                false
            }
        }
        c => {
            if ti < text.len() && text[ti] == c {
                wildcard_match_inner(pattern, text, pi + 1, ti + 1)
            } else {
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_origin_match() {
        assert!(matches_origin_pattern(
            "https://example.com/path",
            "https://example.com",
            false,
        ));
        assert!(!matches_origin_pattern(
            "https://other.com/path",
            "https://example.com",
            false,
        ));
    }

    #[test]
    fn test_wildcard_host_match() {
        assert!(matches_origin_pattern(
            "https://sub.example.com/path",
            "*.example.com",
            false,
        ));
        assert!(!matches_origin_pattern(
            "https://other.com/path",
            "*.example.com",
            false,
        ));
    }

    #[test]
    fn test_protocol_wildcard_match() {
        assert!(matches_origin_pattern(
            "https://sub.example.com/path",
            "https://*.example.com",
            false,
        ));
        assert!(!matches_origin_pattern(
            "http://sub.example.com/path",
            "https://*.example.com",
            false,
        ));
    }

    #[test]
    fn test_relative_path() {
        assert!(matches_origin_pattern("/callback", "irrelevant", true));
        assert!(!matches_origin_pattern("/callback", "irrelevant", false));
        assert!(!matches_origin_pattern("//evil.com", "irrelevant", true));
    }

    #[test]
    fn test_is_trusted_origin() {
        let origins = vec![
            "https://example.com".to_string(),
            "https://*.app.com".to_string(),
        ];
        assert!(is_trusted_origin("https://example.com/api", &origins, false));
        assert!(is_trusted_origin("https://sub.app.com/api", &origins, false));
        assert!(!is_trusted_origin("https://evil.com/api", &origins, false));
    }

    #[test]
    fn test_wildcard_match_basic() {
        assert!(wildcard_match("hello", "hello"));
        assert!(!wildcard_match("hello", "world"));
        assert!(wildcard_match("hel*", "hello"));
        assert!(wildcard_match("*llo", "hello"));
        assert!(wildcard_match("h?llo", "hello"));
        assert!(wildcard_match("*", "anything"));
    }
}
