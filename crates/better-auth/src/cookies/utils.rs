// Cookie utilities — maps to packages/better-auth/src/cookies/cookie-utils.ts
//
// Cookie parsing, Set-Cookie header handling, and cookie name prefix utilities.

use std::collections::HashMap;

/// Cookie attributes for a single cookie.
#[derive(Debug, Clone)]
pub struct CookieAttributes {
    pub value: String,
    pub max_age: Option<i64>,
    pub expires: Option<String>,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<SameSite>,
}

/// SameSite cookie attribute values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl std::fmt::Display for SameSite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SameSite::Strict => write!(f, "Strict"),
            SameSite::Lax => write!(f, "Lax"),
            SameSite::None => write!(f, "None"),
        }
    }
}

/// Cookie prefixes for secure contexts.
pub const SECURE_COOKIE_PREFIX: &str = "__Secure-";
pub const HOST_COOKIE_PREFIX: &str = "__Host-";

/// Remove __Secure- or __Host- prefix from a cookie name.
pub fn strip_secure_cookie_prefix(cookie_name: &str) -> &str {
    if let Some(rest) = cookie_name.strip_prefix(SECURE_COOKIE_PREFIX) {
        return rest;
    }
    if let Some(rest) = cookie_name.strip_prefix(HOST_COOKIE_PREFIX) {
        return rest;
    }
    cookie_name
}

/// Parse a `Cookie` header string into a map of name → value.
///
/// Maps to TypeScript `parseCookies(cookieHeader)`.
pub fn parse_cookies(cookie_header: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for cookie in cookie_header.split("; ") {
        if let Some((name, value)) = cookie.split_once('=') {
            map.insert(name.to_string(), value.to_string());
        }
    }
    map
}

/// Split a `Set-Cookie` header value into individual cookie strings,
/// handling commas inside `Expires` date values.
///
/// Maps to TypeScript `splitSetCookieHeader`.
pub fn split_set_cookie_header(set_cookie: &str) -> Vec<String> {
    if set_cookie.is_empty() {
        return Vec::new();
    }

    let mut result = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = set_cookie.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];

        if c == ',' {
            let lower = current.to_lowercase();
            if lower.contains("expires=") && !lower.contains("gmt") {
                // Comma is part of the Expires date, keep going
                current.push(c);
                i += 1;
            } else {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    result.push(trimmed);
                }
                current = String::new();
                i += 1;
                // Skip leading space after comma
                if i < chars.len() && chars[i] == ' ' {
                    i += 1;
                }
            }
            continue;
        }

        current.push(c);
        i += 1;
    }

    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        result.push(trimmed);
    }

    result
}

/// Parse a `Set-Cookie` header into a map of cookie name → attributes.
///
/// Maps to TypeScript `parseSetCookieHeader`.
pub fn parse_set_cookie_header(set_cookie: &str) -> HashMap<String, CookieAttributes> {
    let mut cookies = HashMap::new();
    let cookie_array = split_set_cookie_header(set_cookie);

    for cookie_string in cookie_array {
        let parts: Vec<&str> = cookie_string.split(';').map(|s| s.trim()).collect();
        if parts.is_empty() {
            continue;
        }

        let name_value = parts[0];
        let (name, value) = match name_value.split_once('=') {
            Some((n, v)) => (n.to_string(), v.to_string()),
            None => continue,
        };

        if name.is_empty() {
            continue;
        }

        let mut attrs = CookieAttributes {
            value,
            max_age: None,
            expires: None,
            domain: None,
            path: None,
            secure: false,
            http_only: false,
            same_site: None,
        };

        for attr in &parts[1..] {
            let (attr_name, attr_value) = match attr.split_once('=') {
                Some((n, v)) => (n.trim().to_lowercase(), Some(v.trim().to_string())),
                None => (attr.trim().to_lowercase(), None),
            };

            match attr_name.as_str() {
                "max-age" => {
                    attrs.max_age = attr_value.as_deref().and_then(|v| v.parse().ok());
                }
                "expires" => {
                    attrs.expires = attr_value;
                }
                "domain" => {
                    attrs.domain = attr_value;
                }
                "path" => {
                    attrs.path = attr_value;
                }
                "secure" => {
                    attrs.secure = true;
                }
                "httponly" => {
                    attrs.http_only = true;
                }
                "samesite" => {
                    attrs.same_site = attr_value.as_deref().map(|v| match v.to_lowercase().as_str() {
                        "strict" => SameSite::Strict,
                        "lax" => SameSite::Lax,
                        "none" => SameSite::None,
                        _ => SameSite::Lax,
                    });
                }
                _ => {}
            }
        }

        cookies.insert(name, attrs);
    }

    cookies
}

/// Serialize a `CookieAttributes` into a `Set-Cookie` header value string.
pub fn serialize_cookie(name: &str, attrs: &CookieAttributes) -> String {
    let mut parts = vec![format!("{}={}", name, attrs.value)];

    if let Some(max_age) = attrs.max_age {
        parts.push(format!("Max-Age={}", max_age));
    }
    if let Some(ref expires) = attrs.expires {
        parts.push(format!("Expires={}", expires));
    }
    if let Some(ref domain) = attrs.domain {
        parts.push(format!("Domain={}", domain));
    }
    if let Some(ref path) = attrs.path {
        parts.push(format!("Path={}", path));
    }
    if attrs.secure {
        parts.push("Secure".into());
    }
    if attrs.http_only {
        parts.push("HttpOnly".into());
    }
    if let Some(same_site) = attrs.same_site {
        parts.push(format!("SameSite={}", same_site));
    }

    parts.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cookies() {
        let header = "session=abc123; user=john; theme=dark";
        let cookies = parse_cookies(header);
        assert_eq!(cookies.get("session").unwrap(), "abc123");
        assert_eq!(cookies.get("user").unwrap(), "john");
        assert_eq!(cookies.get("theme").unwrap(), "dark");
    }

    #[test]
    fn test_strip_secure_prefix() {
        assert_eq!(strip_secure_cookie_prefix("__Secure-session"), "session");
        assert_eq!(strip_secure_cookie_prefix("__Host-session"), "session");
        assert_eq!(strip_secure_cookie_prefix("session"), "session");
    }

    #[test]
    fn test_split_set_cookie_header() {
        let header = "a=1; Path=/, b=2; Secure";
        let parts = split_set_cookie_header(header);
        assert_eq!(parts.len(), 2);
        assert!(parts[0].starts_with("a=1"));
        assert!(parts[1].starts_with("b=2"));
    }

    #[test]
    fn test_parse_set_cookie_header() {
        let header = "session=abc; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600";
        let cookies = parse_set_cookie_header(header);
        let session = cookies.get("session").unwrap();
        assert_eq!(session.value, "abc");
        assert_eq!(session.path.as_deref(), Some("/"));
        assert!(session.http_only);
        assert!(session.secure);
        assert_eq!(session.same_site, Some(SameSite::Lax));
        assert_eq!(session.max_age, Some(3600));
    }

    #[test]
    fn test_serialize_cookie() {
        let attrs = CookieAttributes {
            value: "abc".into(),
            max_age: Some(3600),
            expires: None,
            domain: None,
            path: Some("/".into()),
            secure: true,
            http_only: true,
            same_site: Some(SameSite::Lax),
        };
        let serialized = serialize_cookie("session", &attrs);
        assert!(serialized.contains("session=abc"));
        assert!(serialized.contains("Max-Age=3600"));
        assert!(serialized.contains("Path=/"));
        assert!(serialized.contains("Secure"));
        assert!(serialized.contains("HttpOnly"));
        assert!(serialized.contains("SameSite=Lax"));
    }
}
