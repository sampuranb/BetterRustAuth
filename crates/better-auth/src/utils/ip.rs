// IP extraction utilities — maps to packages/better-auth/src/utils/get-request-ip.ts
//
// Extract and validate client IP addresses from request headers.

use std::collections::HashMap;
use std::net::IpAddr;

/// Default IP address headers to check.
const DEFAULT_IP_HEADERS: &[&str] = &["x-forwarded-for", "x-real-ip"];

/// Localhost fallback IP.
const LOCALHOST_IP: &str = "127.0.0.1";

/// Extract the client IP address from headers.
///
/// Matches TS `getIp`:
/// 1. Check configured IP headers (default: x-forwarded-for)
/// 2. Take the first IP from comma-separated lists (x-forwarded-for)
/// 3. Validate the IP
/// 4. Fall back to localhost in development
pub fn get_ip(headers: &HashMap<String, String>, custom_headers: Option<&[&str]>) -> Option<String> {
    let ip_headers = custom_headers.unwrap_or(DEFAULT_IP_HEADERS);

    for key in ip_headers {
        if let Some(value) = headers.get(*key) {
            // x-forwarded-for may contain multiple IPs separated by commas
            let ip = value.split(',').next().unwrap_or("").trim();
            if is_valid_ip(ip) {
                return Some(normalize_ip(ip));
            }
        }
    }

    None
}

/// Get IP with localhost fallback for development.
pub fn get_ip_or_localhost(
    headers: &HashMap<String, String>,
    custom_headers: Option<&[&str]>,
) -> String {
    get_ip(headers, custom_headers).unwrap_or_else(|| LOCALHOST_IP.to_string())
}

/// Check if a string is a valid IP address.
pub fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<IpAddr>().is_ok()
}

/// Normalize an IP address.
///
/// - IPv4: returned as-is
/// - IPv6: can optionally be truncated to a subnet prefix
pub fn normalize_ip(ip: &str) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.to_string(),
        Ok(IpAddr::V6(v6)) => {
            // Return the full IPv6 address
            // Subnet truncation can be added here when ipv6Subnet option is supported
            v6.to_string()
        }
        Err(_) => ip.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_ip_forwarded_for() {
        let mut headers = HashMap::new();
        headers.insert("x-forwarded-for".into(), "1.2.3.4, 5.6.7.8".into());
        assert_eq!(get_ip(&headers, None), Some("1.2.3.4".into()));
    }

    #[test]
    fn test_get_ip_real_ip() {
        let mut headers = HashMap::new();
        headers.insert("x-real-ip".into(), "10.0.0.1".into());
        assert_eq!(get_ip(&headers, None), Some("10.0.0.1".into()));
    }

    #[test]
    fn test_get_ip_no_headers() {
        let headers = HashMap::new();
        assert_eq!(get_ip(&headers, None), None);
    }

    #[test]
    fn test_get_ip_or_localhost() {
        let headers = HashMap::new();
        assert_eq!(get_ip_or_localhost(&headers, None), "127.0.0.1");
    }

    #[test]
    fn test_is_valid_ip() {
        assert!(is_valid_ip("127.0.0.1"));
        assert!(is_valid_ip("::1"));
        assert!(is_valid_ip("192.168.0.1"));
        assert!(!is_valid_ip("not-an-ip"));
        assert!(!is_valid_ip(""));
    }

    #[test]
    fn test_normalize_ip() {
        assert_eq!(normalize_ip("127.0.0.1"), "127.0.0.1");
        assert_eq!(normalize_ip("::1"), "::1");
    }

    #[test]
    fn test_custom_headers() {
        let mut headers = HashMap::new();
        headers.insert("cf-connecting-ip".into(), "9.8.7.6".into());
        let result = get_ip(&headers, Some(&["cf-connecting-ip"]));
        assert_eq!(result, Some("9.8.7.6".into()));
    }
}
