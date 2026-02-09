// Cookie management — maps to packages/better-auth/src/cookies/index.ts
//
// Session cookies, cookie cache (3 strategies), and auth cookie creation.

pub mod session_cookie;
pub mod session_store;
pub mod utils;

pub use session_cookie::{ResponseCookies, SessionUser, CookieCacheConfig, set_session_cookie, delete_session_cookie, get_cookie_cache, get_cookie_cache_with_config};
pub use session_store::{CookieChunk, chunk_cookie_value, clean_chunk_cookies, get_chunked_cookie};
pub use utils::*;

use crate::crypto;
use better_auth_core::options::BetterAuthOptions;

/// The set of auth-related cookies.
#[derive(Debug, Clone)]
pub struct BetterAuthCookies {
    pub session_token: AuthCookie,
    pub session_data: AuthCookie,
    pub dont_remember_token: AuthCookie,
    pub account_data: AuthCookie,
}

/// A single auth cookie definition (name + default attributes).
#[derive(Debug, Clone)]
pub struct AuthCookie {
    pub name: String,
    pub secure: bool,
    pub same_site: SameSite,
    pub path: String,
    pub http_only: bool,
    pub max_age: Option<i64>,
    pub domain: Option<String>,
}

impl AuthCookie {
    /// Create a CookieAttributes with the stored defaults + a specific value.
    pub fn to_attributes(&self, value: &str) -> CookieAttributes {
        CookieAttributes {
            value: value.to_string(),
            max_age: self.max_age,
            expires: None,
            domain: self.domain.clone(),
            path: Some(self.path.clone()),
            secure: self.secure,
            http_only: self.http_only,
            same_site: Some(self.same_site),
        }
    }
}

/// Create an auth cookie with the standard naming convention.
///
/// Maps to TypeScript `createCookieGetter` → `createCookie`.
pub fn create_auth_cookie(
    cookie_name: &str,
    prefix: &str,
    secure: bool,
    cross_subdomain: Option<&str>,
    max_age: Option<i64>,
) -> AuthCookie {
    let secure_prefix = if secure { SECURE_COOKIE_PREFIX } else { "" };
    let name = format!("{}{}.{}", secure_prefix, prefix, cookie_name);

    AuthCookie {
        name,
        secure,
        same_site: SameSite::Lax,
        path: "/".to_string(),
        http_only: true,
        max_age,
        domain: cross_subdomain.map(|d| d.to_string()),
    }
}

/// Build the full set of auth cookies from options.
///
/// Maps to TypeScript `getCookies(options)`.
pub fn get_cookies(options: &BetterAuthOptions) -> BetterAuthCookies {
    let secure = options
        .base_url
        .as_ref()
        .map(|u| u.starts_with("https://"))
        .unwrap_or(false);

    let prefix = options
        .advanced
        .cookie_prefix
        .as_deref()
        .unwrap_or("better-auth");

    let cross_subdomain = options
        .advanced
        .cross_sub_domain_cookies
        .as_ref()
        .filter(|c| c.enabled)
        .and_then(|c| c.domain.as_deref());

    let session_max_age = options.session.expires_in as i64;

    let cache_max_age = options.session.cookie_cache.max_age as i64;

    BetterAuthCookies {
        session_token: create_auth_cookie(
            "session_token",
            prefix,
            secure,
            cross_subdomain,
            Some(session_max_age),
        ),
        session_data: create_auth_cookie(
            "session_data",
            prefix,
            secure,
            cross_subdomain,
            Some(cache_max_age),
        ),
        dont_remember_token: create_auth_cookie(
            "dont_remember",
            prefix,
            secure,
            cross_subdomain,
            None,
        ),
        account_data: create_auth_cookie(
            "account_data",
            prefix,
            secure,
            cross_subdomain,
            Some(cache_max_age),
        ),
    }
}

/// Get the session token from a cookie header string.
///
/// Maps to TypeScript `getSessionCookie`.
pub fn get_session_cookie(
    cookie_header: &str,
    cookie_prefix: Option<&str>,
    cookie_name: Option<&str>,
) -> Option<String> {
    let prefix = cookie_prefix.unwrap_or("better-auth");
    let name = cookie_name.unwrap_or("session_token");
    let full_name = format!("{}.{}", prefix, name);
    let secure_name = format!("{}{}", SECURE_COOKIE_PREFIX, full_name);

    let cookies = parse_cookies(cookie_header);
    cookies
        .get(&full_name)
        .or_else(|| cookies.get(&secure_name))
        .cloned()
}

/// Create an HMAC-signed cookie value.
///
/// Format: `value.signature`
pub fn sign_cookie_value(
    value: &str,
    secret: &str,
) -> Result<String, better_auth_core::error::BetterAuthError> {
    let signature = crypto::make_signature(value, secret)?;
    Ok(format!("{}.{}", value, signature))
}

/// Verify and extract the value from a signed cookie.
///
/// Returns `None` if the signature doesn't match.
pub fn verify_signed_cookie(cookie_value: &str, secret: &str) -> Option<String> {
    // Find the last dot (signature is always 44 chars base64)
    let dot_pos = cookie_value.rfind('.')?;
    let (value, signature) = cookie_value.split_at(dot_pos);
    let signature = &signature[1..]; // Skip the dot

    let expected = crypto::make_signature(value, secret).ok()?;
    if crypto::constant_time_equal(expected.as_bytes(), signature.as_bytes()) {
        Some(value.to_string())
    } else {
        None
    }
}

/// Create an expired cookie (for deletion).
///
/// Maps to TypeScript `expireCookie`.
pub fn expire_cookie(cookie: &AuthCookie) -> CookieAttributes {
    CookieAttributes {
        value: String::new(),
        max_age: Some(0),
        expires: None,
        domain: cookie.domain.clone(),
        path: Some(cookie.path.clone()),
        secure: cookie.secure,
        http_only: cookie.http_only,
        same_site: Some(cookie.same_site),
    }
}

// ─── Account Cookie Store ────────────────────────────────────────
//
// Maps to TypeScript `setAccountCookie` / `getAccountCookie` in session-store.ts.
// Uses symmetric encryption (XChaCha20-Poly1305) to store linked account data.

/// Encrypt account data and store as a cookie, with chunking if needed.
///
/// Maps to TypeScript `setAccountCookie`.
pub fn set_account_cookie(
    cookies: &mut session_cookie::ResponseCookies,
    auth_cookies: &BetterAuthCookies,
    secret: &str,
    account_data: &serde_json::Value,
) {
    let json_str = match serde_json::to_string(account_data) {
        Ok(s) => s,
        Err(_) => return,
    };

    let encrypted = match crypto::symmetric_encrypt(secret, &json_str) {
        Ok(enc) => enc,
        Err(_) => return,
    };

    let max_age = auth_cookies.account_data.max_age;

    if encrypted.len() > session_store::MAX_COOKIE_SIZE {
        // Chunk the cookie
        let chunks = chunk_cookie_value(&auth_cookies.account_data.name, &encrypted);
        for chunk in &chunks {
            let attrs = CookieAttributes {
                value: chunk.value.clone(),
                max_age,
                expires: None,
                domain: auth_cookies.account_data.domain.clone(),
                path: Some(auth_cookies.account_data.path.clone()),
                secure: auth_cookies.account_data.secure,
                http_only: auth_cookies.account_data.http_only,
                same_site: Some(auth_cookies.account_data.same_site),
            };
            cookies.set_cookie(&chunk.name, &attrs);
        }
    } else {
        let attrs = CookieAttributes {
            value: encrypted,
            max_age,
            expires: None,
            domain: auth_cookies.account_data.domain.clone(),
            path: Some(auth_cookies.account_data.path.clone()),
            secure: auth_cookies.account_data.secure,
            http_only: auth_cookies.account_data.http_only,
            same_site: Some(auth_cookies.account_data.same_site),
        };
        cookies.set_cookie(&auth_cookies.account_data.name, &attrs);
    }
}

/// Read and decrypt account data from cookies.
///
/// Maps to TypeScript `getAccountCookie`.
pub fn get_account_cookie(
    cookie_header: &str,
    auth_cookies: &BetterAuthCookies,
    secret: &str,
) -> Option<serde_json::Value> {
    let cookies = parse_cookies(cookie_header);
    let data = get_chunked_cookie(&cookies, &auth_cookies.account_data.name)?;
    let decrypted = crypto::symmetric_decrypt(secret, &data).ok()?;
    serde_json::from_str(&decrypted).ok()
}

/// Delete account data cookies (expire main + chunks).
///
/// Maps to the account cookie cleanup in TypeScript `deleteSessionCookie`.
pub fn delete_account_cookies(
    cookies: &mut session_cookie::ResponseCookies,
    auth_cookies: &BetterAuthCookies,
) {
    // Expire the main account_data cookie
    cookies.expire_cookie(&auth_cookies.account_data);

    // Clean up account data chunks (assume up to 10)
    let chunk_cookies = clean_chunk_cookies(&auth_cookies.account_data.name, 10);
    for chunk in &chunk_cookies {
        let attrs = CookieAttributes {
            value: String::new(),
            max_age: Some(0),
            expires: None,
            domain: auth_cookies.account_data.domain.clone(),
            path: Some(auth_cookies.account_data.path.clone()),
            secure: auth_cookies.account_data.secure,
            http_only: auth_cookies.account_data.http_only,
            same_site: Some(auth_cookies.account_data.same_site),
        };
        cookies.set_cookie(&chunk.name, &attrs);
    }
}

// ─── setCookieToHeader Utility ───────────────────────────────────
//
// Maps to TypeScript `setCookieToHeader` in cookie-utils.ts.
// Converts Set-Cookie response headers into Cookie request headers.

/// Apply Set-Cookie values from a response to a request cookie header.
///
/// This is used for chained requests (e.g., sign-in then get-session)
/// where the response cookies need to become the next request's cookies.
///
/// Maps to TypeScript `setCookieToHeader`.
pub fn set_cookie_to_header(
    existing_cookie_header: &str,
    set_cookie_header: &str,
) -> String {
    use std::collections::HashMap;

    let mut cookie_map: HashMap<String, String> = HashMap::new();

    // Parse existing cookies
    if !existing_cookie_header.is_empty() {
        for pair in existing_cookie_header.split(';') {
            let pair = pair.trim();
            if let Some(eq_pos) = pair.find('=') {
                let name = pair[..eq_pos].to_string();
                let value = pair[eq_pos + 1..].to_string();
                cookie_map.insert(name, value);
            }
        }
    }

    // Parse Set-Cookie headers and extract name=value pairs
    let parsed = parse_set_cookie_header(set_cookie_header);
    for (name, attrs) in &parsed {
        cookie_map.insert(name.clone(), attrs.value.clone());
    }

    // Serialize back to Cookie: header format
    cookie_map
        .into_iter()
        .map(|(name, value)| format!("{}={}", name, value))
        .collect::<Vec<_>>()
        .join("; ")
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_cookies_defaults() {
        let options = BetterAuthOptions::default();
        let cookies = get_cookies(&options);

        // Not secure by default (no base_url)
        assert!(!cookies.session_token.secure);
        assert!(cookies.session_token.name.contains("session_token"));
        assert!(cookies.session_data.name.contains("session_data"));
        assert!(cookies.dont_remember_token.name.contains("dont_remember"));
        assert!(cookies.account_data.name.contains("account_data"));
    }

    #[test]
    fn test_get_cookies_secure() {
        let mut options = BetterAuthOptions::default();
        options.base_url = Some("https://example.com".into());
        let cookies = get_cookies(&options);

        assert!(cookies.session_token.secure);
        assert!(cookies.session_token.name.starts_with(SECURE_COOKIE_PREFIX));
    }

    #[test]
    fn test_sign_and_verify_cookie() {
        let secret = "my-secret-key";
        let value = "session-token-123";

        let signed = sign_cookie_value(value, secret).unwrap();
        assert!(signed.starts_with(value));
        assert!(signed.contains('.'));

        let verified = verify_signed_cookie(&signed, secret);
        assert_eq!(verified, Some(value.to_string()));
    }

    #[test]
    fn test_verify_cookie_wrong_secret() {
        let signed = sign_cookie_value("value", "correct-secret").unwrap();
        let result = verify_signed_cookie(&signed, "wrong-secret");
        assert!(result.is_none());
    }

    #[test]
    fn test_expire_cookie() {
        let cookie = create_auth_cookie("session_token", "better-auth", false, None, Some(3600));
        let expired = expire_cookie(&cookie);
        assert_eq!(expired.max_age, Some(0));
        assert!(expired.value.is_empty());
    }

    #[test]
    fn test_get_session_cookie() {
        let header = "better-auth.session_token=abc123; other=value";
        let result = get_session_cookie(header, None, None);
        assert_eq!(result, Some("abc123".to_string()));
    }

    #[test]
    fn test_get_session_cookie_missing() {
        let header = "other=value";
        let result = get_session_cookie(header, None, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_account_cookie_roundtrip() {
        let options = BetterAuthOptions::default();
        let auth_cookies = get_cookies(&options);
        let secret = "test-secret-that-is-long-enough-32";

        let account_data = serde_json::json!({
            "provider_id": "github",
            "access_token": "gho_abc123",
            "refresh_token": "ghr_xyz456",
        });

        // Set the account cookie
        let mut rc = session_cookie::ResponseCookies::new();
        set_account_cookie(&mut rc, &auth_cookies, secret, &account_data);

        // Extract the Set-Cookie header and simulate sending it back
        let headers = rc.headers();
        let account_header = headers
            .iter()
            .find(|(name, _)| name.contains("account_data"))
            .expect("account_data cookie should be set");

        let nv_part = account_header.1.split(';').next().unwrap();
        let cookie_header = nv_part.to_string();

        // Read the account cookie back
        let result = get_account_cookie(&cookie_header, &auth_cookies, secret);
        assert!(result.is_some());

        let result = result.unwrap();
        assert_eq!(result["provider_id"], "github");
        assert_eq!(result["access_token"], "gho_abc123");
    }

    #[test]
    fn test_account_cookie_wrong_secret() {
        let options = BetterAuthOptions::default();
        let auth_cookies = get_cookies(&options);

        let account_data = serde_json::json!({"provider_id": "github"});

        let mut rc = session_cookie::ResponseCookies::new();
        set_account_cookie(&mut rc, &auth_cookies, "correct-secret", &account_data);

        let headers = rc.headers();
        let account_header = headers.iter().find(|(name, _)| name.contains("account_data")).unwrap();
        let nv_part = account_header.1.split(';').next().unwrap();
        let cookie_header = nv_part.to_string();

        let result = get_account_cookie(&cookie_header, &auth_cookies, "wrong-secret");
        assert!(result.is_none());
    }

    #[test]
    fn test_set_cookie_to_header() {
        let existing = "session=abc; theme=dark";
        let set_cookie = "session=new_value; Path=/; HttpOnly, token=xyz; Path=/";

        let result = set_cookie_to_header(existing, set_cookie);

        // Should contain updated session and new token
        assert!(result.contains("session=new_value"));
        assert!(result.contains("token=xyz"));
        assert!(result.contains("theme=dark"));
    }

    #[test]
    fn test_set_cookie_to_header_empty_existing() {
        let result = set_cookie_to_header("", "session=abc; Path=/");
        assert!(result.contains("session=abc"));
    }

    #[test]
    fn test_delete_account_cookies() {
        let options = BetterAuthOptions::default();
        let auth_cookies = get_cookies(&options);

        let mut rc = session_cookie::ResponseCookies::new();
        delete_account_cookies(&mut rc, &auth_cookies);

        let headers = rc.headers();
        // Should have account_data + chunk cleanup cookies
        assert!(headers.len() >= 1);
        assert!(headers.iter().any(|(name, _)| name.contains("account_data")));
        for (_, header_val) in headers {
            assert!(header_val.contains("Max-Age=0"));
        }
    }
}
