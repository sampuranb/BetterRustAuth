// Session cookie operations — maps to packages/better-auth/src/cookies/index.ts
//
// High-level functions that route handlers call to set/clear session cookies.
// These collect Set-Cookie headers into a ResponseCookies accumulator that the
// HTTP framework layer (e.g. Axum) converts into actual response headers.

use std::collections::HashMap;

use crate::context::AuthContext;
use crate::cookies::{
    AuthCookie, BetterAuthCookies, CookieChunk, chunk_cookie_value, clean_chunk_cookies,
    get_chunked_cookie, serialize_cookie, sign_cookie_value, verify_signed_cookie,
};
use crate::cookies::utils::{CookieAttributes, SameSite, parse_cookies};
use crate::crypto;
use better_auth_core::options::CookieCacheStrategy;

/// Accumulator for Set-Cookie headers to include in the response.
///
/// Route handlers push cookies here; the HTTP framework layer reads them
/// and adds `Set-Cookie` headers to the response.
#[derive(Debug, Clone, Default)]
pub struct ResponseCookies {
    /// Each entry is (cookie_name, serialized_set_cookie_value).
    cookies: Vec<(String, String)>,
}

impl ResponseCookies {
    pub fn new() -> Self {
        Self {
            cookies: Vec::new(),
        }
    }

    /// Add a cookie to the response.
    pub fn set_cookie(&mut self, name: &str, attrs: &CookieAttributes) {
        let header = serialize_cookie(name, attrs);
        self.cookies.push((name.to_string(), header));
    }

    /// Set a signed cookie (value.HMAC-signature).
    pub fn set_signed_cookie(
        &mut self,
        name: &str,
        value: &str,
        secret: &str,
        attrs: &CookieAttributes,
    ) {
        if let Ok(signed_value) = sign_cookie_value(value, secret) {
            let mut signed_attrs = attrs.clone();
            signed_attrs.value = signed_value;
            self.set_cookie(name, &signed_attrs);
        }
    }

    /// Expire a cookie (set max_age=0, empty value).
    pub fn expire_cookie(&mut self, cookie: &AuthCookie) {
        let attrs = CookieAttributes {
            value: String::new(),
            max_age: Some(0),
            expires: None,
            domain: cookie.domain.clone(),
            path: Some(cookie.path.clone()),
            secure: cookie.secure,
            http_only: cookie.http_only,
            same_site: Some(cookie.same_site),
        };
        self.set_cookie(&cookie.name, &attrs);
    }

    /// Get the accumulated Set-Cookie header values.
    pub fn headers(&self) -> &[(String, String)] {
        &self.cookies
    }

    /// Consume and return all Set-Cookie header values.
    pub fn into_headers(self) -> Vec<(String, String)> {
        self.cookies
    }

    /// Check if any cookies have been set.
    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }
}

/// Session + User data for cookie operations.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionUser {
    pub session: serde_json::Value,
    pub user: serde_json::Value,
}

/// Set the session cookie (token + optional cache).
///
/// Maps to TypeScript `setSessionCookie`.
///
/// 1. Signs the session token and sets as session_token cookie
/// 2. If dontRememberMe, sets that cookie too
/// 3. If cookie cache is enabled, calls set_cookie_cache
pub fn set_session_cookie(
    cookies: &mut ResponseCookies,
    auth_cookies: &BetterAuthCookies,
    secret: &str,
    session_user: &SessionUser,
    session_token: &str,
    dont_remember_me: bool,
    cookie_cache_enabled: bool,
    session_expires_in: u64,
    cookie_cache_max_age: Option<u64>,
    cookie_cache_config: Option<&CookieCacheConfig>,
) {
    // 1. Set the signed session token cookie
    let max_age = if dont_remember_me {
        None
    } else {
        Some(session_expires_in as i64)
    };

    let attrs = CookieAttributes {
        value: String::new(), // Will be replaced by set_signed_cookie
        max_age,
        expires: None,
        domain: auth_cookies.session_token.domain.clone(),
        path: Some(auth_cookies.session_token.path.clone()),
        secure: auth_cookies.session_token.secure,
        http_only: auth_cookies.session_token.http_only,
        same_site: Some(auth_cookies.session_token.same_site),
    };

    cookies.set_signed_cookie(
        &auth_cookies.session_token.name,
        session_token,
        secret,
        &attrs,
    );

    // 2. If dontRememberMe, set that cookie
    if dont_remember_me {
        let drm_attrs = CookieAttributes {
            value: String::new(),
            max_age: None, // Session cookie (no max_age = browser session)
            expires: None,
            domain: auth_cookies.dont_remember_token.domain.clone(),
            path: Some(auth_cookies.dont_remember_token.path.clone()),
            secure: auth_cookies.dont_remember_token.secure,
            http_only: auth_cookies.dont_remember_token.http_only,
            same_site: Some(auth_cookies.dont_remember_token.same_site),
        };
        cookies.set_signed_cookie(
            &auth_cookies.dont_remember_token.name,
            "true",
            secret,
            &drm_attrs,
        );
    }

    // 3. Set cookie cache if enabled
    if cookie_cache_enabled {
        let default_config = CookieCacheConfig::default();
        let config = cookie_cache_config.unwrap_or(&default_config);
        set_cookie_cache(
            cookies,
            auth_cookies,
            secret,
            session_user,
            dont_remember_me,
            cookie_cache_max_age.unwrap_or(300), // Default 5 minutes
            config,
        );
    }
}

/// Delete session cookies (expire token, data, chunks).
///
/// Maps to TypeScript `deleteSessionCookie`.
///
/// If `store_account_cookie` is true, also cleans up account data cookies.
pub fn delete_session_cookie(
    cookies: &mut ResponseCookies,
    auth_cookies: &BetterAuthCookies,
    skip_dont_remember_me: bool,
    store_account_cookie: bool,
) {
    // Expire the session token cookie
    cookies.expire_cookie(&auth_cookies.session_token);

    // Expire the session data cookie
    cookies.expire_cookie(&auth_cookies.session_data);

    // Clean up account data cookies if enabled
    if store_account_cookie {
        cookies.expire_cookie(&auth_cookies.account_data);

        // Clean up account data chunks
        let account_chunks = clean_chunk_cookies(&auth_cookies.account_data.name, 10);
        for chunk in &account_chunks {
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

    // Clean up session data chunks (assume up to 10 chunks max)
    let chunk_cookies = clean_chunk_cookies(&auth_cookies.session_data.name, 10);
    for chunk in &chunk_cookies {
        let attrs = CookieAttributes {
            value: String::new(),
            max_age: Some(0),
            expires: None,
            domain: auth_cookies.session_data.domain.clone(),
            path: Some(auth_cookies.session_data.path.clone()),
            secure: auth_cookies.session_data.secure,
            http_only: auth_cookies.session_data.http_only,
            same_site: Some(auth_cookies.session_data.same_site),
        };
        cookies.set_cookie(&chunk.name, &attrs);
    }

    // Expire the dont_remember cookie unless skipped
    if !skip_dont_remember_me {
        cookies.expire_cookie(&auth_cookies.dont_remember_token);
    }
}

/// Configuration for cookie cache set/get operations.
#[derive(Debug, Clone)]
pub struct CookieCacheConfig {
    pub strategy: CookieCacheStrategy,
    pub version: Option<String>,
}

impl Default for CookieCacheConfig {
    fn default() -> Self {
        Self {
            strategy: CookieCacheStrategy::Compact,
            version: None,
        }
    }
}

/// Set the cookie cache (session + user data in a signed/encoded cookie).
///
/// Maps to TypeScript `setCookieCache`.
///
/// Supports 3 strategies:
/// - **Compact** (default): base64url(JSON({ session, expiresAt, signature })) with HMAC-SHA256
/// - **JWT**: HS256-signed JWT token
/// - **JWE**: Symmetrically encrypted (XChaCha20-Poly1305)
fn set_cookie_cache(
    cookies: &mut ResponseCookies,
    auth_cookies: &BetterAuthCookies,
    secret: &str,
    session_user: &SessionUser,
    dont_remember_me: bool,
    cache_max_age: u64,
    config: &CookieCacheConfig,
) {
    let max_age = if dont_remember_me {
        None
    } else {
        Some(cache_max_age as i64)
    };

    let now_ms = chrono::Utc::now().timestamp_millis();
    let version = config.version.as_deref().unwrap_or("1");

    // Build the session data payload
    let session_data = serde_json::json!({
        "session": session_user.session,
        "user": session_user.user,
        "updatedAt": now_ms,
        "version": version,
    });

    let data = match config.strategy {
        CookieCacheStrategy::Jwe => {
            // JWE strategy: symmetrically encrypt the session data
            match crypto::symmetric_encrypt(
                secret,
                &serde_json::to_string(&session_data).unwrap_or_default(),
            ) {
                Ok(encrypted) => encrypted,
                Err(_) => return,
            }
        }
        CookieCacheStrategy::Jwt => {
            // JWT strategy: HS256-signed JWT
            match crate::crypto::jwt::sign_jwt(
                &session_data,
                secret,
                cache_max_age,
            ) {
                Ok(token) => token,
                Err(_) => return,
            }
        }
        CookieCacheStrategy::Compact => {
            // Compact strategy: base64url + HMAC
            let expires_at = now_ms + (cache_max_age as i64 * 1000);

            let sign_payload = serde_json::json!({
                "session": session_user.session,
                "user": session_user.user,
                "updatedAt": now_ms,
                "version": version,
                "expiresAt": expires_at,
            });

            let signature = match crypto::make_signature(
                &serde_json::to_string(&sign_payload).unwrap_or_default(),
                secret,
            ) {
                Ok(sig) => sig,
                Err(_) => return,
            };

            let envelope = serde_json::json!({
                "session": session_data,
                "expiresAt": expires_at,
                "signature": signature,
            });

            base64_url_encode(&serde_json::to_string(&envelope).unwrap_or_default())
        }
    };

    // Check if we need to chunk
    if data.len() > crate::cookies::session_store::MAX_COOKIE_SIZE {
        let chunks = chunk_cookie_value(&auth_cookies.session_data.name, &data);
        for chunk in &chunks {
            let attrs = CookieAttributes {
                value: chunk.value.clone(),
                max_age,
                expires: None,
                domain: auth_cookies.session_data.domain.clone(),
                path: Some(auth_cookies.session_data.path.clone()),
                secure: auth_cookies.session_data.secure,
                http_only: auth_cookies.session_data.http_only,
                same_site: Some(auth_cookies.session_data.same_site),
            };
            cookies.set_cookie(&chunk.name, &attrs);
        }
    } else {
        let attrs = CookieAttributes {
            value: data,
            max_age,
            expires: None,
            domain: auth_cookies.session_data.domain.clone(),
            path: Some(auth_cookies.session_data.path.clone()),
            secure: auth_cookies.session_data.secure,
            http_only: auth_cookies.session_data.http_only,
            same_site: Some(auth_cookies.session_data.same_site),
        };
        cookies.set_cookie(&auth_cookies.session_data.name, &attrs);
    }
}

/// Read and verify the cookie cache.
///
/// Maps to TypeScript `getCookieCache`.
///
/// Supports all 3 strategies (compact, jwt, jwe) and version validation.
/// Returns the cached session+user if valid, None otherwise.
pub fn get_cookie_cache(
    cookie_header: &str,
    auth_cookies: &BetterAuthCookies,
    secret: &str,
) -> Option<SessionUser> {
    get_cookie_cache_with_config(cookie_header, auth_cookies, secret, &CookieCacheConfig::default())
}

/// Read and verify the cookie cache with explicit strategy and version config.
pub fn get_cookie_cache_with_config(
    cookie_header: &str,
    auth_cookies: &BetterAuthCookies,
    secret: &str,
    config: &CookieCacheConfig,
) -> Option<SessionUser> {
    let cookies = parse_cookies(cookie_header);

    // Try to get the data (possibly chunked)
    let data = get_chunked_cookie(&cookies, &auth_cookies.session_data.name)?;

    match config.strategy {
        CookieCacheStrategy::Jwe => {
            get_cookie_cache_jwe(&data, secret, config.version.as_deref())
        }
        CookieCacheStrategy::Jwt => {
            get_cookie_cache_jwt(&data, secret, config.version.as_deref())
        }
        CookieCacheStrategy::Compact => {
            get_cookie_cache_compact(&data, secret, config.version.as_deref())
        }
    }
}

/// Compact strategy: base64url(JSON({ session, expiresAt, signature })) + HMAC verification.
fn get_cookie_cache_compact(
    data: &str,
    secret: &str,
    expected_version: Option<&str>,
) -> Option<SessionUser> {
    let decoded = base64_url_decode(data)?;
    let envelope: serde_json::Value = serde_json::from_str(&decoded).ok()?;

    let expires_at = envelope["expiresAt"].as_i64()?;
    let stored_signature = envelope["signature"].as_str()?;

    // Check expiration
    let now_ms = chrono::Utc::now().timestamp_millis();
    if now_ms > expires_at {
        return None;
    }

    // Verify HMAC signature
    let session_data = &envelope["session"];
    let sign_payload = serde_json::json!({
        "session": session_data["session"],
        "user": session_data["user"],
        "updatedAt": session_data["updatedAt"],
        "version": session_data["version"],
        "expiresAt": expires_at,
    });

    let expected_signature = crypto::make_signature(
        &serde_json::to_string(&sign_payload).unwrap_or_default(),
        secret,
    )
    .ok()?;

    if !crypto::constant_time_equal(expected_signature.as_bytes(), stored_signature.as_bytes()) {
        return None;
    }

    // Validate version if configured
    if let Some(expected) = expected_version {
        let cookie_version = session_data["version"].as_str().unwrap_or("1");
        if cookie_version != expected {
            return None;
        }
    }

    Some(SessionUser {
        session: session_data["session"].clone(),
        user: session_data["user"].clone(),
    })
}

/// JWT strategy: HS256-signed JWT with payload verification.
fn get_cookie_cache_jwt(
    data: &str,
    secret: &str,
    expected_version: Option<&str>,
) -> Option<SessionUser> {
    let payload: serde_json::Value = crate::crypto::jwt::verify_jwt(data, secret)?;

    let session = payload.get("session")?;
    let user = payload.get("user")?;

    // Validate version if configured
    if let Some(expected) = expected_version {
        let cookie_version = payload["version"].as_str().unwrap_or("1");
        if cookie_version != expected {
            return None;
        }
    }

    Some(SessionUser {
        session: session.clone(),
        user: user.clone(),
    })
}

/// JWE strategy: symmetric decryption (XChaCha20-Poly1305).
fn get_cookie_cache_jwe(
    data: &str,
    secret: &str,
    expected_version: Option<&str>,
) -> Option<SessionUser> {
    let decrypted = crypto::symmetric_decrypt(secret, data).ok()?;
    let payload: serde_json::Value = serde_json::from_str(&decrypted).ok()?;

    let session = payload.get("session")?;
    let user = payload.get("user")?;

    // Validate version if configured
    if let Some(expected) = expected_version {
        let cookie_version = payload["version"].as_str().unwrap_or("1");
        if cookie_version != expected {
            return None;
        }
    }

    Some(SessionUser {
        session: session.clone(),
        user: user.clone(),
    })
}

// ─── Base64url Helpers ───────────────────────────────────────────

fn base64_url_encode(data: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data.as_bytes())
}

fn base64_url_decode(data: &str) -> Option<String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(data)
        .ok()?;
    String::from_utf8(bytes).ok()
}

// ─── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::options::BetterAuthOptions;

    fn test_cookies() -> BetterAuthCookies {
        let options = BetterAuthOptions::default();
        crate::cookies::get_cookies(&options)
    }

    #[test]
    fn test_response_cookies_new() {
        let rc = ResponseCookies::new();
        assert!(rc.is_empty());
    }

    #[test]
    fn test_set_session_cookie_basic() {
        let mut rc = ResponseCookies::new();
        let auth_cookies = test_cookies();

        let session_user = SessionUser {
            session: serde_json::json!({"id": "s1", "token": "tok1"}),
            user: serde_json::json!({"id": "u1", "email": "test@test.com"}),
        };

        set_session_cookie(
            &mut rc,
            &auth_cookies,
            "test-secret-that-is-long-enough-32",
            &session_user,
            "session-token-abc",
            false,
            false,
            86400,
            None,
            None,
        );

        assert!(!rc.is_empty());
        // Should have set the session_token cookie (signed)
        let headers = rc.headers();
        assert!(headers.iter().any(|(name, _)| name.contains("session_token")));
    }

    #[test]
    fn test_set_session_cookie_with_cache() {
        let mut rc = ResponseCookies::new();
        let auth_cookies = test_cookies();

        let session_user = SessionUser {
            session: serde_json::json!({"id": "s1", "token": "tok1"}),
            user: serde_json::json!({"id": "u1", "email": "test@test.com"}),
        };

        set_session_cookie(
            &mut rc,
            &auth_cookies,
            "test-secret-that-is-long-enough-32",
            &session_user,
            "session-token-xyz",
            false,
            true, // cookie cache enabled
            86400,
            Some(300),
            None,
        );

        let headers = rc.headers();
        // Should have session_token + session_data cookies
        assert!(headers.iter().any(|(name, _)| name.contains("session_token")));
        assert!(headers.iter().any(|(name, _)| name.contains("session_data")));
    }

    #[test]
    fn test_set_and_get_cookie_cache() {
        let auth_cookies = test_cookies();
        let secret = "test-secret-that-is-long-enough-32";

        let session_user = SessionUser {
            session: serde_json::json!({"id": "s1", "token": "tok1"}),
            user: serde_json::json!({"id": "u1", "email": "test@test.com", "name": "Test"}),
        };

        // Set the cache
        let mut rc = ResponseCookies::new();
        set_cookie_cache(&mut rc, &auth_cookies, secret, &session_user, false, 300, &CookieCacheConfig::default());

        // Extract the Set-Cookie header and parse it as a Cookie header
        // (simulate the browser sending the cookie back)
        let headers = rc.headers();
        let session_data_header = headers
            .iter()
            .find(|(name, _)| name.contains("session_data"))
            .expect("session_data cookie should be set");

        // Parse the Set-Cookie to extract name=value
        let set_cookie_val = &session_data_header.1;
        let nv_part = set_cookie_val.split(';').next().unwrap();
        // Build a Cookie: header
        let cookie_header = nv_part.to_string();

        // Read the cache back
        let cached = get_cookie_cache(&cookie_header, &auth_cookies, secret);
        assert!(cached.is_some());

        let cached = cached.unwrap();
        assert_eq!(cached.user["email"], "test@test.com");
        assert_eq!(cached.session["id"], "s1");
    }

    #[test]
    fn test_cookie_cache_expired() {
        let auth_cookies = test_cookies();
        let secret = "test-secret-that-is-long-enough-32";

        // Manually create an expired cache
        let now_ms = chrono::Utc::now().timestamp_millis();
        let expires_at = now_ms - 1000; // Already expired

        let session_data = serde_json::json!({
            "session": {"id": "s1"},
            "user": {"id": "u1"},
            "updatedAt": now_ms,
            "version": "1",
        });

        let sign_payload = serde_json::json!({
            "session": {"id": "s1"},
            "user": {"id": "u1"},
            "updatedAt": now_ms,
            "version": "1",
            "expiresAt": expires_at,
        });

        let signature = crypto::make_signature(
            &serde_json::to_string(&sign_payload).unwrap(),
            secret,
        )
        .unwrap();

        let envelope = serde_json::json!({
            "session": session_data,
            "expiresAt": expires_at,
            "signature": signature,
        });

        let data = base64_url_encode(&serde_json::to_string(&envelope).unwrap());
        let cookie_header = format!("{}={}", auth_cookies.session_data.name, data);

        let result = get_cookie_cache(&cookie_header, &auth_cookies, secret);
        assert!(result.is_none());
    }

    #[test]
    fn test_cookie_cache_bad_signature() {
        let auth_cookies = test_cookies();
        let secret = "test-secret-that-is-long-enough-32";

        let now_ms = chrono::Utc::now().timestamp_millis();
        let expires_at = now_ms + 300_000;

        let session_data = serde_json::json!({
            "session": {"id": "s1"},
            "user": {"id": "u1"},
            "updatedAt": now_ms,
            "version": "1",
        });

        let envelope = serde_json::json!({
            "session": session_data,
            "expiresAt": expires_at,
            "signature": "bad-signature",
        });

        let data = base64_url_encode(&serde_json::to_string(&envelope).unwrap());
        let cookie_header = format!("{}={}", auth_cookies.session_data.name, data);

        let result = get_cookie_cache(&cookie_header, &auth_cookies, secret);
        assert!(result.is_none());
    }

    #[test]
    fn test_delete_session_cookie() {
        let mut rc = ResponseCookies::new();
        let auth_cookies = test_cookies();

        delete_session_cookie(&mut rc, &auth_cookies, false, false);

        let headers = rc.headers();
        // Should expire session_token, session_data, dont_remember, + chunks
        assert!(headers.len() >= 3);
        // All cookies should have max-age=0
        for (_, header_val) in headers {
            assert!(header_val.contains("Max-Age=0"));
        }
    }

    // ─── JWT Strategy Tests ──────────────────────────────────────

    #[test]
    fn test_cookie_cache_jwt_strategy() {
        let auth_cookies = test_cookies();
        let secret = "test-secret-that-is-long-enough-32";

        let session_user = SessionUser {
            session: serde_json::json!({"id": "s1", "token": "tok1"}),
            user: serde_json::json!({"id": "u1", "email": "jwt@test.com"}),
        };

        let config = CookieCacheConfig {
            strategy: CookieCacheStrategy::Jwt,
            version: None,
        };

        let mut rc = ResponseCookies::new();
        set_cookie_cache(&mut rc, &auth_cookies, secret, &session_user, false, 300, &config);

        let headers = rc.headers();
        let session_data_header = headers
            .iter()
            .find(|(name, _)| name.contains("session_data"))
            .expect("session_data cookie should be set");

        let set_cookie_val = &session_data_header.1;
        let nv_part = set_cookie_val.split(';').next().unwrap();
        let cookie_header = nv_part.to_string();

        let cached = get_cookie_cache_with_config(&cookie_header, &auth_cookies, secret, &config);
        assert!(cached.is_some());

        let cached = cached.unwrap();
        assert_eq!(cached.user["email"], "jwt@test.com");
        assert_eq!(cached.session["id"], "s1");
    }

    #[test]
    fn test_cookie_cache_jwt_wrong_secret() {
        let auth_cookies = test_cookies();

        let session_user = SessionUser {
            session: serde_json::json!({"id": "s1"}),
            user: serde_json::json!({"id": "u1"}),
        };

        let config = CookieCacheConfig {
            strategy: CookieCacheStrategy::Jwt,
            version: None,
        };

        let mut rc = ResponseCookies::new();
        set_cookie_cache(&mut rc, &auth_cookies, "correct-secret-long-enough-32!!", &session_user, false, 300, &config);

        let headers = rc.headers();
        let session_data_header = headers.iter().find(|(name, _)| name.contains("session_data")).unwrap();
        let nv_part = session_data_header.1.split(';').next().unwrap();
        let cookie_header = nv_part.to_string();

        let result = get_cookie_cache_with_config(&cookie_header, &auth_cookies, "wrong-secret-totally-different!!", &config);
        assert!(result.is_none());
    }

    // ─── JWE Strategy Tests ──────────────────────────────────────

    #[test]
    fn test_cookie_cache_jwe_strategy() {
        let auth_cookies = test_cookies();
        let secret = "test-secret-that-is-long-enough-32";

        let session_user = SessionUser {
            session: serde_json::json!({"id": "s1", "token": "tok1"}),
            user: serde_json::json!({"id": "u1", "email": "jwe@test.com"}),
        };

        let config = CookieCacheConfig {
            strategy: CookieCacheStrategy::Jwe,
            version: None,
        };

        let mut rc = ResponseCookies::new();
        set_cookie_cache(&mut rc, &auth_cookies, secret, &session_user, false, 300, &config);

        let headers = rc.headers();
        let session_data_header = headers
            .iter()
            .find(|(name, _)| name.contains("session_data"))
            .expect("session_data cookie should be set");

        let set_cookie_val = &session_data_header.1;
        let nv_part = set_cookie_val.split(';').next().unwrap();
        let cookie_header = nv_part.to_string();

        let cached = get_cookie_cache_with_config(&cookie_header, &auth_cookies, secret, &config);
        assert!(cached.is_some());

        let cached = cached.unwrap();
        assert_eq!(cached.user["email"], "jwe@test.com");
        assert_eq!(cached.session["id"], "s1");
    }

    #[test]
    fn test_cookie_cache_jwe_wrong_secret() {
        let auth_cookies = test_cookies();

        let session_user = SessionUser {
            session: serde_json::json!({"id": "s1"}),
            user: serde_json::json!({"id": "u1"}),
        };

        let config = CookieCacheConfig {
            strategy: CookieCacheStrategy::Jwe,
            version: None,
        };

        let mut rc = ResponseCookies::new();
        set_cookie_cache(&mut rc, &auth_cookies, "correct-secret-long-enough-32!!", &session_user, false, 300, &config);

        let headers = rc.headers();
        let session_data_header = headers.iter().find(|(name, _)| name.contains("session_data")).unwrap();
        let nv_part = session_data_header.1.split(';').next().unwrap();
        let cookie_header = nv_part.to_string();

        let result = get_cookie_cache_with_config(&cookie_header, &auth_cookies, "wrong-secret-totally-different!!", &config);
        assert!(result.is_none());
    }

    // ─── Version Validation Tests ────────────────────────────────

    #[test]
    fn test_cookie_cache_version_match() {
        let auth_cookies = test_cookies();
        let secret = "test-secret-that-is-long-enough-32";

        let session_user = SessionUser {
            session: serde_json::json!({"id": "s1"}),
            user: serde_json::json!({"id": "u1"}),
        };

        let config = CookieCacheConfig {
            strategy: CookieCacheStrategy::Compact,
            version: Some("2".to_string()),
        };

        let mut rc = ResponseCookies::new();
        set_cookie_cache(&mut rc, &auth_cookies, secret, &session_user, false, 300, &config);

        let headers = rc.headers();
        let session_data_header = headers.iter().find(|(name, _)| name.contains("session_data")).unwrap();
        let nv_part = session_data_header.1.split(';').next().unwrap();
        let cookie_header = nv_part.to_string();

        // Same version should work
        let result = get_cookie_cache_with_config(&cookie_header, &auth_cookies, secret, &config);
        assert!(result.is_some());
    }

    #[test]
    fn test_cookie_cache_version_mismatch() {
        let auth_cookies = test_cookies();
        let secret = "test-secret-that-is-long-enough-32";

        let session_user = SessionUser {
            session: serde_json::json!({"id": "s1"}),
            user: serde_json::json!({"id": "u1"}),
        };

        let write_config = CookieCacheConfig {
            strategy: CookieCacheStrategy::Compact,
            version: Some("1".to_string()),
        };

        let mut rc = ResponseCookies::new();
        set_cookie_cache(&mut rc, &auth_cookies, secret, &session_user, false, 300, &write_config);

        let headers = rc.headers();
        let session_data_header = headers.iter().find(|(name, _)| name.contains("session_data")).unwrap();
        let nv_part = session_data_header.1.split(';').next().unwrap();
        let cookie_header = nv_part.to_string();

        // Different version should fail
        let read_config = CookieCacheConfig {
            strategy: CookieCacheStrategy::Compact,
            version: Some("2".to_string()),
        };
        let result = get_cookie_cache_with_config(&cookie_header, &auth_cookies, secret, &read_config);
        assert!(result.is_none());
    }

    // ─── Delete Session Cookie with Account Data ─────────────────

    #[test]
    fn test_delete_session_cookie_with_account() {
        let mut rc = ResponseCookies::new();
        let auth_cookies = test_cookies();

        delete_session_cookie(&mut rc, &auth_cookies, false, true);

        let headers = rc.headers();
        // Should have more cookies when account cleanup is included
        assert!(headers.len() >= 4);
        // All cookies should have max-age=0
        for (_, header_val) in headers {
            assert!(header_val.contains("Max-Age=0"));
        }
        // Should include account_data cleanup
        assert!(headers.iter().any(|(name, _)| name.contains("account_data")));
    }
}
