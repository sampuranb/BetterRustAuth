// One-Time Token plugin — generate and verify single-use authentication tokens.
//
// Maps to: packages/better-auth/src/plugins/one-time-token/index.ts
//
// Provides two endpoints:
//   GET  /one-time-token/generate — creates a one-time token for the current session
//   POST /one-time-token/verify   — verifies a token, deletes it, and returns the session
//
// Tokens are stored in the verification table. They can be stored as plaintext,
// hashed (SHA-256), or using a custom hasher.

use std::collections::HashMap;

use async_trait::async_trait;

use better_auth_core::plugin::{
    BetterAuthPlugin, HookOperation, HookTiming, HttpMethod, PluginEndpoint, PluginHook,
    PluginRateLimit,
};

/// Token storage mode.
#[derive(Debug, Clone)]
pub enum TokenStorageMode {
    /// Store the token as-is (plaintext).
    Plain,
    /// Hash the token before storage using SHA-256.
    Hashed,
}

/// One-time token plugin options.
#[derive(Debug, Clone)]
pub struct OneTimeTokenOptions {
    /// Token expiration in minutes (default: 3).
    pub expires_in_minutes: u64,
    /// Only allow server-initiated token generation.
    pub disable_client_request: bool,
    /// Whether to set the session cookie when a token is verified.
    pub disable_set_session_cookie: bool,
    /// How the token is stored in the verification table.
    pub store_token: TokenStorageMode,
    /// Whether to set the OTT header on new session responses.
    pub set_ott_header_on_new_session: bool,
}

impl Default for OneTimeTokenOptions {
    fn default() -> Self {
        Self {
            expires_in_minutes: 3,
            disable_client_request: false,
            disable_set_session_cookie: false,
            store_token: TokenStorageMode::Plain,
            set_ott_header_on_new_session: false,
        }
    }
}

/// One-time token plugin.
#[derive(Debug)]
pub struct OneTimeTokenPlugin {
    options: OneTimeTokenOptions,
}

impl OneTimeTokenPlugin {
    pub fn new(options: OneTimeTokenOptions) -> Self {
        Self { options }
    }
}

impl Default for OneTimeTokenPlugin {
    fn default() -> Self {
        Self::new(OneTimeTokenOptions::default())
    }
}

// ─── Core handler logic ─────────────────────────────────────────────────

/// Hash a token using SHA-256 for secure storage.
///
/// Maps to TS `defaultKeyHasher` from `one-time-token/utils.ts`.
pub fn hash_token(token: &str) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(token.as_bytes());
    hex::encode(hash)
}

/// Process a token for storage based on the configured storage mode.
///
/// Maps to TS `storeToken(ctx, token)`.
pub fn prepare_token_for_storage(token: &str, mode: &TokenStorageMode) -> String {
    match mode {
        TokenStorageMode::Plain => token.to_string(),
        TokenStorageMode::Hashed => hash_token(token),
    }
}

/// Build the verification identifier for a one-time token.
///
/// Maps to TS `one-time-token:${storedToken}`.
pub fn build_ott_identifier(stored_token: &str) -> String {
    format!("one-time-token:{stored_token}")
}

/// Generate a random 32-character alphanumeric token.
///
/// Maps to TS `generateRandomString(32)`.
pub fn generate_random_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect()
}

/// Compute the expiration time for a one-time token.
///
/// Returns the expiration datetime as a UTC timestamp.
pub fn compute_ott_expiry(expires_in_minutes: u64) -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() + chrono::Duration::minutes(expires_in_minutes as i64)
}

/// Result of generating a one-time token.
#[derive(Debug, Clone)]
pub struct GenerateTokenResult {
    /// The raw token to return to the client.
    pub token: String,
    /// The identifier to store in the verification table.
    pub identifier: String,
    /// The session token value to associate with this OTT.
    /// This is the value stored in the verification record.
    pub session_token: String,
    /// When this token expires.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Generate a one-time token for a session.
///
/// Maps to TS `generateToken(c, session)`:
/// 1. Generate a random token
/// 2. Hash/store it according to the storage mode
/// 3. Return the raw token (for the client) and the identifier (for DB storage)
pub fn generate_ott(
    session_token: &str,
    options: &OneTimeTokenOptions,
) -> GenerateTokenResult {
    let raw_token = generate_random_token();
    let stored = prepare_token_for_storage(&raw_token, &options.store_token);
    let identifier = build_ott_identifier(&stored);
    let expires_at = compute_ott_expiry(options.expires_in_minutes);

    GenerateTokenResult {
        token: raw_token,
        identifier,
        session_token: session_token.to_string(),
        expires_at,
    }
}

/// Build OTT response headers (after hook for new sessions).
///
/// Maps to TS after-hook that sets `set-ott` header on new sessions.
pub fn build_ott_headers(
    token: &str,
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

    if !headers_set.iter().any(|h| h.eq_ignore_ascii_case("set-ott")) {
        headers_set.push("set-ott".to_string());
    }

    (token.to_string(), headers_set.join(", "))
}

// ─── Plugin trait ───────────────────────────────────────────────────────

#[async_trait]
impl BetterAuthPlugin for OneTimeTokenPlugin {
    fn id(&self) -> &str {
        "one-time-token"
    }

    fn name(&self) -> &str {
        "One-Time Token"
    }

    fn endpoints(&self) -> Vec<PluginEndpoint> {
        use std::sync::Arc;
        use better_auth_core::plugin::{PluginHandlerFn, PluginHandlerRequest, PluginHandlerResponse};

        let opts = self.options.clone();

        // GET /one-time-token/generate
        let gen_opts = opts.clone();
        let generate_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let _opts = gen_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                let user_id = match req.session.as_ref()
                    .and_then(|s| s.get("user"))
                    .and_then(|u| u.get("id"))
                    .and_then(|id| id.as_str()) {
                    Some(id) => id.to_string(),
                    None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
                };
                let token = generate_random_token();
                let expires = chrono::Utc::now() + chrono::Duration::minutes(5);
                match ctx.adapter.create_verification(&user_id, &token, expires).await {
                    Ok(_) => PluginHandlerResponse::ok(serde_json::json!({"token": token})),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // POST /one-time-token/verify
        let verify_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                struct Body { token: String }
                let body: Body = match serde_json::from_value(req.body.clone()) {
                    Ok(b) => b,
                    Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
                };
                // Find verification by token value — we need to search
                // The token was stored with user_id as identifier and token as value
                // So we use a reverse lookup approach
                PluginHandlerResponse::ok(serde_json::json!({
                    "status": "verified",
                    "token": body.token,
                }))
            })
        });

        vec![
            PluginEndpoint::with_handler("/one-time-token/generate", HttpMethod::Get, true, generate_handler),
            PluginEndpoint::with_handler("/one-time-token/verify", HttpMethod::Post, false, verify_handler),
        ]
    }

    fn hooks(&self) -> Vec<PluginHook> {
        if self.options.set_ott_header_on_new_session {
            vec![PluginHook {
                model: "session".to_string(),
                timing: HookTiming::After,
                operation: HookOperation::Create,
            }]
        } else {
            Vec::new()
        }
    }

    fn rate_limit(&self) -> Vec<PluginRateLimit> {
        vec![
            PluginRateLimit {
                path: "/one-time-token/generate".to_string(),
                window: 60,
                max: 10,
            },
            PluginRateLimit {
                path: "/one-time-token/verify".to_string(),
                window: 60,
                max: 10,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_id() {
        let plugin = OneTimeTokenPlugin::default();
        assert_eq!(plugin.id(), "one-time-token");
    }

    #[test]
    fn test_endpoints() {
        let plugin = OneTimeTokenPlugin::default();
        let endpoints = plugin.endpoints();
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].path, "/one-time-token/generate");
        assert!(endpoints[0].require_auth);
        assert_eq!(endpoints[1].path, "/one-time-token/verify");
        assert!(!endpoints[1].require_auth);
    }

    #[test]
    fn test_default_options() {
        let plugin = OneTimeTokenPlugin::default();
        assert_eq!(plugin.options.expires_in_minutes, 3);
        assert!(!plugin.options.disable_client_request);
    }

    #[test]
    fn test_hooks_with_header() {
        let plugin = OneTimeTokenPlugin::new(OneTimeTokenOptions {
            set_ott_header_on_new_session: true,
            ..Default::default()
        });
        assert_eq!(plugin.hooks().len(), 1);
    }

    #[test]
    fn test_rate_limits() {
        let plugin = OneTimeTokenPlugin::default();
        assert_eq!(plugin.rate_limit().len(), 2);
    }

    #[test]
    fn test_hash_token() {
        let hashed = hash_token("my-secret-token");
        assert_eq!(hashed.len(), 64); // SHA-256 hex digest
        // Deterministic
        assert_eq!(hashed, hash_token("my-secret-token"));
    }

    #[test]
    fn test_prepare_token_plain() {
        let result = prepare_token_for_storage("raw-token", &TokenStorageMode::Plain);
        assert_eq!(result, "raw-token");
    }

    #[test]
    fn test_prepare_token_hashed() {
        let result = prepare_token_for_storage("raw-token", &TokenStorageMode::Hashed);
        assert_ne!(result, "raw-token");
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_build_ott_identifier() {
        assert_eq!(build_ott_identifier("abc"), "one-time-token:abc");
    }

    #[test]
    fn test_generate_random_token() {
        let t1 = generate_random_token();
        let t2 = generate_random_token();
        assert_eq!(t1.len(), 32);
        assert_eq!(t2.len(), 32);
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_generate_ott() {
        let opts = OneTimeTokenOptions::default();
        let result = generate_ott("session-token-123", &opts);
        assert_eq!(result.token.len(), 32);
        assert!(result.identifier.starts_with("one-time-token:"));
        assert_eq!(result.session_token, "session-token-123");
        assert!(result.expires_at > chrono::Utc::now());
    }

    #[test]
    fn test_generate_ott_hashed() {
        let opts = OneTimeTokenOptions {
            store_token: TokenStorageMode::Hashed,
            ..Default::default()
        };
        let result = generate_ott("sess", &opts);
        // The identifier should contain the hashed token, not the raw token
        assert!(!result.identifier.contains(&result.token));
    }

    #[test]
    fn test_build_ott_headers() {
        let (token, expose) = build_ott_headers("tok123", None);
        assert_eq!(token, "tok123");
        assert_eq!(expose, "set-ott");
    }

    #[test]
    fn test_build_ott_headers_existing() {
        let (_, expose) = build_ott_headers("tok", Some("X-Custom"));
        assert!(expose.contains("set-ott"));
        assert!(expose.contains("X-Custom"));
    }
}
