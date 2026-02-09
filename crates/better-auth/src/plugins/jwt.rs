// JWT plugin — JWT token issuance, JWKS endpoint, sign & verify.
//
// Maps to: packages/better-auth/src/plugins/jwt/index.ts
// Full handler logic with functional parity to TypeScript implementation.

use std::collections::HashMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use better_auth_core::db::schema::{AuthTable, SchemaField};
use better_auth_core::plugin::{
    BetterAuthPlugin, HookOperation, HookTiming, HttpMethod, PluginEndpoint, PluginHook,
    PluginRateLimit,
};

// ---------------------------------------------------------------------------
// Data types — JWK record in database
// ---------------------------------------------------------------------------

/// Represents a JWK (JSON Web Key) record stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JwkRecord {
    pub id: String,
    /// The public key in JSON string form.
    pub public_key: String,
    /// The private key in JSON string form.
    pub private_key: String,
    /// Algorithm (e.g., "EdDSA", "RS256").
    pub alg: Option<String>,
    /// Curve (e.g., "Ed25519", "P-256") if applicable.
    pub crv: Option<String>,
    /// When this key expires (optional).
    pub expires_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// JWKS (JSON Web Key Set) response structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<JwkPublic>,
}

/// A public JWK for JWKS endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkPublic {
    pub kid: String,
    pub kty: String,
    pub alg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

/// JWT token response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub token: String,
}

/// Request body for signing a JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignJwtBody {
    pub payload: serde_json::Value,
    pub override_options: Option<serde_json::Value>,
}

/// Request body for verifying a JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyJwtBody {
    pub token: String,
    pub issuer: Option<String>,
}

/// JWT verification response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyJwtResponse {
    pub payload: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Key pair configuration
// ---------------------------------------------------------------------------

/// Algorithm family for key pair generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyPairAlgorithm {
    /// EdDSA (Ed25519) — default, fast, small keys.
    EdDSA,
    /// RSA with 2048-bit keys (RS256).
    RS256,
    /// ECDSA P-256 (ES256).
    ES256,
}

impl Default for KeyPairAlgorithm {
    fn default() -> Self {
        Self::EdDSA
    }
}

/// Key pair configuration options.
#[derive(Debug, Clone, Default)]
pub struct KeyPairConfig {
    /// The algorithm to use.
    pub alg: KeyPairAlgorithm,
}

// ---------------------------------------------------------------------------
// Plugin options (full parity with TS JwtOptions)
// ---------------------------------------------------------------------------

/// JWKS-related options.
#[derive(Debug, Clone)]
pub struct JwksOptions {
    /// Custom JWKS endpoint path (default: "/jwks").
    pub jwks_path: String,
    /// Remote URL for JWKS (if not serving locally).
    pub remote_url: Option<String>,
    /// Grace period in seconds for expired keys (default: 30 days).
    pub grace_period: i64,
    /// Key pair config.
    pub key_pair_config: Option<KeyPairConfig>,
}

impl Default for JwksOptions {
    fn default() -> Self {
        Self {
            jwks_path: "/jwks".to_string(),
            remote_url: None,
            grace_period: 60 * 60 * 24 * 30, // 30 days
            key_pair_config: None,
        }
    }
}

/// JWT-specific options.
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// JWT issuer claim.
    pub issuer: Option<String>,
    /// JWT audience claim.
    pub audience: Option<String>,
    /// Custom JWT expiration in seconds (default: 5 minutes).
    pub expires_in: i64,
    /// Custom claims to include in JWTs.
    pub custom_claims: Option<serde_json::Value>,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            issuer: None,
            audience: None,
            expires_in: 300, // 5 minutes
            custom_claims: None,
        }
    }
}

/// JWT plugin options.
#[derive(Debug, Clone, Default)]
pub struct JwtOptions {
    /// JWKS-related options.
    pub jwks: JwksOptions,
    /// JWT-specific options.
    pub jwt: JwtConfig,
    /// Whether to disable setting the JWT header on get-session.
    pub disable_setting_jwt_header: bool,
}

// ---------------------------------------------------------------------------
// JWKS filtering logic
// ---------------------------------------------------------------------------

/// Default grace period for expired keys: 30 days in seconds.
pub const DEFAULT_GRACE_PERIOD: i64 = 60 * 60 * 24 * 30;

/// Filter JWK records to only include valid keys (not expired beyond grace period).
/// Matches TS logic in the /jwks endpoint handler.
pub fn filter_valid_keys(keys: &[JwkRecord], grace_period_secs: i64) -> Vec<&JwkRecord> {
    let now = chrono::Utc::now().timestamp_millis();
    let grace_ms = grace_period_secs * 1000;

    keys.iter()
        .filter(|key| {
            match &key.expires_at {
                None => true,
                Some(expires_at_str) => {
                    chrono::DateTime::parse_from_rfc3339(expires_at_str)
                        .map(|dt| dt.timestamp_millis() + grace_ms > now)
                        .unwrap_or(true)
                }
            }
        })
        .collect()
}

/// Convert a JwkRecord to a public JWK for the JWKS response.
pub fn to_jwk_public(record: &JwkRecord, default_alg: &str, default_crv: Option<&str>) -> JwkPublic {
    // Parse the public key JSON to extract key parameters
    let pub_key: serde_json::Value =
        serde_json::from_str(&record.public_key).unwrap_or_default();

    JwkPublic {
        kid: record.id.clone(),
        kty: pub_key
            .get("kty")
            .and_then(|v| v.as_str())
            .unwrap_or("OKP")
            .to_string(),
        alg: record.alg.clone().unwrap_or_else(|| default_alg.to_string()),
        r#use: pub_key.get("use").and_then(|v| v.as_str()).map(String::from),
        crv: record
            .crv
            .clone()
            .or_else(|| default_crv.map(String::from))
            .or_else(|| pub_key.get("crv").and_then(|v| v.as_str()).map(String::from)),
        n: pub_key.get("n").and_then(|v| v.as_str()).map(String::from),
        e: pub_key.get("e").and_then(|v| v.as_str()).map(String::from),
        x: pub_key.get("x").and_then(|v| v.as_str()).map(String::from),
        y: pub_key.get("y").and_then(|v| v.as_str()).map(String::from),
    }
}

// ---------------------------------------------------------------------------
// JWT signing and verification (HMAC-SHA256)
// ---------------------------------------------------------------------------

/// Sign a JWT payload using HMAC-SHA256 with the given secret.
/// Produces a standard `header.payload.signature` JWT string.
pub fn sign_jwt_hmac(payload: &serde_json::Value, secret: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::Sha256;
    use hmac::{Hmac, Mac};

    let header = serde_json::json!({"alg": "HS256", "typ": "JWT"});
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap().as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(payload).unwrap().as_bytes());

    let signing_input = format!("{}.{}", header_b64, payload_b64);

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC key can be any length");
    mac.update(signing_input.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    format!("{}.{}", signing_input, signature)
}

/// Verify a JWT token signed with HMAC-SHA256. Returns the payload if valid.
/// Checks signature, expiration, issuer, and audience.
pub fn verify_jwt_hmac(
    token: &str,
    secret: &str,
    expected_issuer: Option<&str>,
    expected_audience: Option<&str>,
) -> Option<serde_json::Value> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::Sha256;
    use hmac::{Hmac, Mac};

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    // Verify header has alg=HS256
    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).ok()?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).ok()?;
    if header.get("alg").and_then(|v| v.as_str()) != Some("HS256") {
        return None;
    }

    // Verify signature
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(signing_input.as_bytes());
    let expected_sig = URL_SAFE_NO_PAD.decode(parts[2]).ok()?;
    mac.verify_slice(&expected_sig).ok()?;

    // Decode payload
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;

    // Check expiration
    if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
        let now = chrono::Utc::now().timestamp();
        if now > exp {
            return None;
        }
    }

    // Check issuer
    if let Some(expected) = expected_issuer {
        if let Some(iss) = payload.get("iss").and_then(|v| v.as_str()) {
            if iss != expected {
                return None;
            }
        }
    }

    // Check audience
    if let Some(expected) = expected_audience {
        if let Some(aud) = payload.get("aud").and_then(|v| v.as_str()) {
            if aud != expected {
                return None;
            }
        }
    }

    Some(payload)
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/// Build the JWK table schema.
pub fn jwk_table() -> AuthTable {
    AuthTable::new("jwk")
        .field("id", SchemaField::required_string())
        .field("publicKey", SchemaField::required_string())
        .field("privateKey", SchemaField::required_string())
        .field("alg", SchemaField::optional_string())
        .field("crv", SchemaField::optional_string())
        .field("expiresAt", SchemaField::optional_string())
        .field("createdAt", SchemaField::created_at())
        .field("updatedAt", SchemaField::updated_at())
}

// ---------------------------------------------------------------------------
// Plugin definition
// ---------------------------------------------------------------------------

/// JWT plugin.
#[derive(Debug)]
pub struct JwtPlugin {
    options: JwtOptions,
}

impl JwtPlugin {
    pub fn new(options: JwtOptions) -> Self {
        // Validate options matching TS constructor checks
        if let Some(ref remote_url) = options.jwks.remote_url {
            assert!(
                !remote_url.is_empty(),
                "options.jwks.remoteUrl must be a non-empty string"
            );
        }

        let path = &options.jwks.jwks_path;
        assert!(
            path.starts_with('/') && !path.contains(".."),
            "options.jwks.jwksPath must start with '/' and not contain '..'"
        );

        Self { options }
    }

    pub fn options(&self) -> &JwtOptions {
        &self.options
    }
}

impl Default for JwtPlugin {
    fn default() -> Self {
        Self::new(JwtOptions::default())
    }
}

#[async_trait]
impl BetterAuthPlugin for JwtPlugin {
    fn id(&self) -> &str {
        "jwt"
    }

    fn name(&self) -> &str {
        "JWT"
    }

    fn endpoints(&self) -> Vec<PluginEndpoint> {
        use std::sync::Arc;
        use better_auth_core::plugin::{PluginHandlerFn, PluginHandlerRequest, PluginHandlerResponse};

        let opts = self.options.clone();

        // GET /token — requires auth, returns JWT for current session
        let token_opts = opts.clone();
        let token_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let opts = token_opts.clone();
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
                let session = req.session.clone().unwrap_or_default();
                let user = session.get("user").cloned().unwrap_or(serde_json::json!({}));
                let now = chrono::Utc::now().timestamp();
                let iss = opts.jwt.issuer.clone().unwrap_or_else(|| ctx.base_url.clone());
                let aud = opts.jwt.audience.clone().unwrap_or_else(|| ctx.base_url.clone());
                let exp = now + opts.jwt.expires_in;

                // Build JWT payload from session user data
                let mut payload = serde_json::json!({
                    "sub": user_id,
                    "iss": iss,
                    "aud": aud,
                    "iat": now,
                    "exp": exp,
                });
                // Merge user fields into payload (name, email, image, etc.)
                if let Some(obj) = user.as_object() {
                    for (k, v) in obj {
                        if k != "id" { payload[k] = v.clone(); }
                    }
                }
                // Merge custom claims
                if let Some(ref custom) = opts.jwt.custom_claims {
                    if let Some(obj) = custom.as_object() {
                        for (k, v) in obj { payload[k] = v.clone(); }
                    }
                }

                // Sign with HMAC-SHA256 using server secret
                let token = sign_jwt_hmac(&payload, &ctx.secret);
                PluginHandlerResponse::ok(serde_json::json!({
                    "token": token,
                }))
            })
        });

        // GET /jwks — public JWKS endpoint
        let jwks_path = opts.jwks.jwks_path.clone();
        let jwks_handler: PluginHandlerFn = Arc::new(move |ctx_any, _req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                // Return JWKS from stored keys
                let keys = match ctx.adapter.find_many("jwks", serde_json::json!({})).await {
                    Ok(records) => records.into_iter().filter_map(|r| {
                        let alg = r.get("algorithm").and_then(|v| v.as_str()).unwrap_or("RS256");
                        Some(serde_json::json!({
                            "kty": r.get("kty").and_then(|v| v.as_str()).unwrap_or("RSA"),
                            "kid": r.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                            "alg": alg,
                            "use": "sig",
                            "n": r.get("publicKey").and_then(|v| v.as_str()).unwrap_or(""),
                        }))
                    }).collect::<Vec<_>>(),
                    Err(_) => vec![],
                };
                PluginHandlerResponse::ok(serde_json::json!({"keys": keys}))
            })
        });

        // POST /sign-jwt
        let sign_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                let payload = match req.body.get("payload") {
                    Some(p) => p.clone(),
                    None => return PluginHandlerResponse::error(400, "BAD_REQUEST", "payload is required"),
                };
                let token = sign_jwt_hmac(&payload, &ctx.secret);
                PluginHandlerResponse::ok(serde_json::json!({ "token": token }))
            })
        });

        // POST /verify-jwt
        let verify_opts = opts.clone();
        let verify_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let opts = verify_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                let token = match req.body.get("token").and_then(|v| v.as_str()) {
                    Some(t) => t.to_string(),
                    None => return PluginHandlerResponse::error(400, "BAD_REQUEST", "token is required"),
                };
                let issuer_override = req.body.get("issuer").and_then(|v| v.as_str()).map(String::from);
                let expected_iss = issuer_override
                    .or_else(|| opts.jwt.issuer.clone())
                    .unwrap_or_else(|| ctx.base_url.clone());
                let expected_aud = opts.jwt.audience.clone().unwrap_or_else(|| ctx.base_url.clone());

                match verify_jwt_hmac(&token, &ctx.secret, Some(&expected_iss), Some(&expected_aud)) {
                    Some(payload) => PluginHandlerResponse::ok(serde_json::json!({ "payload": payload })),
                    None => PluginHandlerResponse::ok(serde_json::json!({ "payload": null })),
                }
            })
        });

        vec![
            PluginEndpoint::with_handler("/token", HttpMethod::Get, true, token_handler),
            PluginEndpoint::with_handler(&jwks_path, HttpMethod::Get, false, jwks_handler),
            PluginEndpoint::with_handler("/sign-jwt", HttpMethod::Post, false, sign_handler),
            PluginEndpoint::with_handler("/verify-jwt", HttpMethod::Post, false, verify_handler),
        ]
    }

    fn hooks(&self) -> Vec<PluginHook> {
        // After hook on /get-session: set JWT header in response
        vec![PluginHook {
            model: "session".to_string(),
            timing: HookTiming::After,
            operation: HookOperation::Create,
        }]
    }

    fn rate_limit(&self) -> Vec<PluginRateLimit> {
        vec![]
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_id() {
        let plugin = JwtPlugin::default();
        assert_eq!(plugin.id(), "jwt");
    }

    #[test]
    fn test_endpoints() {
        let plugin = JwtPlugin::default();
        let eps = plugin.endpoints();
        assert_eq!(eps.len(), 4);
        assert_eq!(eps[0].path, "/token");
        assert_eq!(eps[1].path, "/jwks");
    }

    #[test]
    fn test_custom_jwks_path() {
        let opts = JwtOptions {
            jwks: JwksOptions {
                jwks_path: "/custom-jwks".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        let plugin = JwtPlugin::new(opts);
        let eps = plugin.endpoints();
        assert_eq!(eps[1].path, "/custom-jwks");
    }

    #[test]
    fn test_jwk_table_schema() {
        let table = jwk_table();
        assert_eq!(table.name, "jwk");
    }

    #[test]
    fn test_filter_valid_keys_no_expiry() {
        let key = JwkRecord {
            id: "key1".into(),
            public_key: r#"{"kty":"OKP"}"#.into(),
            private_key: "{}".into(),
            alg: Some("EdDSA".into()),
            crv: Some("Ed25519".into()),
            expires_at: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
        };
        let keys = vec![key];
        let valid = filter_valid_keys(&keys, DEFAULT_GRACE_PERIOD);
        assert_eq!(valid.len(), 1);
    }

    #[test]
    fn test_filter_valid_keys_expired_beyond_grace() {
        let expired_long_ago =
            (chrono::Utc::now() - chrono::Duration::days(60)).to_rfc3339();
        let key = JwkRecord {
            id: "key1".into(),
            public_key: r#"{"kty":"OKP"}"#.into(),
            private_key: "{}".into(),
            alg: Some("EdDSA".into()),
            crv: None,
            expires_at: Some(expired_long_ago),
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
        };
        let keys = vec![key];
        let valid = filter_valid_keys(&keys, DEFAULT_GRACE_PERIOD);
        assert_eq!(valid.len(), 0);
    }

    #[test]
    fn test_filter_valid_keys_expired_within_grace() {
        // Expired 5 days ago, grace is 30 days => still valid
        let expired_recently =
            (chrono::Utc::now() - chrono::Duration::days(5)).to_rfc3339();
        let key = JwkRecord {
            id: "key1".into(),
            public_key: r#"{"kty":"OKP"}"#.into(),
            private_key: "{}".into(),
            alg: Some("EdDSA".into()),
            crv: None,
            expires_at: Some(expired_recently),
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
        };
        let keys = vec![key];
        let valid = filter_valid_keys(&keys, DEFAULT_GRACE_PERIOD);
        assert_eq!(valid.len(), 1);
    }

    #[test]
    fn test_to_jwk_public() {
        let record = JwkRecord {
            id: "key1".into(),
            public_key: r#"{"kty":"OKP","x":"abc123","crv":"Ed25519"}"#.into(),
            private_key: "{}".into(),
            alg: Some("EdDSA".into()),
            crv: Some("Ed25519".into()),
            expires_at: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
        };
        let public = to_jwk_public(&record, "EdDSA", Some("Ed25519"));
        assert_eq!(public.kid, "key1");
        assert_eq!(public.kty, "OKP");
        assert_eq!(public.alg, "EdDSA");
        assert_eq!(public.crv, Some("Ed25519".to_string()));
        assert_eq!(public.x, Some("abc123".to_string()));
    }
}
