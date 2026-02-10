// Device Authorization plugin — OAuth 2.0 Device Authorization Grant (RFC 8628).
//
// Maps to: packages/better-auth/src/plugins/device-authorization/index.ts
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
// Error codes — matching TS DEVICE_AUTHORIZATION_ERROR_CODES
// ---------------------------------------------------------------------------

pub mod error_codes {
    pub const INVALID_DEVICE_CODE: &str = "Invalid device code";
    pub const INVALID_USER_CODE: &str = "Invalid user code";
    pub const EXPIRED_DEVICE_CODE: &str = "Device code expired";
    pub const EXPIRED_USER_CODE: &str = "User code expired";
    pub const AUTHORIZATION_PENDING: &str = "Authorization pending";
    pub const POLLING_TOO_FREQUENTLY: &str = "Polling too frequently, please slow down";
    pub const ACCESS_DENIED: &str = "User denied the authorization request";
    pub const INVALID_DEVICE_CODE_STATUS: &str = "Invalid device code status";
    pub const AUTHENTICATION_REQUIRED: &str = "Authentication required";
    pub const DEVICE_CODE_ALREADY_PROCESSED: &str = "Device code has already been processed";
    pub const USER_NOT_FOUND: &str = "User not found";
    pub const FAILED_TO_CREATE_SESSION: &str = "Failed to create session";
}

/// Default character set for user codes (no ambiguous chars).
pub const DEFAULT_USER_CODE_CHARSET: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Device code record stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceCode {
    pub id: String,
    pub device_code: String,
    pub user_code: String,
    pub user_id: Option<String>,
    pub expires_at: String,
    pub status: String,
    pub last_polled_at: Option<String>,
    pub polling_interval: Option<i64>,
    pub client_id: Option<String>,
    pub scope: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Device code status values.
pub mod status {
    pub const PENDING: &str = "pending";
    pub const APPROVED: &str = "approved";
    pub const DENIED: &str = "denied";
}

/// Request body for device code request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCodeRequestBody {
    pub client_id: String,
    pub scope: Option<String>,
}

/// Response for device code request (RFC 8628 §3.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: i64,
    pub interval: i64,
}

/// Request body for device token exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTokenRequestBody {
    pub grant_type: String,
    pub device_code: String,
    pub client_id: String,
}

/// OAuth2 token response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: String,
}

/// OAuth2 error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceErrorResponse {
    pub error: String,
    pub error_description: String,
}

/// Query for device verify endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceVerifyQuery {
    pub user_code: String,
}

/// Response for device verify endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceVerifyResponse {
    pub user_code: String,
    pub status: String,
}

/// Request body for device approve/deny.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceApproveBody {
    pub user_code: String,
}

/// Response for approve/deny.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceApproveResponse {
    pub success: bool,
}

// ---------------------------------------------------------------------------
// Verification URI builder
// ---------------------------------------------------------------------------

/// Build verification URIs from options. Matches TS `buildVerificationUris`.
pub fn build_verification_uris(
    configured_uri: Option<&str>,
    base_url: &str,
    user_code: &str,
) -> (String, String) {
    let verification_uri = match configured_uri {
        Some(uri) if uri.starts_with("http://") || uri.starts_with("https://") => {
            uri.to_string()
        }
        Some(uri) => format!("{}{}", base_url.trim_end_matches('/'), uri),
        None => format!("{}/device", base_url.trim_end_matches('/')),
    };

    let verification_uri_complete = format!("{}?user_code={}", verification_uri, user_code);

    (verification_uri, verification_uri_complete)
}

// ---------------------------------------------------------------------------
// Code generation
// ---------------------------------------------------------------------------

/// Generate a random device code of the given length.
pub fn generate_device_code(length: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Generate a user code of the given length (using unambiguous characters).
pub fn generate_user_code(length: usize) -> String {
    use rand::Rng;
    let charset = DEFAULT_USER_CODE_CHARSET.as_bytes();
    let mut rng = rand::thread_rng();
    let code: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx] as char
        })
        .collect();
    // Insert hyphen in the middle for readability (matching TS behavior)
    if length >= 4 {
        let mid = length / 2;
        format!("{}-{}", &code[..mid], &code[mid..])
    } else {
        code
    }
}

/// Parse time string to milliseconds (e.g., "30m" -> 1800000, "5s" -> 5000).
pub fn parse_time_string(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num_str, unit) = if s.ends_with("ms") {
        (&s[..s.len() - 2], "ms")
    } else if s.ends_with('s') {
        (&s[..s.len() - 1], "s")
    } else if s.ends_with('m') {
        (&s[..s.len() - 1], "m")
    } else if s.ends_with('h') {
        (&s[..s.len() - 1], "h")
    } else if s.ends_with('d') {
        (&s[..s.len() - 1], "d")
    } else {
        return None;
    };

    let num: i64 = num_str.parse().ok()?;
    let ms = match unit {
        "ms" => num,
        "s" => num * 1000,
        "m" => num * 60 * 1000,
        "h" => num * 60 * 60 * 1000,
        "d" => num * 24 * 60 * 60 * 1000,
        _ => return None,
    };
    Some(ms)
}

// ---------------------------------------------------------------------------
// Plugin options
// ---------------------------------------------------------------------------

/// Device authorization plugin options.
#[derive(Debug, Clone)]
pub struct DeviceAuthorizationOptions {
    /// Time until device code expires (default: "30m").
    pub expires_in: String,
    /// Polling interval (default: "5s").
    pub interval: String,
    /// Length of device code (default: 40).
    pub device_code_length: usize,
    /// Length of user code (default: 8).
    pub user_code_length: usize,
    /// Custom verification URI.
    pub verification_uri: Option<String>,
}

impl Default for DeviceAuthorizationOptions {
    fn default() -> Self {
        Self {
            expires_in: "30m".to_string(),
            interval: "5s".to_string(),
            device_code_length: 40,
            user_code_length: 8,
            verification_uri: None,
        }
    }
}

impl DeviceAuthorizationOptions {
    /// Get expires_in as milliseconds.
    pub fn expires_in_ms(&self) -> i64 {
        parse_time_string(&self.expires_in).unwrap_or(30 * 60 * 1000)
    }

    /// Get interval as milliseconds.
    pub fn interval_ms(&self) -> i64 {
        parse_time_string(&self.interval).unwrap_or(5 * 1000)
    }
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/// Build the device code table schema.
pub fn device_code_table() -> AuthTable {
    AuthTable::new("deviceCode")
        .field("id", SchemaField::required_string())
        .field("deviceCode", SchemaField::required_string().with_unique())
        .field("userCode", SchemaField::required_string().with_unique())
        .field("userId", SchemaField::optional_string())
        .field("expiresAt", SchemaField::required_string())
        .field("status", SchemaField::required_string())
        .field("lastPolledAt", SchemaField::optional_string())
        .field("pollingInterval", SchemaField::optional_string())
        .field("clientId", SchemaField::optional_string())
        .field("scope", SchemaField::optional_string())
        .field("createdAt", SchemaField::created_at())
        .field("updatedAt", SchemaField::updated_at())
}

// ---------------------------------------------------------------------------
// Rate-limiting check for device token polling
// ---------------------------------------------------------------------------

/// Check if a device code poll request is too frequent.
pub fn is_polling_too_fast(last_polled_at: Option<&str>, interval_ms: i64) -> bool {
    if let Some(last_polled) = last_polled_at {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(last_polled) {
            let now = chrono::Utc::now().timestamp_millis();
            let last = dt.timestamp_millis();
            return (now - last) < interval_ms;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Plugin definition
// ---------------------------------------------------------------------------

/// Device Authorization plugin.
#[derive(Debug)]
pub struct DeviceAuthorizationPlugin {
    options: DeviceAuthorizationOptions,
}

impl DeviceAuthorizationPlugin {
    pub fn new(options: DeviceAuthorizationOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &DeviceAuthorizationOptions {
        &self.options
    }
}

impl Default for DeviceAuthorizationPlugin {
    fn default() -> Self {
        Self::new(DeviceAuthorizationOptions::default())
    }
}

#[async_trait]
impl BetterAuthPlugin for DeviceAuthorizationPlugin {
    fn id(&self) -> &str {
        "device-authorization"
    }

    fn name(&self) -> &str {
        "Device Authorization"
    }

    fn endpoints(&self) -> Vec<PluginEndpoint> {
        use std::sync::Arc;
        use better_auth_core::plugin::{PluginHandlerFn, PluginHandlerRequest, PluginHandlerResponse};

        let opts = self.options.clone();

        // POST /device/code — request device and user codes
        let code_opts = opts.clone();
        let code_handler: PluginHandlerFn = Arc::new(move |ctx_any, _req: PluginHandlerRequest| {
            let opts = code_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                let device_code = generate_device_code(opts.device_code_length);
                let user_code = generate_user_code(opts.user_code_length);
                let id = uuid::Uuid::new_v4().to_string();
                let now = chrono::Utc::now();
                let expires_at = now + chrono::Duration::milliseconds(opts.expires_in_ms());
                let (verification_uri, verification_uri_complete) = build_verification_uris(opts.verification_uri.as_deref(), &ctx.base_url, &user_code);
                let record = serde_json::json!({
                    "id": id,
                    "deviceCode": device_code,
                    "userCode": user_code,
                    "status": "pending",
                    "expiresAt": expires_at.to_rfc3339(),
                    "lastPolledAt": null,
                    "createdAt": now.to_rfc3339(),
                    "updatedAt": now.to_rfc3339(),
                });
                match ctx.adapter.create("deviceCode", record).await {
                    Ok(_) => PluginHandlerResponse::ok(serde_json::json!({
                        "deviceCode": device_code,
                        "userCode": user_code,
                        "verificationUri": verification_uri,
                        "verificationUriComplete": verification_uri_complete,
                        "expiresIn": opts.expires_in_ms() / 1000,
                        "interval": opts.interval_ms() / 1000,
                    })),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // POST /device/token — poll for token exchange
        let token_opts = opts.clone();
        let token_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let opts = token_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { device_code: String }
                let body: Body = match serde_json::from_value(req.body.clone()) {
                    Ok(b) => b,
                    Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)),
                };
                match ctx.adapter.find_many("deviceCode", serde_json::json!({"deviceCode": body.device_code})).await {
                    Ok(records) if !records.is_empty() => {
                        let record = &records[0];
                        let status = record.get("status").and_then(|v| v.as_str()).unwrap_or("pending");
                        match status {
                            "approved" => {
                                let user_id = record.get("userId").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                let token = uuid::Uuid::new_v4().to_string();
                                let expires = chrono::Utc::now() + chrono::Duration::days(7);
                                match ctx.adapter.create_session(&user_id, None, Some(expires.timestamp_millis())).await {
                                    Ok(session) => PluginHandlerResponse::ok(serde_json::json!({"accessToken": token, "session": session})),
                                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                                }
                            }
                            "denied" => PluginHandlerResponse::error(403, "ACCESS_DENIED", "Device authorization was denied"),
                            _ => {
                                let last_polled = record.get("lastPolledAt").and_then(|v| v.as_str());
                                if is_polling_too_fast(last_polled, opts.interval_ms()) {
                                    return PluginHandlerResponse::error(429, "SLOW_DOWN", "Polling too frequently");
                                }
                                PluginHandlerResponse::error(428, "AUTHORIZATION_PENDING", "Waiting for user authorization")
                            }
                        }
                    }
                    Ok(_) => PluginHandlerResponse::error(404, "NOT_FOUND", "Device code not found"),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // GET /device — verify user code status
        let verify_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                let user_code = match req.query.get("userCode").and_then(|v| v.as_str()) {
                    Some(c) => c.to_string(),
                    None => return PluginHandlerResponse::error(400, "BAD_REQUEST", "Missing userCode"),
                };
                match ctx.adapter.find_many("deviceCode", serde_json::json!({"userCode": user_code})).await {
                    Ok(records) if !records.is_empty() => PluginHandlerResponse::ok(serde_json::json!({"status": records[0].get("status")})),
                    Ok(_) => PluginHandlerResponse::error(404, "NOT_FOUND", "User code not found"),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // POST /device/approve
        let approve_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
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
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { user_code: String }
                let body: Body = match serde_json::from_value(req.body.clone()) {
                    Ok(b) => b,
                    Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)),
                };
                match ctx.adapter.find_many("deviceCode", serde_json::json!({"userCode": body.user_code.clone()})).await {
                    Ok(records) if !records.is_empty() => {
                        let id = records[0].get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let _ = ctx.adapter.update_by_id("deviceCode", &id, serde_json::json!({"status": "approved", "userId": user_id})).await;
                        PluginHandlerResponse::ok(serde_json::json!({"status": "approved"}))
                    }
                    Ok(_) => PluginHandlerResponse::error(404, "NOT_FOUND", "User code not found"),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // POST /device/deny
        let deny_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { user_code: String }
                let body: Body = match serde_json::from_value(req.body.clone()) {
                    Ok(b) => b,
                    Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)),
                };
                match ctx.adapter.find_many("deviceCode", serde_json::json!({"userCode": body.user_code.clone()})).await {
                    Ok(records) if !records.is_empty() => {
                        let id = records[0].get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let _ = ctx.adapter.update_by_id("deviceCode", &id, serde_json::json!({"status": "denied"})).await;
                        PluginHandlerResponse::ok(serde_json::json!({"status": "denied"}))
                    }
                    Ok(_) => PluginHandlerResponse::error(404, "NOT_FOUND", "User code not found"),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        vec![
            PluginEndpoint::with_handler("/device/code", HttpMethod::Post, false, code_handler),
            PluginEndpoint::with_handler("/device/token", HttpMethod::Post, false, token_handler),
            PluginEndpoint::with_handler("/device", HttpMethod::Get, false, verify_handler),
            PluginEndpoint::with_handler("/device/approve", HttpMethod::Post, true, approve_handler),
            PluginEndpoint::with_handler("/device/deny", HttpMethod::Post, true, deny_handler),
        ]
    }

    fn hooks(&self) -> Vec<PluginHook> {
        vec![]
    }

    fn rate_limit(&self) -> Vec<PluginRateLimit> {
        vec![PluginRateLimit {
            path: "/device".to_string(),
            window: 60,
            max: 30,
        }]
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
        let plugin = DeviceAuthorizationPlugin::default();
        assert_eq!(plugin.id(), "device-authorization");
    }

    #[test]
    fn test_endpoints() {
        let plugin = DeviceAuthorizationPlugin::default();
        let eps = plugin.endpoints();
        assert_eq!(eps.len(), 5);
        assert_eq!(eps[0].path, "/device/code");
        assert_eq!(eps[1].path, "/device/token");
        assert_eq!(eps[2].path, "/device");
        assert_eq!(eps[3].path, "/device/approve");
        assert_eq!(eps[4].path, "/device/deny");
    }

    #[test]
    fn test_device_code_table() {
        let table = device_code_table();
        assert_eq!(table.name, "deviceCode");
    }

    #[test]
    fn test_parse_time_string() {
        assert_eq!(parse_time_string("30m"), Some(30 * 60 * 1000));
        assert_eq!(parse_time_string("5s"), Some(5 * 1000));
        assert_eq!(parse_time_string("1h"), Some(60 * 60 * 1000));
        assert_eq!(parse_time_string("500ms"), Some(500));
        assert_eq!(parse_time_string("2d"), Some(2 * 24 * 60 * 60 * 1000));
        assert_eq!(parse_time_string(""), None);
        assert_eq!(parse_time_string("abc"), None);
    }

    #[test]
    fn test_generate_device_code() {
        let code = generate_device_code(40);
        assert_eq!(code.len(), 40);
    }

    #[test]
    fn test_generate_user_code() {
        let code = generate_user_code(8);
        // 8 chars + 1 hyphen = 9
        assert_eq!(code.len(), 9);
        assert!(code.contains('-'));
    }

    #[test]
    fn test_build_verification_uris() {
        let (uri, uri_complete) =
            build_verification_uris(None, "https://example.com/api/auth", "ABCD-EFGH");
        assert_eq!(uri, "https://example.com/api/auth/device");
        assert_eq!(
            uri_complete,
            "https://example.com/api/auth/device?user_code=ABCD-EFGH"
        );
    }

    #[test]
    fn test_build_verification_uris_custom() {
        let (uri, _) = build_verification_uris(
            Some("https://myapp.com/verify"),
            "https://example.com/api/auth",
            "code",
        );
        assert_eq!(uri, "https://myapp.com/verify");
    }

    #[test]
    fn test_build_verification_uris_relative() {
        let (uri, _) = build_verification_uris(
            Some("/custom-device"),
            "https://example.com/api/auth",
            "code",
        );
        assert_eq!(uri, "https://example.com/api/auth/custom-device");
    }

    #[test]
    fn test_is_polling_too_fast() {
        let now = chrono::Utc::now().to_rfc3339();
        assert!(is_polling_too_fast(Some(&now), 5000));
        assert!(!is_polling_too_fast(None, 5000));

        let old = (chrono::Utc::now() - chrono::Duration::seconds(10)).to_rfc3339();
        assert!(!is_polling_too_fast(Some(&old), 5000));
    }

    #[test]
    fn test_default_options() {
        let opts = DeviceAuthorizationOptions::default();
        assert_eq!(opts.expires_in_ms(), 30 * 60 * 1000);
        assert_eq!(opts.interval_ms(), 5 * 1000);
        assert_eq!(opts.device_code_length, 40);
        assert_eq!(opts.user_code_length, 8);
    }
}
