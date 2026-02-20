// Two-Factor Authentication plugin — TOTP, backup codes, OTP.
//
// Maps to: packages/better-auth/src/plugins/two-factor/index.ts
//          packages/better-auth/src/plugins/two-factor/totp/index.ts
//          packages/better-auth/src/plugins/two-factor/backup-codes/index.ts
//          packages/better-auth/src/plugins/two-factor/otp/index.ts
//          packages/better-auth/src/plugins/two-factor/verify-two-factor.ts
//          packages/better-auth/src/plugins/two-factor/utils.ts

use std::collections::HashMap;

use async_trait::async_trait;

use better_auth_core::db::schema::SchemaField;
use better_auth_core::plugin::{
    BetterAuthPlugin, HookOperation, HookTiming, HttpMethod, PluginEndpoint, PluginHook,
    PluginRateLimit,
};

// ── Constants ───────────────────────────────────────────────────────────────

/// Default trust device cookie max age in seconds (30 days).
pub const TRUST_DEVICE_COOKIE_MAX_AGE: u64 = 30 * 24 * 60 * 60;

/// Cookie name for trust device.
pub const TRUST_DEVICE_COOKIE_NAME: &str = "better-auth.trust-device";

/// Cookie name for the 2FA challenge identifier.
pub const TWO_FACTOR_COOKIE_NAME: &str = "better-auth.two-factor";

/// Default two-factor cookie max age in seconds (10 minutes).
pub const TWO_FACTOR_COOKIE_MAX_AGE: u64 = 10 * 60;

/// Default TOTP digits.
pub const TOTP_DEFAULT_DIGITS: u32 = 6;

/// Default TOTP period in seconds.
pub const TOTP_DEFAULT_PERIOD: u64 = 30;

/// Default backup code count.
pub const BACKUP_CODE_DEFAULT_COUNT: usize = 10;

/// Default backup code length.
pub const BACKUP_CODE_DEFAULT_LENGTH: usize = 10;

/// Default OTP validity period in minutes.
pub const OTP_DEFAULT_PERIOD_MINUTES: u64 = 3;

/// Default OTP digits.
pub const OTP_DEFAULT_DIGITS: usize = 6;

/// Default max OTP verification attempts.
pub const OTP_DEFAULT_MAX_ATTEMPTS: u32 = 5;

// ── Error codes ─────────────────────────────────────────────────────────────

/// Two-factor error codes (matches TS TWO_FACTOR_ERROR_CODES).
pub struct TwoFactorErrorCodes;

impl TwoFactorErrorCodes {
    pub const TOTP_NOT_ENABLED: &'static str = "TOTP_NOT_ENABLED";
    pub const INVALID_CODE: &'static str = "INVALID_CODE";
    pub const BACKUP_CODES_NOT_ENABLED: &'static str = "BACKUP_CODES_NOT_ENABLED";
    pub const INVALID_BACKUP_CODE: &'static str = "INVALID_BACKUP_CODE";
    pub const TWO_FACTOR_NOT_ENABLED: &'static str = "TWO_FACTOR_NOT_ENABLED";
    pub const OTP_HAS_EXPIRED: &'static str = "OTP_HAS_EXPIRED";
    pub const OTP_NOT_CONFIGURED: &'static str = "OTP_NOT_CONFIGURED";
    pub const TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE: &'static str =
        "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE";
    pub const INVALID_TWO_FACTOR_COOKIE: &'static str = "INVALID_TWO_FACTOR_COOKIE";
    pub const TOTP_NOT_CONFIGURED: &'static str = "TOTP_NOT_CONFIGURED";
}

/// Error code descriptions.
pub fn two_factor_error_message(code: &str) -> &'static str {
    match code {
        "TOTP_NOT_ENABLED" => "TOTP is not enabled for this user",
        "INVALID_CODE" => "The verification code is invalid",
        "BACKUP_CODES_NOT_ENABLED" => "Backup codes are not enabled",
        "INVALID_BACKUP_CODE" => "The backup code is invalid",
        "TWO_FACTOR_NOT_ENABLED" => "Two-factor authentication is not enabled",
        "OTP_HAS_EXPIRED" => "The OTP has expired. Please request a new one",
        "OTP_NOT_CONFIGURED" => "OTP is not configured. Please configure the send OTP function",
        "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE" => "Too many failed attempts. Please request a new code",
        "INVALID_TWO_FACTOR_COOKIE" => "Invalid two-factor authentication cookie",
        "TOTP_NOT_CONFIGURED" => "TOTP is not configured",
        _ => "Unknown two-factor error",
    }
}

// ── TOTP options ────────────────────────────────────────────────────────────

/// TOTP configuration options.
#[derive(Debug, Clone)]
pub struct TOTPOptions {
    /// Custom issuer for the TOTP URI.
    pub issuer: Option<String>,
    /// Number of digits (6 or 8).
    pub digits: u32,
    /// Period in seconds.
    pub period: u64,
    /// Whether TOTP is disabled.
    pub disable: bool,
}

impl Default for TOTPOptions {
    fn default() -> Self {
        Self {
            issuer: None,
            digits: TOTP_DEFAULT_DIGITS,
            period: TOTP_DEFAULT_PERIOD,
            disable: false,
        }
    }
}

// ── Backup code options ─────────────────────────────────────────────────────

/// How backup codes are stored.
#[derive(Debug, Clone, PartialEq)]
pub enum BackupCodeStorage {
    /// Store backup codes in plaintext JSON.
    Plain,
    /// Encrypt backup codes using symmetric encryption.
    Encrypted,
    /// Hash backup codes (one-way).
    Hashed,
}

/// Backup code configuration.
#[derive(Debug, Clone)]
pub struct BackupCodeOptions {
    /// Number of backup codes to generate.
    pub amount: usize,
    /// Length of each backup code.
    pub length: usize,
    /// How to store backup codes in the database.
    pub store_backup_codes: BackupCodeStorage,
}

impl Default for BackupCodeOptions {
    fn default() -> Self {
        Self {
            amount: BACKUP_CODE_DEFAULT_COUNT,
            length: BACKUP_CODE_DEFAULT_LENGTH,
            store_backup_codes: BackupCodeStorage::Encrypted,
        }
    }
}

// ── OTP options ─────────────────────────────────────────────────────────────

/// OTP storage mode for two-factor OTPs.
#[derive(Debug, Clone, PartialEq)]
pub enum OTPStorage {
    Plain,
    Encrypted,
    Hashed,
}

/// SMS/Email OTP configuration for 2FA.
#[derive(Debug, Clone)]
pub struct TwoFactorOTPOptions {
    /// Validity period in minutes.
    pub period_minutes: u64,
    /// Number of digits for the OTP.
    pub digits: usize,
    /// Max allowed verification attempts before requiring a new code.
    pub allowed_attempts: u32,
    /// How to store the OTP in the verification table.
    pub store_otp: OTPStorage,
}

impl Default for TwoFactorOTPOptions {
    fn default() -> Self {
        Self {
            period_minutes: OTP_DEFAULT_PERIOD_MINUTES,
            digits: OTP_DEFAULT_DIGITS,
            allowed_attempts: OTP_DEFAULT_MAX_ATTEMPTS,
            store_otp: OTPStorage::Plain,
        }
    }
}

// ── Two-factor plugin options ───────────────────────────────────────────────

/// Two-factor plugin options.
#[derive(Debug, Clone)]
pub struct TwoFactorOptions {
    /// Issuer name for TOTP URIs (defaults to app name).
    pub issuer: Option<String>,
    /// TOTP options.
    pub totp_options: TOTPOptions,
    /// Backup code options.
    pub backup_code_options: BackupCodeOptions,
    /// OTP options.
    pub otp_options: TwoFactorOTPOptions,
    /// Skip the 2FA verification on enable (immediately enable).
    pub skip_verification_on_enable: bool,
    /// Max age for trust device cookie in seconds.
    pub trust_device_max_age: u64,
    /// Max age for the 2FA challenge cookie in seconds.
    pub two_factor_cookie_max_age: u64,
    /// Name of the table storing 2FA secrets (default: "twoFactor").
    pub two_factor_table: String,
}

impl Default for TwoFactorOptions {
    fn default() -> Self {
        Self {
            issuer: None,
            totp_options: TOTPOptions::default(),
            backup_code_options: BackupCodeOptions::default(),
            otp_options: TwoFactorOTPOptions::default(),
            skip_verification_on_enable: false,
            trust_device_max_age: TRUST_DEVICE_COOKIE_MAX_AGE,
            two_factor_cookie_max_age: TWO_FACTOR_COOKIE_MAX_AGE,
            two_factor_table: "twoFactor".to_string(),
        }
    }
}

// ── TOTP URI generation ─────────────────────────────────────────────────────

/// Build a TOTP URI (otpauth:// format) for authenticator apps.
///
/// Format: otpauth://totp/{issuer}:{email}?secret={secret}&issuer={issuer}&digits={digits}&period={period}
pub fn build_totp_uri(
    secret: &str,
    issuer: &str,
    account: &str,
    digits: u32,
    period: u64,
) -> String {
    let encoded_issuer = urlencoding::encode(issuer);
    let encoded_account = urlencoding::encode(account);
    // Base32-encode the secret for TOTP URI
    let encoded_secret = base32_encode(secret.as_bytes());
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&digits={}&period={}",
        encoded_issuer, encoded_account, encoded_secret, encoded_issuer, digits, period,
    )
}

/// Simple base32 encoding (RFC 4648) for TOTP secrets.
fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits_left = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let index = ((buffer >> bits_left) & 0x1F) as usize;
            result.push(ALPHABET[index] as char);
        }
    }
    if bits_left > 0 {
        let index = ((buffer << (5 - bits_left)) & 0x1F) as usize;
        result.push(ALPHABET[index] as char);
    }
    result
}

// ── TOTP code generation & verification ─────────────────────────────────────

/// Generate a TOTP code from a secret using the current time.
///
/// Implements RFC 6238 TOTP with HMAC-SHA1.
pub fn generate_totp(secret: &str, digits: u32, period: u64) -> String {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let counter = now / period;

    let counter_bytes = counter.to_be_bytes();
    let mut mac = Hmac::<Sha1>::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(&counter_bytes);
    let result = mac.finalize().into_bytes();

    let offset = (result[result.len() - 1] & 0x0F) as usize;
    let code = ((result[offset] as u32 & 0x7F) << 24)
        | ((result[offset + 1] as u32) << 16)
        | ((result[offset + 2] as u32) << 8)
        | (result[offset + 3] as u32);

    let modulus = 10u32.pow(digits);
    format!("{:0>width$}", code % modulus, width = digits as usize)
}

/// Verify a TOTP code against a secret.
///
/// Checks the current window and ±1 adjacent window for clock skew tolerance.
pub fn verify_totp(secret: &str, code: &str, digits: u32, period: u64) -> bool {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let counter = now / period;

    for offset in [0i64, -1, 1] {
        let adjusted_counter = (counter as i64 + offset) as u64;
        let counter_bytes = adjusted_counter.to_be_bytes();
        let mut mac = Hmac::<Sha1>::new_from_slice(secret.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(&counter_bytes);
        let result = mac.finalize().into_bytes();

        let off = (result[result.len() - 1] & 0x0F) as usize;
        let otp = ((result[off] as u32 & 0x7F) << 24)
            | ((result[off + 1] as u32) << 16)
            | ((result[off + 2] as u32) << 8)
            | (result[off + 3] as u32);

        let modulus = 10u32.pow(digits);
        let expected = format!("{:0>width$}", otp % modulus, width = digits as usize);

        if constant_time_eq(code.as_bytes(), expected.as_bytes()) {
            return true;
        }
    }
    false
}

// ── Backup code generation ──────────────────────────────────────────────────

/// Generate backup codes as `XXXXX-XXXXX` formatted strings.
pub fn generate_backup_codes(amount: usize, length: usize) -> Vec<String> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        .chars()
        .collect();

    (0..amount)
        .map(|_| {
            let code: String = (0..length)
                .map(|_| chars[rng.gen_range(0..chars.len())])
                .collect();
            if code.len() >= 6 {
                let mid = code.len() / 2;
                format!("{}-{}", &code[..mid], &code[mid..])
            } else {
                code
            }
        })
        .collect()
}

/// Verify a backup code against a list of remaining codes.
///
/// Returns `(is_valid, remaining_codes)` — the used code is removed.
pub fn verify_backup_code(codes: &[String], input: &str) -> (bool, Vec<String>) {
    let found = codes.iter().any(|c| constant_time_eq(c.as_bytes(), input.as_bytes()));
    let remaining: Vec<String> = codes.iter().filter(|c| c.as_str() != input).cloned().collect();
    (found, remaining)
}

// ── OTP generation ──────────────────────────────────────────────────────────

/// Generate a random numeric OTP.
pub fn generate_2fa_otp(digits: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let max = 10usize.pow(digits as u32);
    format!("{:0>width$}", rng.gen_range(0..max), width = digits)
}

/// Build a verification identifier for a 2FA OTP.
pub fn otp_verification_identifier(key: &str) -> String {
    format!("2fa-otp-{}", key)
}

/// Parse stored OTP value "code:attempt_count".
pub fn parse_otp_value(stored: &str) -> Option<(&str, u32)> {
    let parts: Vec<&str> = stored.splitn(2, ':').collect();
    if parts.len() == 2 {
        let count = parts[1].parse::<u32>().unwrap_or(0);
        Some((parts[0], count))
    } else {
        Some((stored, 0))
    }
}

/// Build stored OTP value "code:attempt_count".
pub fn build_otp_value(code: &str, attempts: u32) -> String {
    format!("{}:{}", code, attempts)
}

// ── Default key hasher ──────────────────────────────────────────────────────

/// Default key hasher for OTP hashing (SHA-256 → base64url).
pub fn default_key_hasher(token: &str) -> String {
    use sha2::{Sha256, Digest};
    use base64::Engine;

    let hash = Sha256::digest(token.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

// ── Trust device ────────────────────────────────────────────────────────────

/// Build a trust device cookie value: `{hmac_token}!{trust_identifier}`.
pub fn build_trust_device_cookie(token: &str, identifier: &str) -> String {
    format!("{}!{}", token, identifier)
}

/// Parse a trust device cookie value into `(token, identifier)`.
pub fn parse_trust_device_cookie(cookie: &str) -> Option<(&str, &str)> {
    let parts: Vec<&str> = cookie.splitn(2, '!').collect();
    if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
        Some((parts[0], parts[1]))
    } else {
        None
    }
}

/// Generate a trust device identifier.
pub fn generate_trust_identifier() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        .chars()
        .collect();
    let random: String = (0..32).map(|_| chars[rng.gen_range(0..chars.len())]).collect();
    format!("trust-device-{}", random)
}

/// Generate HMAC-SHA256 token for trust device verification.
pub fn generate_trust_device_hmac(secret: &[u8], user_id: &str, identifier: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use base64::Engine;

    let message = format!("{}!{}", user_id, identifier);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)
        .expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    let result = mac.finalize().into_bytes();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(result)
}

// ── 2FA challenge identifier ────────────────────────────────────────────────

/// Generate a 2FA challenge identifier for the verification table.
pub fn generate_2fa_identifier() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        .chars()
        .collect();
    let random: String = (0..20).map(|_| chars[rng.gen_range(0..chars.len())]).collect();
    format!("2fa-{}", random)
}

// ── Sign-in hook paths ──────────────────────────────────────────────────────

/// Paths that should trigger the 2FA sign-in hook.
pub const TWO_FACTOR_SIGN_IN_PATHS: &[&str] = &[
    "/sign-in/email",
    "/sign-in/username",
    "/sign-in/phone-number",
];

/// Check if a request path should trigger the 2FA challenge.
pub fn is_two_factor_sign_in_path(path: &str) -> bool {
    TWO_FACTOR_SIGN_IN_PATHS.iter().any(|&p| path == p)
}

// ── Constant-time comparison ────────────────────────────────────────────────

/// Constant-time byte comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

// ── Schema ──────────────────────────────────────────────────────────────────

/// Schema for the twoFactor table.
pub fn two_factor_schema() -> Vec<(String, SchemaField)> {
    vec![
        ("id".to_string(), SchemaField::required_string()),
        ("secret".to_string(), SchemaField::required_string()),
        ("backupCodes".to_string(), SchemaField::required_string()),
        ("userId".to_string(), SchemaField::required_string()),
    ]
}

// ── Plugin ──────────────────────────────────────────────────────────────────

/// Two-factor authentication plugin.
#[derive(Debug)]
pub struct TwoFactorPlugin {
    options: TwoFactorOptions,
}

impl TwoFactorPlugin {
    pub fn new(options: TwoFactorOptions) -> Self {
        Self { options }
    }

    /// Access the plugin options.
    pub fn options(&self) -> &TwoFactorOptions {
        &self.options
    }
}

impl Default for TwoFactorPlugin {
    fn default() -> Self {
        Self::new(TwoFactorOptions::default())
    }
}

#[async_trait]
impl BetterAuthPlugin for TwoFactorPlugin {
    fn id(&self) -> &str {
        "two-factor"
    }

    fn name(&self) -> &str {
        "Two-Factor Authentication"
    }

    fn additional_fields(&self) -> HashMap<String, HashMap<String, SchemaField>> {
        let mut user_fields = HashMap::new();
        user_fields.insert("twoFactorEnabled".to_string(), SchemaField::boolean(false));
        let mut fields = HashMap::new();
        fields.insert("user".to_string(), user_fields);
        fields
    }

    fn endpoints(&self) -> Vec<PluginEndpoint> {
        use std::sync::Arc;
        use better_auth_core::plugin::{PluginHandlerFn, PluginHandlerRequest, PluginHandlerResponse};

        let opts = self.options.clone();

        // POST /two-factor/enable
        let enable_opts = opts.clone();
        let enable_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let opts = enable_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                let user_id = match req.session.as_ref().and_then(|s| s.get("user")).and_then(|u| u.get("id")).and_then(|id| id.as_str()) {
                    Some(id) => id.to_string(),
                    None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
                };
                let secret = generate_totp(&uuid::Uuid::new_v4().to_string(), opts.totp_options.digits, opts.totp_options.period);
                let backup_codes = generate_backup_codes(opts.backup_code_options.amount, opts.backup_code_options.length);
                let record = serde_json::json!({
                    "id": uuid::Uuid::new_v4().to_string(),
                    "userId": user_id,
                    "secret": secret,
                    "backupCodes": serde_json::to_string(&backup_codes).unwrap_or_default(),
                    "enabled": true,
                    "createdAt": chrono::Utc::now().to_rfc3339(),
                    "updatedAt": chrono::Utc::now().to_rfc3339(),
                });
                match ctx.adapter.create("twoFactor", record).await {
                    Ok(_) => PluginHandlerResponse::ok(serde_json::json!({"totpURI": secret, "backupCodes": backup_codes})),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // POST /two-factor/disable
        let disable_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                let user_id = match req.session.as_ref().and_then(|s| s.get("user")).and_then(|u| u.get("id")).and_then(|id| id.as_str()) {
                    Some(id) => id.to_string(),
                    None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
                };
                match ctx.adapter.find_many("twoFactor", serde_json::json!({"userId": user_id.clone()})).await {
                    Ok(records) if !records.is_empty() => {
                        let id = records[0].get("id").and_then(|v| v.as_str()).unwrap_or("");
                        let _ = ctx.adapter.delete_by_id("twoFactor", id).await;
                        PluginHandlerResponse::ok(serde_json::json!({"status": true}))
                    }
                    _ => PluginHandlerResponse::error(404, "NOT_FOUND", "2FA not enabled"),
                }
            })
        });

        // POST /two-factor/generate-totp
        let gen_opts = opts.clone();
        let gen_totp: PluginHandlerFn = Arc::new(move |_ctx_any, _req: PluginHandlerRequest| {
            let opts = gen_opts.clone();
            Box::pin(async move {
                let secret = uuid::Uuid::new_v4().to_string().replace('-', "");
                let code = generate_totp(&secret, opts.totp_options.digits, opts.totp_options.period);
                PluginHandlerResponse::ok(serde_json::json!({"code": code, "secret": secret}))
            })
        });

        // POST /two-factor/verify-totp
        let vt_opts = opts.clone();
        let verify_totp_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let opts = vt_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                struct Body { code: String, #[serde(default, rename = "userId")] user_id: Option<String> }
                let body: Body = match serde_json::from_value(req.body.clone()) {
                    Ok(b) => b, Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)),
                };
                let uid = body.user_id.or_else(|| req.session.as_ref().and_then(|s| s.get("user")).and_then(|u| u.get("id")).and_then(|id| id.as_str()).map(|s| s.to_string()));
                let uid = match uid { Some(id) => id, None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Missing userId") };
                match ctx.adapter.find_many("twoFactor", serde_json::json!({"userId": uid.clone()})).await {
                    Ok(records) if !records.is_empty() => {
                        let secret = records[0].get("secret").and_then(|v| v.as_str()).unwrap_or("");
                        if verify_totp(secret, &body.code, opts.totp_options.digits, opts.totp_options.period) {
                            let token = uuid::Uuid::new_v4().to_string();
                            let expires = chrono::Utc::now() + chrono::Duration::days(7);
                            match ctx.adapter.create_session(&uid, None, Some(expires.timestamp_millis())).await {
                                Ok(session) => PluginHandlerResponse::ok(serde_json::json!({"valid": true, "token": token, "session": session})),
                                Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                            }
                        } else {
                            PluginHandlerResponse::error(401, "INVALID_CODE", "Invalid TOTP code")
                        }
                    }
                    _ => PluginHandlerResponse::error(404, "NOT_FOUND", "2FA not enabled"),
                }
            })
        });

        // POST /two-factor/get-totp-uri
        let uri_opts = opts.clone();
        let get_uri: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let opts = uri_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                let uid = match req.session.as_ref().and_then(|s| s.get("user")).and_then(|u| u.get("id")).and_then(|id| id.as_str()) {
                    Some(id) => id.to_string(), None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
                };
                let email = req.session.as_ref().and_then(|s| s.get("user")).and_then(|u| u.get("email")).and_then(|e| e.as_str()).unwrap_or("user").to_string();
                match ctx.adapter.find_many("twoFactor", serde_json::json!({"userId": uid})).await {
                    Ok(records) if !records.is_empty() => {
                        let secret = records[0].get("secret").and_then(|v| v.as_str()).unwrap_or("");
                        let uri = build_totp_uri(secret, &email, opts.totp_options.issuer.as_deref().unwrap_or("Better Auth"), opts.totp_options.digits, opts.totp_options.period);
                        PluginHandlerResponse::ok(serde_json::json!({"totpURI": uri}))
                    }
                    _ => PluginHandlerResponse::error(404, "NOT_FOUND", "2FA not enabled"),
                }
            })
        });

        // POST /two-factor/generate-backup-codes
        let bc_opts = opts.clone();
        let gen_backup: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let opts = bc_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                let uid = match req.session.as_ref().and_then(|s| s.get("user")).and_then(|u| u.get("id")).and_then(|id| id.as_str()) {
                    Some(id) => id.to_string(), None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
                };
                let codes = generate_backup_codes(opts.backup_code_options.amount, opts.backup_code_options.length);
                match ctx.adapter.find_many("twoFactor", serde_json::json!({"userId": uid})).await {
                    Ok(records) if !records.is_empty() => {
                        let id = records[0].get("id").and_then(|v| v.as_str()).unwrap_or("");
                        let _ = ctx.adapter.update_by_id("twoFactor", id, serde_json::json!({"backupCodes": serde_json::to_string(&codes).unwrap_or_default()})).await;
                        PluginHandlerResponse::ok(serde_json::json!({"backupCodes": codes}))
                    }
                    _ => PluginHandlerResponse::error(404, "NOT_FOUND", "2FA not enabled"),
                }
            })
        });

        // POST /two-factor/verify-backup-code
        let vbc_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                struct Body { code: String, #[serde(default, rename = "userId")] user_id: Option<String> }
                let body: Body = match serde_json::from_value(req.body.clone()) { Ok(b) => b, Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)) };
                let uid = body.user_id.or_else(|| req.session.as_ref().and_then(|s| s.get("user")).and_then(|u| u.get("id")).and_then(|id| id.as_str()).map(|s| s.to_string()));
                let uid = match uid { Some(id) => id, None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Missing userId") };
                match ctx.adapter.find_many("twoFactor", serde_json::json!({"userId": uid.clone()})).await {
                    Ok(records) if !records.is_empty() => {
                        let codes_str = records[0].get("backupCodes").and_then(|v| v.as_str()).unwrap_or("[]");
                        let codes: Vec<String> = serde_json::from_str(codes_str).unwrap_or_default();
                        let (valid, remaining) = verify_backup_code(&codes, &body.code);
                        if valid {
                            let id = records[0].get("id").and_then(|v| v.as_str()).unwrap_or("");
                            let _ = ctx.adapter.update_by_id("twoFactor", id, serde_json::json!({"backupCodes": serde_json::to_string(&remaining).unwrap_or_default()})).await;
                            let token = uuid::Uuid::new_v4().to_string();
                            let expires = chrono::Utc::now() + chrono::Duration::days(7);
                            match ctx.adapter.create_session(&uid, None, Some(expires.timestamp_millis())).await {
                                Ok(session) => PluginHandlerResponse::ok(serde_json::json!({"valid": true, "token": token, "session": session})),
                                Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                            }
                        } else {
                            PluginHandlerResponse::error(401, "INVALID_CODE", "Invalid backup code")
                        }
                    }
                    _ => PluginHandlerResponse::error(404, "NOT_FOUND", "2FA not enabled"),
                }
            })
        });

        // POST /two-factor/view-backup-codes
        let view_backup: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                struct Body { #[serde(default, rename = "userId")] user_id: Option<String> }
                let body: Body = serde_json::from_value(req.body.clone()).unwrap_or(Body { user_id: None });
                let uid = body.user_id.or_else(|| req.session.as_ref().and_then(|s| s.get("user")).and_then(|u| u.get("id")).and_then(|id| id.as_str()).map(|s| s.to_string()));
                let uid = match uid { Some(id) => id, None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Missing userId") };
                match ctx.adapter.find_many("twoFactor", serde_json::json!({"userId": uid})).await {
                    Ok(records) if !records.is_empty() => {
                        let codes_str = records[0].get("backupCodes").and_then(|v| v.as_str()).unwrap_or("[]");
                        let codes: Vec<String> = serde_json::from_str(codes_str).unwrap_or_default();
                        PluginHandlerResponse::ok(serde_json::json!({"backupCodes": codes}))
                    }
                    _ => PluginHandlerResponse::error(404, "NOT_FOUND", "2FA not enabled"),
                }
            })
        });

        // POST /two-factor/send-otp
        let so_opts = opts.clone();
        let send_otp: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let _opts = so_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                struct Body { #[serde(default, rename = "userId")] user_id: Option<String> }
                let body: Body = serde_json::from_value(req.body.clone()).unwrap_or(Body { user_id: None });
                let uid = body.user_id.or_else(|| req.session.as_ref().and_then(|s| s.get("user")).and_then(|u| u.get("id")).and_then(|id| id.as_str()).map(|s| s.to_string()));
                let uid = match uid { Some(id) => id, None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Missing userId") };
                let otp = generate_2fa_otp(6);
                let identifier = otp_verification_identifier(&uid);
                let expires = chrono::Utc::now() + chrono::Duration::minutes(5);
                let _ = ctx.adapter.create_verification(&identifier, &build_otp_value(&otp, 0), expires).await;
                PluginHandlerResponse::ok(serde_json::json!({"status": true}))
            })
        });

        // POST /two-factor/verify-otp
        let vo_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                struct Body { code: String, #[serde(default, rename = "userId")] user_id: Option<String> }
                let body: Body = match serde_json::from_value(req.body.clone()) { Ok(b) => b, Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)) };
                let uid = body.user_id.or_else(|| req.session.as_ref().and_then(|s| s.get("user")).and_then(|u| u.get("id")).and_then(|id| id.as_str()).map(|s| s.to_string()));
                let uid = match uid { Some(id) => id, None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Missing userId") };
                let identifier = otp_verification_identifier(&uid);
                match ctx.adapter.find_verification(&identifier).await {
                    Ok(Some(v)) => {
                        let stored = v.get("value").and_then(|v| v.as_str()).unwrap_or("");
                        if let Some((code, _attempts)) = parse_otp_value(stored) {
                            if code == body.code {
                                let _ = ctx.adapter.delete_verification(&identifier).await;
                                let token = uuid::Uuid::new_v4().to_string();
                                let expires = chrono::Utc::now() + chrono::Duration::days(7);
                                match ctx.adapter.create_session(&uid, None, Some(expires.timestamp_millis())).await {
                                    Ok(session) => return PluginHandlerResponse::ok(serde_json::json!({"valid": true, "token": token, "session": session})),
                                    Err(e) => return PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                                }
                            }
                        }
                        PluginHandlerResponse::error(401, "INVALID_CODE", "Invalid OTP code")
                    }
                    _ => PluginHandlerResponse::error(404, "NOT_FOUND", "No pending OTP"),
                }
            })
        });

        vec![
            PluginEndpoint::with_handler("/two-factor/enable", HttpMethod::Post, true, enable_handler),
            PluginEndpoint::with_handler("/two-factor/disable", HttpMethod::Post, true, disable_handler),
            PluginEndpoint::with_handler("/two-factor/generate-totp", HttpMethod::Post, true, gen_totp),
            PluginEndpoint::with_handler("/two-factor/verify-totp", HttpMethod::Post, false, verify_totp_handler),
            PluginEndpoint::with_handler("/two-factor/get-totp-uri", HttpMethod::Post, true, get_uri),
            PluginEndpoint::with_handler("/two-factor/generate-backup-codes", HttpMethod::Post, true, gen_backup),
            PluginEndpoint::with_handler("/two-factor/verify-backup-code", HttpMethod::Post, false, vbc_handler),
            PluginEndpoint::with_handler("/two-factor/view-backup-codes", HttpMethod::Post, false, view_backup),
            PluginEndpoint::with_handler("/two-factor/send-otp", HttpMethod::Post, false, send_otp),
            PluginEndpoint::with_handler("/two-factor/verify-otp", HttpMethod::Post, false, vo_handler),
        ]
    }

    fn hooks(&self) -> Vec<PluginHook> {
        vec![
            // After sign-in: intercept to require 2FA if enabled
            PluginHook {
                model: "session".to_string(),
                timing: HookTiming::After,
                operation: HookOperation::Create,
            },
        ]
    }

    fn rate_limit(&self) -> Vec<PluginRateLimit> {
        vec![PluginRateLimit {
            path: "/two-factor".to_string(),
            window: 10,
            max: 3,
        }]
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_id() {
        let plugin = TwoFactorPlugin::default();
        assert_eq!(plugin.id(), "two-factor");
    }

    #[test]
    fn test_plugin_name() {
        let plugin = TwoFactorPlugin::default();
        assert_eq!(plugin.name(), "Two-Factor Authentication");
    }

    #[test]
    fn test_endpoints_count() {
        let plugin = TwoFactorPlugin::default();
        assert_eq!(plugin.endpoints().len(), 10);
    }

    #[test]
    fn test_schema_fields() {
        let plugin = TwoFactorPlugin::default();
        let fields = plugin.additional_fields();
        assert!(fields["user"].contains_key("twoFactorEnabled"));
    }

    #[test]
    fn test_hooks() {
        let plugin = TwoFactorPlugin::default();
        assert_eq!(plugin.hooks().len(), 1);
        assert_eq!(plugin.hooks()[0].model, "session");
    }

    #[test]
    fn test_rate_limit() {
        let plugin = TwoFactorPlugin::default();
        let limits = plugin.rate_limit();
        assert_eq!(limits.len(), 1);
        assert_eq!(limits[0].window, 10);
        assert_eq!(limits[0].max, 3);
    }

    #[test]
    fn test_base32_encode() {
        assert_eq!(base32_encode(b"Hello"), "JBSWY3DP");
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn test_totp_uri_format() {
        let uri = build_totp_uri("mysecret", "MyApp", "user@example.com", 6, 30);
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("MyApp"));
        assert!(uri.contains("user%40example.com"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }

    #[test]
    fn test_generate_totp_length() {
        let code = generate_totp("testsecret12345", 6, 30);
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));

        let code8 = generate_totp("testsecret12345", 8, 30);
        assert_eq!(code8.len(), 8);
    }

    #[test]
    fn test_verify_totp_current_code() {
        let secret = "test_secret_key_123";
        let code = generate_totp(secret, 6, 30);
        assert!(verify_totp(secret, &code, 6, 30));
    }

    #[test]
    fn test_verify_totp_wrong_code() {
        assert!(!verify_totp("secret", "000000", 6, 30));
    }

    #[test]
    fn test_generate_backup_codes() {
        let codes = generate_backup_codes(10, 10);
        assert_eq!(codes.len(), 10);
        for code in &codes {
            assert!(code.contains('-'), "Backup code should contain dash: {}", code);
            assert_eq!(code.len(), 11); // 5 + '-' + 5
        }
    }

    #[test]
    fn test_verify_backup_code_valid() {
        let codes = vec![
            "abcde-fghij".to_string(),
            "klmno-pqrst".to_string(),
        ];
        let (valid, remaining) = verify_backup_code(&codes, "abcde-fghij");
        assert!(valid);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0], "klmno-pqrst");
    }

    #[test]
    fn test_verify_backup_code_invalid() {
        let codes = vec!["abcde-fghij".to_string()];
        let (valid, remaining) = verify_backup_code(&codes, "wrong-code0");
        assert!(!valid);
        assert_eq!(remaining.len(), 1);
    }

    #[test]
    fn test_generate_2fa_otp() {
        let otp = generate_2fa_otp(6);
        assert_eq!(otp.len(), 6);
        assert!(otp.chars().all(|c| c.is_ascii_digit()));

        let otp8 = generate_2fa_otp(8);
        assert_eq!(otp8.len(), 8);
    }

    #[test]
    fn test_otp_verification_identifier() {
        let id = otp_verification_identifier("user123!session456");
        assert_eq!(id, "2fa-otp-user123!session456");
    }

    #[test]
    fn test_parse_otp_value() {
        let (code, count) = parse_otp_value("123456:3").unwrap();
        assert_eq!(code, "123456");
        assert_eq!(count, 3);

        let (code2, count2) = parse_otp_value("123456:0").unwrap();
        assert_eq!(code2, "123456");
        assert_eq!(count2, 0);
    }

    #[test]
    fn test_build_otp_value() {
        assert_eq!(build_otp_value("123456", 0), "123456:0");
        assert_eq!(build_otp_value("654321", 3), "654321:3");
    }

    #[test]
    fn test_default_key_hasher() {
        let hash1 = default_key_hasher("test_otp");
        let hash2 = default_key_hasher("test_otp");
        assert_eq!(hash1, hash2);
        assert!(!hash1.is_empty());

        // Different input → different hash
        let hash3 = default_key_hasher("different");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_trust_device_cookie() {
        let cookie = build_trust_device_cookie("token123", "trust-device-abc");
        assert_eq!(cookie, "token123!trust-device-abc");

        let (token, id) = parse_trust_device_cookie(&cookie).unwrap();
        assert_eq!(token, "token123");
        assert_eq!(id, "trust-device-abc");
    }

    #[test]
    fn test_parse_trust_device_cookie_invalid() {
        assert!(parse_trust_device_cookie("no-separator").is_none());
        assert!(parse_trust_device_cookie("!trailing").is_none());
        // "leading!" splits to ["leading", ""] — second is empty → None
        assert!(parse_trust_device_cookie("leading!").is_none());
    }

    #[test]
    fn test_generate_trust_identifier() {
        let id = generate_trust_identifier();
        assert!(id.starts_with("trust-device-"));
        assert!(id.len() > 13); // "trust-device-" + random
    }

    #[test]
    fn test_generate_trust_device_hmac() {
        let secret = b"my-secret-key";
        let hmac1 = generate_trust_device_hmac(secret, "user1", "trust-device-abc");
        let hmac2 = generate_trust_device_hmac(secret, "user1", "trust-device-abc");
        assert_eq!(hmac1, hmac2);

        // Different data → different HMAC
        let hmac3 = generate_trust_device_hmac(secret, "user2", "trust-device-abc");
        assert_ne!(hmac1, hmac3);
    }

    #[test]
    fn test_generate_2fa_identifier() {
        let id = generate_2fa_identifier();
        assert!(id.starts_with("2fa-"));
        assert!(id.len() > 4);
    }

    #[test]
    fn test_is_two_factor_sign_in_path() {
        assert!(is_two_factor_sign_in_path("/sign-in/email"));
        assert!(is_two_factor_sign_in_path("/sign-in/username"));
        assert!(is_two_factor_sign_in_path("/sign-in/phone-number"));
        assert!(!is_two_factor_sign_in_path("/sign-up/email"));
        assert!(!is_two_factor_sign_in_path("/sign-in/social"));
    }

    #[test]
    fn test_two_factor_schema() {
        let schema = two_factor_schema();
        assert_eq!(schema.len(), 4);
        let field_names: Vec<&str> = schema.iter().map(|(n, _)| n.as_str()).collect();
        assert!(field_names.contains(&"id"));
        assert!(field_names.contains(&"secret"));
        assert!(field_names.contains(&"backupCodes"));
        assert!(field_names.contains(&"userId"));
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(TwoFactorErrorCodes::TOTP_NOT_ENABLED, "TOTP_NOT_ENABLED");
        assert_eq!(TwoFactorErrorCodes::INVALID_CODE, "INVALID_CODE");
        assert_eq!(TwoFactorErrorCodes::OTP_HAS_EXPIRED, "OTP_HAS_EXPIRED");
    }

    #[test]
    fn test_error_messages() {
        assert!(two_factor_error_message("TOTP_NOT_ENABLED").contains("not enabled"));
        assert!(two_factor_error_message("INVALID_CODE").contains("invalid"));
        assert!(two_factor_error_message("OTP_HAS_EXPIRED").contains("expired"));
        assert!(two_factor_error_message("UNKNOWN").contains("Unknown"));
    }

    #[test]
    fn test_options_defaults() {
        let opts = TwoFactorOptions::default();
        assert_eq!(opts.totp_options.digits, 6);
        assert_eq!(opts.totp_options.period, 30);
        assert_eq!(opts.backup_code_options.amount, 10);
        assert_eq!(opts.backup_code_options.length, 10);
        assert_eq!(opts.otp_options.digits, 6);
        assert_eq!(opts.otp_options.period_minutes, 3);
        assert_eq!(opts.otp_options.allowed_attempts, 5);
        assert_eq!(opts.trust_device_max_age, 30 * 24 * 60 * 60);
        assert_eq!(opts.two_factor_cookie_max_age, 10 * 60);
        assert!(!opts.skip_verification_on_enable);
    }

    #[test]
    fn test_totp_options_custom() {
        let opts = TOTPOptions {
            issuer: Some("MyApp".to_string()),
            digits: 8,
            period: 60,
            disable: false,
        };
        assert_eq!(opts.digits, 8);
        assert_eq!(opts.period, 60);
        assert_eq!(opts.issuer.unwrap(), "MyApp");
    }

    #[test]
    fn test_backup_code_options_custom() {
        let opts = BackupCodeOptions {
            amount: 5,
            length: 8,
            store_backup_codes: BackupCodeStorage::Plain,
        };
        let codes = generate_backup_codes(opts.amount, opts.length);
        assert_eq!(codes.len(), 5);
        for code in &codes {
            // 4-4 = 9 chars total
            assert_eq!(code.len(), 9);
        }
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }
}
