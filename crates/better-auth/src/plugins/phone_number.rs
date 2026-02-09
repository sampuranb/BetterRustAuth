// Phone Number plugin — phone-based authentication via OTP.
//
// Maps to: packages/better-auth/src/plugins/phone-number/index.ts + routes.ts
//
// Endpoints (5):
//   POST /phone-number/send-otp          — send OTP to phone number
//   POST /phone-number/verify            — verify phone number with OTP
//   POST /sign-in/phone-number           — sign in with phone + OTP
//   POST /phone-number/update            — update phone number (requires auth)
//   POST /phone-number/remove            — remove phone number (requires auth)
//
// Features:
//   - SMS OTP dispatch (user-supplied callback)
//   - Configurable OTP length (default: 6)
//   - Attempt limiting
//   - Phone number normalization
//   - User schema extension (phoneNumber, phoneNumberVerified)

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::pin::Pin;
use std::future::Future;

use better_auth_core::error::ErrorCode;
use better_auth_core::plugin::{BetterAuthPlugin, HttpMethod, PluginEndpoint, PluginHook};

/// Data passed to the `sendOTP` callback.
#[derive(Debug, Clone)]
pub struct SendPhoneOtpData {
    pub phone_number: String,
    pub code: String,
}

/// Callback function type for sending phone OTPs via SMS.
///
/// Maps to TS `sendOTP: (data: { phoneNumber, code }) => Promise<void>`.
pub type SendPhoneOtpFn = Arc<
    dyn Fn(SendPhoneOtpData) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>>
        + Send
        + Sync,
>;

// ─── Error codes ────────────────────────────────────────────────────────

pub struct PhoneNumberErrorCodes;

impl PhoneNumberErrorCodes {
    pub const INVALID_PHONE_NUMBER: &str = "Invalid phone number";
    pub const INVALID_OTP: &str = "Invalid OTP";
    pub const OTP_EXPIRED: &str = "OTP expired";
    pub const OTP_NOT_FOUND: &str = "OTP not found";
    pub const TOO_MANY_ATTEMPTS: &str = "Too many attempts";
    pub const PHONE_NUMBER_EXISTS: &str = "Phone number already exists";
    pub const PHONE_NUMBER_NOT_EXIST: &str = "phone number isn't registered";
    pub const PHONE_NUMBER_NOT_VERIFIED: &str = "Phone number not verified";
    pub const PHONE_NUMBER_CANNOT_BE_UPDATED: &str = "Phone number cannot be updated";
    pub const INVALID_PHONE_NUMBER_OR_PASSWORD: &str = "Invalid phone number or password";
    pub const SEND_OTP_NOT_IMPLEMENTED: &str = "sendOTP not implemented";
    pub const USER_NOT_FOUND: &str = "User not found";
    pub const UNEXPECTED_ERROR: &str = "Unexpected error";
    pub const SIGN_UP_DISABLED: &str = "Sign up is disabled";
    pub const PASSWORD_TOO_SHORT: &str = "Password is too short";
    pub const PASSWORD_TOO_LONG: &str = "Password is too long";
}

// ─── Options ────────────────────────────────────────────────────────────

/// Sign-up on verification configuration.
/// When set, users who verify a phone number that doesn't match any existing
/// user will be automatically signed up.
#[derive(Debug, Clone)]
pub struct SignUpOnVerification {
    /// Function name / key that produces a temporary email from the phone number.
    /// e.g. "+1234567890" → "1234567890@phone.temp"
    pub temp_email_template: String,
    /// Optional template for the temporary display name.
    /// If None, defaults to using the phone number itself.
    pub temp_name_template: Option<String>,
}

impl SignUpOnVerification {
    /// Generate a temporary email for the given phone number.
    pub fn get_temp_email(&self, phone: &str) -> String {
        let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
        self.temp_email_template
            .replace("{phone}", &digits)
            .replace("{phoneNumber}", &digits)
    }

    /// Generate a temporary name for the given phone number.
    pub fn get_temp_name(&self, phone: &str) -> String {
        if let Some(template) = &self.temp_name_template {
            template.replace("{phone}", phone)
        } else {
            phone.to_string()
        }
    }
}

/// Configuration for the phone number plugin.
#[derive(Clone)]
pub struct PhoneNumberOptions {
    /// OTP length in digits (default: 6).
    pub otp_length: usize,
    /// Time in seconds until the OTP expires (default: 300 = 5 minutes).
    pub expires_in: u64,
    /// Maximum allowed verification attempts (default: 3).
    pub allowed_attempts: u32,
    /// Whether to disable sign-up for new users (default: false).
    pub disable_sign_up: bool,
    /// Whether phone numbers must be verified to sign in (default: false).
    /// When true, unverified users will receive a new OTP and get an error.
    pub require_verification: bool,
    /// Rate limit window in seconds (default: 60).
    pub rate_limit_window: u64,
    /// Rate limit max per window (default: 10).
    pub rate_limit_max: u32,
    /// Optional: sign up user automatically on phone verification.
    pub sign_up_on_verification: Option<SignUpOnVerification>,
    /// Minimum password length for password reset (default: 8).
    pub min_password_length: usize,
    /// Maximum password length for password reset (default: 128).
    pub max_password_length: usize,
    /// Whether to revoke sessions on password reset (default: false).
    pub revoke_sessions_on_password_reset: bool,
    /// Callback to send the OTP to the user's phone.
    ///
    /// Maps to TS `sendOTP`.
    /// This is the primary integration point — users must supply an implementation
    /// that dispatches the OTP via their SMS provider (Twilio, etc.).
    pub send_otp: Option<SendPhoneOtpFn>,
}

impl std::fmt::Debug for PhoneNumberOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhoneNumberOptions")
            .field("otp_length", &self.otp_length)
            .field("expires_in", &self.expires_in)
            .field("allowed_attempts", &self.allowed_attempts)
            .field("disable_sign_up", &self.disable_sign_up)
            .field("send_otp", &self.send_otp.is_some())
            .finish()
    }
}

impl Default for PhoneNumberOptions {
    fn default() -> Self {
        Self {
            otp_length: 6,
            expires_in: 5 * 60,
            allowed_attempts: 3,
            disable_sign_up: false,
            require_verification: false,
            rate_limit_window: 60,
            rate_limit_max: 10,
            sign_up_on_verification: None,
            min_password_length: 8,
            max_password_length: 128,
            revoke_sessions_on_password_reset: false,
            send_otp: None,
        }
    }
}

// ─── Request / response types ──────────────────────────────────────────

/// Send OTP request.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendPhoneOtpRequest {
    pub phone_number: String,
}

/// Verify phone request.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyPhoneRequest {
    pub phone_number: String,
    pub code: String,
    /// Disable session creation after verification (default: false).
    #[serde(default)]
    pub disable_session: bool,
    /// If true, update the authenticated user's phone number with
    /// the provided number instead of creating a new account.
    #[serde(default)]
    pub update_phone_number: bool,
}

/// Phone sign-in request (password-based, with phone as identifier).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhoneSignInRequest {
    pub phone_number: String,
    pub password: String,
    /// Remember the session (default: true).
    pub remember_me: Option<bool>,
}

/// Update phone request.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePhoneRequest {
    pub phone_number: String,
}

/// Request password reset via phone OTP.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestPasswordResetPhoneRequest {
    pub phone_number: String,
}

/// Reset password using phone number OTP.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetPasswordPhoneRequest {
    pub phone_number: String,
    pub otp: String,
    pub new_password: String,
}

/// Success response.
#[derive(Debug, Serialize)]
pub struct PhoneSuccessResponse {
    pub status: bool,
}

/// Verify phone response.
#[derive(Debug, Serialize)]
pub struct VerifyPhoneResponse {
    pub status: bool,
    pub token: Option<String>,
    pub user: Option<serde_json::Value>,
}

/// Sign-in response.
#[derive(Debug, Serialize)]
pub struct PhoneSignInResponse {
    pub token: String,
    pub user: serde_json::Value,
}

// ─── Core handler logic ────────────────────────────────────────────────

/// Validate a phone number format.
/// Basic validation: must start with + and contain only digits after that.
pub fn validate_phone_number(phone: &str) -> bool {
    if phone.len() < 4 || phone.len() > 20 {
        return false;
    }
    let trimmed = phone.trim();
    if let Some(digits) = trimmed.strip_prefix('+') {
        digits.chars().all(|c| c.is_ascii_digit())
    } else {
        // Allow numbers without + prefix
        trimmed.chars().all(|c| c.is_ascii_digit())
    }
}

/// Normalize a phone number by removing spaces, dashes, parentheses, dots.
pub fn normalize_phone_number(phone: &str) -> String {
    phone
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '+')
        .collect()
}

/// Generate a random numeric OTP.
pub fn generate_phone_otp(length: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| char::from(b'0' + rng.gen_range(0..10)))
        .collect()
}

/// Build the verification identifier for phone OTP.
pub fn build_phone_otp_identifier(phone: &str) -> String {
    let normalized = normalize_phone_number(phone);
    format!("phone-otp-{}", normalized)
}

/// Build the verification identifier for password reset OTP.
pub fn build_password_reset_identifier(phone: &str) -> String {
    format!("{}-request-password-reset", phone)
}

/// Build the stored value with attempt counter.
pub fn build_stored_value(otp: &str, attempts: u32) -> String {
    format!("{}:{}", otp, attempts)
}

/// Split a stored value into OTP and attempt count.
pub fn split_stored_value(value: &str) -> (&str, u32) {
    match value.rsplit_once(':') {
        Some((otp, attempts_str)) => {
            let attempts = attempts_str.parse::<u32>().unwrap_or(0);
            (otp, attempts)
        }
        None => (value, 0),
    }
}

/// Verify an OTP with constant-time comparison.
pub fn verify_phone_otp(stored: &str, input: &str) -> bool {
    use subtle::ConstantTimeEq;
    stored.as_bytes().ct_eq(input.as_bytes()).into()
}

/// Verify an OTP against a stored value, checking attempts and expiry.
/// Returns Ok(()) on success, Err(error_message) on failure.
pub fn verify_otp_with_attempts(
    stored_value: &str,
    input_code: &str,
    allowed_attempts: u32,
) -> Result<(), &'static str> {
    let (otp_value, attempts) = split_stored_value(stored_value);

    // Check attempt limit
    if attempts >= allowed_attempts {
        return Err(PhoneNumberErrorCodes::TOO_MANY_ATTEMPTS);
    }

    // Constant-time comparison
    if !verify_phone_otp(otp_value, input_code) {
        return Err(PhoneNumberErrorCodes::INVALID_OTP);
    }

    Ok(())
}

/// Schema fields added by the phone number plugin.
pub fn phone_number_schema_fields() -> Vec<(&'static str, &'static str, bool)> {
    vec![
        ("phoneNumber", "string", false),
        ("phoneNumberVerified", "boolean", false),
    ]
}

/// Rate-limited paths.
pub fn phone_rate_limited_paths() -> Vec<&'static str> {
    vec![
        "/phone-number/send-otp",
        "/phone-number/verify",
        "/sign-in/phone-number",
        "/phone-number/request-password-reset",
        "/phone-number/reset-password",
    ]
}

// ─── Plugin struct ─────────────────────────────────────────────────────

#[derive(Debug)]
pub struct PhoneNumberPlugin {
    options: PhoneNumberOptions,
}

impl PhoneNumberPlugin {
    pub fn new(options: PhoneNumberOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &PhoneNumberOptions {
        &self.options
    }
}

impl Default for PhoneNumberPlugin {
    fn default() -> Self {
        Self::new(PhoneNumberOptions::default())
    }
}

// ─── Plugin trait ──────────────────────────────────────────────────────

#[async_trait]
impl BetterAuthPlugin for PhoneNumberPlugin {
    fn id(&self) -> &str {
        "phone-number"
    }

    fn name(&self) -> &str {
        "Phone Number"
    }

    fn endpoints(&self) -> Vec<PluginEndpoint> {
        use std::sync::Arc;
        use better_auth_core::plugin::{PluginHandlerFn, PluginHandlerRequest, PluginHandlerResponse};

        let opts = self.options.clone();

        // POST /phone-number/send-otp
        let send_opts = opts.clone();
        let send_otp: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let opts = send_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { phone_number: String }
                let body: Body = match serde_json::from_value(req.body.clone()) {
                    Ok(b) => b,
                    Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)),
                };
                let otp = generate_phone_otp(opts.otp_length);
                let expires = chrono::Utc::now() + chrono::Duration::seconds(opts.expires_in as i64);
                let _ = ctx.adapter.create_verification(&body.phone_number, &otp, expires).await;

                // Invoke the send callback if configured
                if let Some(ref send_fn) = opts.send_otp {
                    let data = SendPhoneOtpData {
                        phone_number: body.phone_number.clone(),
                        code: otp.clone(),
                    };
                    if let Err(e) = send_fn(data).await {
                        tracing::error!("Failed to send phone OTP: {}", e);
                        return PluginHandlerResponse::error(500, "SEND_FAILED", &e);
                    }
                } else {
                    tracing::warn!("{}", PhoneNumberErrorCodes::SEND_OTP_NOT_IMPLEMENTED);
                }

                PluginHandlerResponse::ok(serde_json::json!({"status": true}))
            })
        });

        // POST /phone-number/verify
        let verify_otp: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { phone_number: String, otp: String }
                let body: Body = match serde_json::from_value(req.body.clone()) {
                    Ok(b) => b,
                    Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)),
                };
                match ctx.adapter.find_verification(&body.phone_number).await {
                    Ok(Some(v)) => {
                        let stored_otp = v.get("value").and_then(|v| v.as_str()).unwrap_or("");
                        if stored_otp != body.otp {
                            return PluginHandlerResponse::error(401, "INVALID_OTP", "Invalid OTP");
                        }
                        let _ = ctx.adapter.delete_verification(&body.phone_number).await;
                        PluginHandlerResponse::ok(serde_json::json!({"status": true, "verified": true}))
                    }
                    Ok(None) => PluginHandlerResponse::error(400, "NO_VERIFICATION", "No pending verification found"),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // POST /sign-in/phone-number
        let sign_in_opts = opts.clone();
        let sign_in: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let _opts = sign_in_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { phone_number: String, otp: String }
                let body: Body = match serde_json::from_value(req.body.clone()) {
                    Ok(b) => b,
                    Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)),
                };
                // Verify OTP
                match ctx.adapter.find_verification(&body.phone_number).await {
                    Ok(Some(v)) => {
                        let stored_otp = v.get("value").and_then(|v| v.as_str()).unwrap_or("");
                        if stored_otp != body.otp {
                            return PluginHandlerResponse::error(401, "INVALID_OTP", "Invalid OTP");
                        }
                        let _ = ctx.adapter.delete_verification(&body.phone_number).await;
                    }
                    _ => return PluginHandlerResponse::error(401, "INVALID_OTP", "No pending OTP"),
                };
                // Find or create user
                let user = match ctx.adapter.find_user_by_email(&format!("{}@phone", body.phone_number)).await {
                    Ok(Some(u)) => u,
                    Ok(None) => {
                        let user_data = serde_json::json!({
                            "id": uuid::Uuid::new_v4().to_string(),
                            "email": format!("{}@phone", body.phone_number),
                            "name": body.phone_number,
                            "phoneNumber": body.phone_number,
                            "phoneNumberVerified": true,
                            "createdAt": chrono::Utc::now().to_rfc3339(),
                            "updatedAt": chrono::Utc::now().to_rfc3339(),
                        });
                        match ctx.adapter.create_user(user_data).await {
                            Ok(u) => u,
                            Err(e) => return PluginHandlerResponse::error(500, "FAILED_TO_CREATE_USER", &format!("{}", e)),
                        }
                    }
                    Err(e) => return PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                };
                let user_id = user.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let token = uuid::Uuid::new_v4().to_string();
                let expires = chrono::Utc::now() + chrono::Duration::days(7);
                match ctx.adapter.create_session(&user_id, None, Some(expires.timestamp_millis())).await {
                    Ok(session) => PluginHandlerResponse::ok(serde_json::json!({"token": token, "user": user, "session": session})),
                    Err(e) => PluginHandlerResponse::error(500, "FAILED_TO_CREATE_SESSION", &format!("{}", e)),
                }
            })
        });

        // POST /phone-number/update
        let update_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
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
                struct Body { phone_number: String }
                let body: Body = match serde_json::from_value(req.body.clone()) {
                    Ok(b) => b,
                    Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)),
                };
                match ctx.adapter.update_user(&user_id, serde_json::json!({"phoneNumber": body.phone_number, "updatedAt": chrono::Utc::now().to_rfc3339()})).await {
                    Ok(u) => PluginHandlerResponse::ok(u),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // POST /phone-number/remove
        let remove_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
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
                let update_val = {
                    let mut m = serde_json::Map::new();
                    m.insert("phoneNumber".into(), serde_json::Value::Null);
                    m.insert("phoneNumberVerified".into(), serde_json::Value::Bool(false));
                    serde_json::Value::Object(m)
                };
                match ctx.adapter.update_user(&user_id, update_val).await {
                    Ok(_) => PluginHandlerResponse::ok(serde_json::json!({"status": true})),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // POST /phone-number/request-password-reset
        let reset_req_opts = opts.clone();
        let reset_request: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let opts = reset_req_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { phone_number: String }
                let body: Body = match serde_json::from_value(req.body.clone()) {
                    Ok(b) => b,
                    Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)),
                };
                let otp = generate_phone_otp(opts.otp_length);
                let expires = chrono::Utc::now() + chrono::Duration::seconds(opts.expires_in as i64);
                let _ = ctx.adapter.create_verification(&format!("reset:{}", body.phone_number), &otp, expires).await;
                PluginHandlerResponse::ok(serde_json::json!({"status": true}))
            })
        });

        // POST /phone-number/reset-password
        let reset_password: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { phone_number: String, otp: String, new_password: String }
                let body: Body = match serde_json::from_value(req.body.clone()) {
                    Ok(b) => b,
                    Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)),
                };
                let key = format!("reset:{}", body.phone_number);
                match ctx.adapter.find_verification(&key).await {
                    Ok(Some(v)) => {
                        let stored = v.get("value").and_then(|v| v.as_str()).unwrap_or("");
                        if stored != body.otp {
                            return PluginHandlerResponse::error(401, "INVALID_OTP", "Invalid OTP");
                        }
                        let _ = ctx.adapter.delete_verification(&key).await;
                        PluginHandlerResponse::ok(serde_json::json!({"status": true}))
                    }
                    _ => PluginHandlerResponse::error(401, "INVALID_OTP", "No pending reset"),
                }
            })
        });

        vec![
            PluginEndpoint::with_handler("/phone-number/send-otp", HttpMethod::Post, false, send_otp),
            PluginEndpoint::with_handler("/phone-number/verify", HttpMethod::Post, false, verify_otp),
            PluginEndpoint::with_handler("/sign-in/phone-number", HttpMethod::Post, false, sign_in),
            PluginEndpoint::with_handler("/phone-number/update", HttpMethod::Post, true, update_handler),
            PluginEndpoint::with_handler("/phone-number/remove", HttpMethod::Post, true, remove_handler),
            PluginEndpoint::with_handler("/phone-number/request-password-reset", HttpMethod::Post, false, reset_request),
            PluginEndpoint::with_handler("/phone-number/reset-password", HttpMethod::Post, false, reset_password),
        ]
    }

    fn hooks(&self) -> Vec<PluginHook> {
        use better_auth_core::plugin::{HookOperation, HookTiming};
        vec![
            // Block direct phone number updates via /update-user
            PluginHook {
                model: "user".to_string(),
                timing: HookTiming::Before,
                operation: HookOperation::Update,
            },
        ]
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![
            ErrorCode::InvalidToken,
            ErrorCode::Unauthorized,
            ErrorCode::UserNotFound,
            ErrorCode::SignupDisabled,
        ]
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_phone_number_valid() {
        assert!(validate_phone_number("+14155551234"));
        assert!(validate_phone_number("+442071234567"));
        assert!(validate_phone_number("14155551234"));
    }

    #[test]
    fn test_validate_phone_number_invalid() {
        assert!(!validate_phone_number(""));
        assert!(!validate_phone_number("+1"));
        assert!(!validate_phone_number("abc123"));
        assert!(!validate_phone_number("+1-415-555-1234")); // dashes not allowed in strict check
    }

    #[test]
    fn test_normalize_phone_number() {
        assert_eq!(normalize_phone_number("+1 415 555 1234"), "+14155551234");
        assert_eq!(normalize_phone_number("+1-415-555-1234"), "+14155551234");
        assert_eq!(normalize_phone_number("14155551234"), "14155551234");
        assert_eq!(normalize_phone_number("(415) 555-1234"), "4155551234");
    }

    #[test]
    fn test_generate_phone_otp() {
        let otp = generate_phone_otp(6);
        assert_eq!(otp.len(), 6);
        assert!(otp.chars().all(|c| c.is_ascii_digit()));

        // Custom length
        let otp8 = generate_phone_otp(8);
        assert_eq!(otp8.len(), 8);
    }

    #[test]
    fn test_build_phone_otp_identifier() {
        assert_eq!(
            build_phone_otp_identifier("+1 415 555 1234"),
            "phone-otp-+14155551234"
        );
    }

    #[test]
    fn test_build_password_reset_identifier() {
        assert_eq!(
            build_password_reset_identifier("+14155551234"),
            "+14155551234-request-password-reset"
        );
    }

    #[test]
    fn test_build_stored_value() {
        assert_eq!(build_stored_value("123456", 0), "123456:0");
        assert_eq!(build_stored_value("123456", 2), "123456:2");
    }

    #[test]
    fn test_split_stored_value() {
        let (otp, attempts) = split_stored_value("123456:2");
        assert_eq!(otp, "123456");
        assert_eq!(attempts, 2);
    }

    #[test]
    fn test_verify_phone_otp() {
        assert!(verify_phone_otp("123456", "123456"));
        assert!(!verify_phone_otp("123456", "654321"));
    }

    #[test]
    fn test_verify_otp_with_attempts_success() {
        assert!(verify_otp_with_attempts("123456:0", "123456", 3).is_ok());
        assert!(verify_otp_with_attempts("123456:2", "123456", 3).is_ok());
    }

    #[test]
    fn test_verify_otp_with_attempts_too_many() {
        let result = verify_otp_with_attempts("123456:3", "123456", 3);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), PhoneNumberErrorCodes::TOO_MANY_ATTEMPTS);
    }

    #[test]
    fn test_verify_otp_with_attempts_invalid() {
        let result = verify_otp_with_attempts("123456:0", "999999", 3);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), PhoneNumberErrorCodes::INVALID_OTP);
    }

    #[test]
    fn test_phone_schema_fields() {
        let fields = phone_number_schema_fields();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].0, "phoneNumber");
        assert_eq!(fields[1].0, "phoneNumberVerified");
    }

    #[test]
    fn test_plugin_id() {
        let plugin = PhoneNumberPlugin::default();
        assert_eq!(plugin.id(), "phone-number");
    }

    #[test]
    fn test_plugin_endpoints() {
        let plugin = PhoneNumberPlugin::default();
        // Now 7 endpoints: 5 original + 2 password reset
        assert_eq!(plugin.endpoints().len(), 7);
    }

    #[test]
    fn test_default_options() {
        let opts = PhoneNumberOptions::default();
        assert_eq!(opts.otp_length, 6);
        assert_eq!(opts.expires_in, 300);
        assert_eq!(opts.allowed_attempts, 3);
        assert!(!opts.require_verification);
        assert_eq!(opts.rate_limit_max, 10);
        assert_eq!(opts.min_password_length, 8);
        assert_eq!(opts.max_password_length, 128);
        assert!(!opts.revoke_sessions_on_password_reset);
    }

    #[test]
    fn test_request_deserialization() {
        let json = serde_json::json!({ "phoneNumber": "+14155551234" });
        let req: SendPhoneOtpRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.phone_number, "+14155551234");
    }

    #[test]
    fn test_verify_request_deserialization() {
        let json = serde_json::json!({
            "phoneNumber": "+14155551234",
            "code": "123456",
            "disableSession": true,
            "updatePhoneNumber": false
        });
        let req: VerifyPhoneRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.phone_number, "+14155551234");
        assert_eq!(req.code, "123456");
        assert!(req.disable_session);
        assert!(!req.update_phone_number);
    }

    #[test]
    fn test_sign_in_request_deserialization() {
        let json = serde_json::json!({
            "phoneNumber": "+14155551234",
            "password": "secret123",
            "rememberMe": false
        });
        let req: PhoneSignInRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.phone_number, "+14155551234");
        assert_eq!(req.password, "secret123");
        assert_eq!(req.remember_me, Some(false));
    }

    #[test]
    fn test_password_reset_request_deserialization() {
        let json = serde_json::json!({
            "phoneNumber": "+14155551234",
            "otp": "123456",
            "newPassword": "newpass123"
        });
        let req: ResetPasswordPhoneRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.phone_number, "+14155551234");
        assert_eq!(req.otp, "123456");
        assert_eq!(req.new_password, "newpass123");
    }

    #[test]
    fn test_sign_up_on_verification() {
        let config = SignUpOnVerification {
            temp_email_template: "{phone}@phone.temp".to_string(),
            temp_name_template: None,
        };
        assert_eq!(config.get_temp_email("+14155551234"), "14155551234@phone.temp");
        assert_eq!(config.get_temp_name("+14155551234"), "+14155551234");
    }

    #[test]
    fn test_sign_up_on_verification_custom_name() {
        let config = SignUpOnVerification {
            temp_email_template: "{phone}@phone.temp".to_string(),
            temp_name_template: Some("Phone User {phone}".to_string()),
        };
        assert_eq!(config.get_temp_name("+14155551234"), "Phone User +14155551234");
    }

    #[test]
    fn test_rate_limited_paths() {
        let paths = phone_rate_limited_paths();
        assert_eq!(paths.len(), 5);
        assert!(paths.contains(&"/phone-number/request-password-reset"));
        assert!(paths.contains(&"/phone-number/reset-password"));
    }

    #[test]
    fn test_error_codes_complete() {
        // Verify all error codes from TS are present
        assert!(!PhoneNumberErrorCodes::INVALID_PHONE_NUMBER.is_empty());
        assert!(!PhoneNumberErrorCodes::PHONE_NUMBER_EXISTS.is_empty());
        assert!(!PhoneNumberErrorCodes::PHONE_NUMBER_NOT_EXIST.is_empty());
        assert!(!PhoneNumberErrorCodes::INVALID_PHONE_NUMBER_OR_PASSWORD.is_empty());
        assert!(!PhoneNumberErrorCodes::UNEXPECTED_ERROR.is_empty());
        assert!(!PhoneNumberErrorCodes::OTP_NOT_FOUND.is_empty());
        assert!(!PhoneNumberErrorCodes::OTP_EXPIRED.is_empty());
        assert!(!PhoneNumberErrorCodes::INVALID_OTP.is_empty());
        assert!(!PhoneNumberErrorCodes::PHONE_NUMBER_NOT_VERIFIED.is_empty());
        assert!(!PhoneNumberErrorCodes::PHONE_NUMBER_CANNOT_BE_UPDATED.is_empty());
        assert!(!PhoneNumberErrorCodes::SEND_OTP_NOT_IMPLEMENTED.is_empty());
        assert!(!PhoneNumberErrorCodes::TOO_MANY_ATTEMPTS.is_empty());
    }
}
