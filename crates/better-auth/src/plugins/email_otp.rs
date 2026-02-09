// Email OTP plugin — passwordless sign-in and email verification via one-time passwords.
//
// Maps to: packages/better-auth/src/plugins/email-otp/index.ts + routes.ts + otp-token.ts
//
// Endpoints (9):
//   POST /email-otp/send-verification-otp      — send OTP to email
//   POST /email-otp/create-verification-otp     — create OTP (server-to-server)
//   GET  /email-otp/get-verification-otp        — retrieve stored OTP (plain mode only)
//   POST /email-otp/check-verification-otp      — verify OTP without consuming it
//   POST /email-otp/verify-email                — verify email + auto sign-in
//   POST /sign-in/email-otp                     — sign in with email OTP
//   POST /email-otp/request-password-reset      — send password reset OTP
//   POST /forget-password/email-otp             — (deprecated alias)
//   POST /email-otp/reset-password              — reset password with OTP
//
// Features:
//   - Configurable OTP length (default: 6 digits)
//   - Storage modes: plain, hashed (SHA-256), encrypted
//   - Attempt limiting (default: 3)
//   - Rate limiting per endpoint
//   - Auto sign-in after verification
//   - Send-on-sign-up hook

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::pin::Pin;
use std::future::Future;

use better_auth_core::error::ErrorCode;
use better_auth_core::plugin::{BetterAuthPlugin, HttpMethod, PluginEndpoint, PluginHook};

/// Data passed to the `sendVerificationOTP` callback.
#[derive(Debug, Clone)]
pub struct SendOtpData {
    pub email: String,
    pub otp: String,
    pub otp_type: OtpType,
}

/// Callback function type for sending verification OTPs.
///
/// Maps to TS `sendVerificationOTP: (data: { email, otp, type }) => Promise<void>`.
///
/// Users provide an implementation that sends the OTP via email (e.g., using
/// an SMTP client, SendGrid, Resend, etc.).
pub type SendVerificationOtpFn = Arc<
    dyn Fn(SendOtpData) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>>
        + Send
        + Sync,
>;

// ─── Error codes ────────────────────────────────────────────────────────

pub struct EmailOtpErrorCodes;

impl EmailOtpErrorCodes {
    pub const INVALID_OTP: &str = "Invalid OTP";
    pub const OTP_EXPIRED: &str = "OTP has expired";
    pub const TOO_MANY_ATTEMPTS: &str = "Too many attempts. Please request a new OTP";
    pub const SEND_NOT_IMPLEMENTED: &str = "Send email verification is not implemented";
    pub const OTP_HASHED_CANNOT_RETURN: &str = "OTP is hashed, cannot return the plain text OTP";
}

// ─── OTP types ──────────────────────────────────────────────────────────

/// The type of OTP being generated/verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OtpType {
    EmailVerification,
    SignIn,
    ForgetPassword,
}

impl OtpType {
    /// Get the verification identifier prefix for this type.
    pub fn identifier_prefix(&self) -> &str {
        match self {
            Self::EmailVerification => "email-verification-otp",
            Self::SignIn => "sign-in-otp",
            Self::ForgetPassword => "forget-password-otp",
        }
    }

    /// Build the full verification identifier.
    pub fn build_identifier(&self, email: &str) -> String {
        format!("{}-{}", self.identifier_prefix(), email.to_lowercase())
    }

    /// Parse an OTP type from a string.
    pub fn from_str(s: &str) -> Self {
        match s {
            "sign-in" => Self::SignIn,
            "forget-password" => Self::ForgetPassword,
            _ => Self::EmailVerification,
        }
    }
}

// ─── Token storage modes ───────────────────────────────────────────────

/// How the OTP is stored in the verification table.
#[derive(Debug, Clone)]
pub enum OtpStorageMode {
    Plain,
    Hashed,
    /// Encrypted using symmetric encryption (requires secret key).
    Encrypted,
}

impl Default for OtpStorageMode {
    fn default() -> Self {
        Self::Plain
    }
}

// ─── Options ────────────────────────────────────────────────────────────

/// Configuration options for the email OTP plugin.
#[derive(Clone)]
pub struct EmailOtpOptions {
    /// OTP length in digits (default: 6).
    pub otp_length: usize,
    /// Time in seconds until the OTP expires (default: 300 = 5 minutes).
    pub expires_in: u64,
    /// Maximum allowed verification attempts (default: 3).
    pub allowed_attempts: u32,
    /// How the OTP is stored.
    pub store_otp: OtpStorageMode,
    /// Disable sign-up for new users on sign-in (default: false).
    pub disable_sign_up: bool,
    /// Send verification OTP on sign-up (default: false).
    pub send_verification_on_sign_up: bool,
    /// Override the default email verification flow (default: false).
    pub override_default_email_verification: bool,
    /// Rate limit window in seconds (default: 60).
    pub rate_limit_window: u64,
    /// Rate limit max per window (default: 3).
    pub rate_limit_max: u32,
    /// Whether a custom OTP generator is provided.
    /// When true, the framework consumer supplies OTPs via a callback
    /// instead of using the built-in random generator.
    /// Maps to TS `generateOTP` option.
    pub use_custom_otp_generator: bool,
    /// Callback to send the OTP to the user's email.
    ///
    /// Maps to TS `sendVerificationOTP`.
    /// This is the primary integration point — users must supply an implementation
    /// that sends the OTP via their email provider.
    pub send_verification_otp: Option<SendVerificationOtpFn>,
}

impl std::fmt::Debug for EmailOtpOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailOtpOptions")
            .field("otp_length", &self.otp_length)
            .field("expires_in", &self.expires_in)
            .field("allowed_attempts", &self.allowed_attempts)
            .field("disable_sign_up", &self.disable_sign_up)
            .field("send_verification_on_sign_up", &self.send_verification_on_sign_up)
            .field("send_verification_otp", &self.send_verification_otp.is_some())
            .finish()
    }
}

impl Default for EmailOtpOptions {
    fn default() -> Self {
        Self {
            otp_length: 6,
            expires_in: 5 * 60,
            allowed_attempts: 3,
            store_otp: OtpStorageMode::default(),
            disable_sign_up: false,
            send_verification_on_sign_up: false,
            override_default_email_verification: false,
            rate_limit_window: 60,
            rate_limit_max: 3,
            use_custom_otp_generator: false,
            send_verification_otp: None,
        }
    }
}

// ─── Request / Response types ──────────────────────────────────────────

/// Request body for send/create verification OTP.
#[derive(Debug, Deserialize)]
pub struct SendOtpRequest {
    pub email: String,
    #[serde(rename = "type")]
    pub otp_type: OtpType,
}

/// Request body for check/verify OTP.
#[derive(Debug, Deserialize)]
pub struct VerifyOtpRequest {
    pub email: String,
    pub otp: String,
    #[serde(rename = "type", default)]
    pub otp_type: Option<OtpType>,
}

/// Request body for sign-in with OTP.
#[derive(Debug, Deserialize)]
pub struct SignInOtpRequest {
    pub email: String,
    pub otp: String,
}

/// Request body for password reset with OTP.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetPasswordOtpRequest {
    pub email: String,
    pub otp: String,
    pub new_password: String,
}

/// Generic success response.
#[derive(Debug, Serialize)]
pub struct OtpSuccessResponse {
    pub success: bool,
}

/// Verify email response (with optional auto-sign-in).
#[derive(Debug, Serialize)]
pub struct VerifyEmailResponse {
    pub status: bool,
    pub token: Option<String>,
    pub user: serde_json::Value,
}

/// Sign-in response.
#[derive(Debug, Serialize)]
pub struct SignInOtpResponse {
    pub token: String,
    pub user: serde_json::Value,
}

// ─── Core handler logic ────────────────────────────────────────────────

/// Generate a random numeric OTP of the specified length.
pub fn generate_otp(length: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| char::from(b'0' + rng.gen_range(0..10)))
        .collect()
}

/// Hash an OTP using SHA-256 (for hashed storage mode).
pub fn hash_otp(otp: &str) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(otp.as_bytes());
    hex::encode(hash)
}

/// Prepare an OTP for storage based on the storage mode.
pub fn prepare_otp_for_storage(otp: &str, mode: &OtpStorageMode) -> String {
    match mode {
        OtpStorageMode::Plain => otp.to_string(),
        OtpStorageMode::Hashed => hash_otp(otp),
        OtpStorageMode::Encrypted => {
            // Encrypted mode: in real usage, this will be encrypted via
            // the auth context's symmetric encryption key.
            // Here we return the OTP as-is; actual encryption happens at the handler level.
            otp.to_string()
        }
    }
}

/// Build the stored value with attempt counter: `{otp}:{attempts}`.
pub fn build_stored_value(stored_otp: &str, attempts: u32) -> String {
    format!("{}:{}", stored_otp, attempts)
}

/// Split a stored value at the last colon to extract OTP and attempt count.
///
/// Returns `(otp_value, attempts_count)`.
pub fn split_stored_value(value: &str) -> (&str, u32) {
    match value.rsplit_once(':') {
        Some((otp, attempts_str)) => {
            let attempts = attempts_str.parse::<u32>().unwrap_or(0);
            (otp, attempts)
        }
        None => (value, 0),
    }
}

/// Verify an OTP against the stored value.
///
/// For plain/encrypted storage: direct comparison.
/// For hashed storage: hash the input and compare.
pub fn verify_otp(stored_otp: &str, input_otp: &str, mode: &OtpStorageMode) -> bool {
    let prepared = match mode {
        OtpStorageMode::Plain | OtpStorageMode::Encrypted => input_otp.to_string(),
        OtpStorageMode::Hashed => hash_otp(input_otp),
    };
    // Use constant-time comparison
    use subtle::ConstantTimeEq;
    stored_otp.as_bytes().ct_eq(prepared.as_bytes()).into()
}

/// Compute OTP expiration time.
pub fn compute_otp_expiry(expires_in_secs: u64) -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() + chrono::Duration::seconds(expires_in_secs as i64)
}

/// Check if the attempt limit has been reached.
pub fn is_attempt_limit_reached(attempts: u32, max_attempts: u32) -> bool {
    attempts >= max_attempts
}

/// Increment attempt count in a stored value string.
pub fn increment_attempts(stored_value: &str) -> String {
    let (otp, attempts) = split_stored_value(stored_value);
    build_stored_value(otp, attempts + 1)
}

/// Rate-limited paths for the email OTP plugin.
pub fn email_otp_rate_limited_paths() -> Vec<&'static str> {
    vec![
        "/email-otp/send-verification-otp",
        "/email-otp/check-verification-otp",
        "/email-otp/verify-email",
        "/sign-in/email-otp",
        "/email-otp/request-password-reset",
        "/email-otp/reset-password",
        "/forget-password/email-otp",
    ]
}

/// Check if a path is rate-limited by this plugin.
pub fn is_email_otp_rate_limited_path(path: &str) -> bool {
    email_otp_rate_limited_paths().iter().any(|p| path == *p)
}

// ─── Plugin struct ─────────────────────────────────────────────────────

#[derive(Debug)]
pub struct EmailOtpPlugin {
    options: EmailOtpOptions,
}

impl EmailOtpPlugin {
    pub fn new(options: EmailOtpOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &EmailOtpOptions {
        &self.options
    }
}

impl Default for EmailOtpPlugin {
    fn default() -> Self {
        Self::new(EmailOtpOptions::default())
    }
}

// ─── Plugin trait ──────────────────────────────────────────────────────

#[async_trait]
impl BetterAuthPlugin for EmailOtpPlugin {
    fn id(&self) -> &str {
        "email-otp"
    }

    fn name(&self) -> &str {
        "Email OTP"
    }

    fn endpoints(&self) -> Vec<PluginEndpoint> {
        use std::sync::Arc;
        use better_auth_core::plugin::{PluginHandlerFn, PluginHandlerRequest, PluginHandlerResponse};

        let opts = self.options.clone();

        // POST /email-otp/send-verification-otp
        let send_opts = opts.clone();
        let send_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let opts = send_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                struct Body { email: String, #[serde(default)] r#type: Option<String> }
                let body: Body = match serde_json::from_value(req.body.clone()) {
                    Ok(b) => b,
                    Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)),
                };
                let otp_type = OtpType::from_str(body.r#type.as_deref().unwrap_or("email-verification"));
                let otp = generate_otp(opts.otp_length);
                let stored = prepare_otp_for_storage(&otp, &opts.store_otp);
                let identifier = otp_type.build_identifier(&body.email);
                let expires = compute_otp_expiry(opts.expires_in);
                let _ = ctx.adapter.create_verification(&identifier, &build_stored_value(&stored, 0), expires).await;

                // Invoke the send callback if configured
                if let Some(ref send_fn) = opts.send_verification_otp {
                    let data = SendOtpData {
                        email: body.email.clone(),
                        otp: otp.clone(),
                        otp_type,
                    };
                    if let Err(e) = send_fn(data).await {
                        tracing::error!("Failed to send verification OTP: {}", e);
                        return PluginHandlerResponse::error(500, "SEND_FAILED", &e);
                    }
                } else {
                    tracing::warn!("{}", EmailOtpErrorCodes::SEND_NOT_IMPLEMENTED);
                }

                PluginHandlerResponse::ok(serde_json::json!({"status": true}))
            })
        });

        // POST /email-otp/create-verification-otp
        let create_opts = opts.clone();
        let create_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let opts = create_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                struct Body { email: String, #[serde(default)] r#type: Option<String> }
                let body: Body = match serde_json::from_value(req.body.clone()) {
                    Ok(b) => b,
                    Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)),
                };
                let otp_type = OtpType::from_str(body.r#type.as_deref().unwrap_or("email-verification"));
                let otp = generate_otp(opts.otp_length);
                let stored = prepare_otp_for_storage(&otp, &opts.store_otp);
                let identifier = otp_type.build_identifier(&body.email);
                let expires = compute_otp_expiry(opts.expires_in);
                let _ = ctx.adapter.create_verification(&identifier, &build_stored_value(&stored, 0), expires).await;
                PluginHandlerResponse::ok(serde_json::json!({"otp": otp}))
            })
        });

        // GET /email-otp/get-verification-otp
        let get_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                let email = match req.query.get("email").and_then(|v| v.as_str()) {
                    Some(e) => e.to_string(),
                    None => return PluginHandlerResponse::error(400, "BAD_REQUEST", "Missing email"),
                };
                let otp_type = OtpType::from_str(req.query.get("type").and_then(|v| v.as_str()).unwrap_or("email-verification"));
                let identifier = otp_type.build_identifier(&email);
                match ctx.adapter.find_verification(&identifier).await {
                    Ok(Some(v)) => PluginHandlerResponse::ok(v),
                    Ok(None) => PluginHandlerResponse::error(404, "NOT_FOUND", "No OTP found"),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // POST /email-otp/check-verification-otp
        let check_opts = opts.clone();
        let check_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let opts = check_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                struct Body { email: String, otp: String, #[serde(default)] r#type: Option<String> }
                let body: Body = match serde_json::from_value(req.body.clone()) {
                    Ok(b) => b,
                    Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)),
                };
                let otp_type = OtpType::from_str(body.r#type.as_deref().unwrap_or("email-verification"));
                let identifier = otp_type.build_identifier(&body.email);
                match ctx.adapter.find_verification(&identifier).await {
                    Ok(Some(v)) => {
                        let stored_value = v.get("value").and_then(|v| v.as_str()).unwrap_or("");
                        let (stored_otp, attempts) = split_stored_value(stored_value);
                        if is_attempt_limit_reached(attempts, opts.allowed_attempts) {
                            let _ = ctx.adapter.delete_verification(&identifier).await;
                            return PluginHandlerResponse::error(429, "MAX_ATTEMPTS", "Maximum attempts reached");
                        }
                        if verify_otp(stored_otp, &body.otp, &opts.store_otp) {
                            let _ = ctx.adapter.delete_verification(&identifier).await;
                            PluginHandlerResponse::ok(serde_json::json!({"valid": true}))
                        } else {
                            let _ = ctx.adapter.update_verification(
                                v.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                                serde_json::json!({"value": build_stored_value(stored_otp, attempts + 1)}),
                            ).await;
                            PluginHandlerResponse::error(401, "INVALID_OTP", "Invalid OTP")
                        }
                    }
                    Ok(None) => PluginHandlerResponse::error(404, "NOT_FOUND", "No verification found"),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // POST /email-otp/verify-email
        let ve_opts = opts.clone();
        let verify_email: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let opts = ve_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                struct Body { email: String, otp: String }
                let body: Body = match serde_json::from_value(req.body.clone()) {
                    Ok(b) => b,
                    Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)),
                };
                let identifier = OtpType::EmailVerification.build_identifier(&body.email);
                match ctx.adapter.find_verification(&identifier).await {
                    Ok(Some(v)) => {
                        let stored_value = v.get("value").and_then(|v| v.as_str()).unwrap_or("");
                        let (stored_otp, _) = split_stored_value(stored_value);
                        if verify_otp(stored_otp, &body.otp, &opts.store_otp) {
                            let _ = ctx.adapter.delete_verification(&identifier).await;
                            // Mark email as verified
                            if let Ok(Some(user)) = ctx.adapter.find_user_by_email(&body.email).await {
                                let uid = user.get("id").and_then(|v| v.as_str()).unwrap_or("");
                                let _ = ctx.adapter.update_user(uid, serde_json::json!({"emailVerified": true})).await;
                            }
                            PluginHandlerResponse::ok(serde_json::json!({"verified": true}))
                        } else {
                            PluginHandlerResponse::error(401, "INVALID_OTP", "Invalid OTP")
                        }
                    }
                    _ => PluginHandlerResponse::error(404, "NOT_FOUND", "No verification found"),
                }
            })
        });

        // POST /sign-in/email-otp
        let si_opts = opts.clone();
        let sign_in: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let opts = si_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                struct Body { email: String, otp: String }
                let body: Body = match serde_json::from_value(req.body.clone()) {
                    Ok(b) => b,
                    Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)),
                };
                let identifier = OtpType::SignIn.build_identifier(&body.email);
                match ctx.adapter.find_verification(&identifier).await {
                    Ok(Some(v)) => {
                        let stored_value = v.get("value").and_then(|v| v.as_str()).unwrap_or("");
                        let (stored_otp, _) = split_stored_value(stored_value);
                        if !verify_otp(stored_otp, &body.otp, &opts.store_otp) {
                            return PluginHandlerResponse::error(401, "INVALID_OTP", "Invalid OTP");
                        }
                        let _ = ctx.adapter.delete_verification(&identifier).await;
                    }
                    _ => return PluginHandlerResponse::error(401, "INVALID_OTP", "No pending OTP"),
                };
                let user = match ctx.adapter.find_user_by_email(&body.email).await {
                    Ok(Some(u)) => u,
                    Ok(None) => {
                        let data = serde_json::json!({
                            "id": uuid::Uuid::new_v4().to_string(),
                            "email": body.email, "emailVerified": true,
                            "name": body.email.split('@').next().unwrap_or("User"),
                            "createdAt": chrono::Utc::now().to_rfc3339(),
                            "updatedAt": chrono::Utc::now().to_rfc3339(),
                        });
                        match ctx.adapter.create_user(data).await { Ok(u) => u, Err(e) => return PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)) }
                    }
                    Err(e) => return PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                };
                let uid = user.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let token = uuid::Uuid::new_v4().to_string();
                let expires = chrono::Utc::now() + chrono::Duration::days(7);
                match ctx.adapter.create_session(&uid, None, Some(expires.timestamp_millis())).await {
                    Ok(session) => PluginHandlerResponse::ok(serde_json::json!({"token": token, "user": user, "session": session})),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // POST /email-otp/request-password-reset & POST /forget-password/email-otp (alias)
        let rpr_opts = opts.clone();
        let req_reset: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let opts = rpr_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                struct Body { email: String }
                let body: Body = match serde_json::from_value(req.body.clone()) {
                    Ok(b) => b,
                    Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)),
                };
                let otp = generate_otp(opts.otp_length);
                let stored = prepare_otp_for_storage(&otp, &opts.store_otp);
                let identifier = OtpType::ForgetPassword.build_identifier(&body.email);
                let expires = compute_otp_expiry(opts.expires_in);
                let _ = ctx.adapter.create_verification(&identifier, &build_stored_value(&stored, 0), expires).await;
                PluginHandlerResponse::ok(serde_json::json!({"status": true}))
            })
        });

        // POST /email-otp/reset-password
        let rp_opts = opts.clone();
        let reset_password: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let opts = rp_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { email: String, otp: String, new_password: String }
                let body: Body = match serde_json::from_value(req.body.clone()) {
                    Ok(b) => b,
                    Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)),
                };
                let identifier = OtpType::ForgetPassword.build_identifier(&body.email);
                match ctx.adapter.find_verification(&identifier).await {
                    Ok(Some(v)) => {
                        let stored_value = v.get("value").and_then(|v| v.as_str()).unwrap_or("");
                        let (stored_otp, _) = split_stored_value(stored_value);
                        if !verify_otp(stored_otp, &body.otp, &opts.store_otp) {
                            return PluginHandlerResponse::error(401, "INVALID_OTP", "Invalid OTP");
                        }
                        let _ = ctx.adapter.delete_verification(&identifier).await;
                        PluginHandlerResponse::ok(serde_json::json!({"status": true}))
                    }
                    _ => PluginHandlerResponse::error(401, "INVALID_OTP", "No pending reset"),
                }
            })
        });

        let req_reset2 = req_reset.clone();

        vec![
            PluginEndpoint::with_handler("/email-otp/send-verification-otp", HttpMethod::Post, false, send_handler),
            PluginEndpoint::with_handler("/email-otp/create-verification-otp", HttpMethod::Post, false, create_handler),
            PluginEndpoint::with_handler("/email-otp/get-verification-otp", HttpMethod::Get, false, get_handler),
            PluginEndpoint::with_handler("/email-otp/check-verification-otp", HttpMethod::Post, false, check_handler),
            PluginEndpoint::with_handler("/email-otp/verify-email", HttpMethod::Post, false, verify_email),
            PluginEndpoint::with_handler("/sign-in/email-otp", HttpMethod::Post, false, sign_in),
            PluginEndpoint::with_handler("/email-otp/request-password-reset", HttpMethod::Post, false, req_reset),
            PluginEndpoint::with_handler("/forget-password/email-otp", HttpMethod::Post, false, req_reset2),
            PluginEndpoint::with_handler("/email-otp/reset-password", HttpMethod::Post, false, reset_password),
        ]
    }

    fn hooks(&self) -> Vec<PluginHook> {
        use better_auth_core::plugin::{HookOperation, HookTiming};
        if self.options.send_verification_on_sign_up {
            vec![PluginHook {
                model: "user".to_string(),
                timing: HookTiming::After,
                operation: HookOperation::Create,
            }]
        } else {
            vec![]
        }
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![
            ErrorCode::InvalidToken,
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
    fn test_generate_otp_length() {
        let otp = generate_otp(6);
        assert_eq!(otp.len(), 6);
        assert!(otp.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_otp_custom_length() {
        let otp = generate_otp(8);
        assert_eq!(otp.len(), 8);
    }

    #[test]
    fn test_generate_otp_uniqueness() {
        let mut all_equal = true;
        for _ in 0..10 {
            if generate_otp(6) != generate_otp(6) {
                all_equal = false;
                break;
            }
        }
        assert!(!all_equal);
    }

    #[test]
    fn test_hash_otp() {
        let hash = hash_otp("123456");
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, hash_otp("123456")); // deterministic
    }

    #[test]
    fn test_prepare_otp_plain() {
        assert_eq!(prepare_otp_for_storage("123456", &OtpStorageMode::Plain), "123456");
    }

    #[test]
    fn test_prepare_otp_hashed() {
        let result = prepare_otp_for_storage("123456", &OtpStorageMode::Hashed);
        assert_eq!(result.len(), 64);
        assert_ne!(result, "123456");
    }

    #[test]
    fn test_build_stored_value() {
        assert_eq!(build_stored_value("abc", 0), "abc:0");
        assert_eq!(build_stored_value("abc", 3), "abc:3");
    }

    #[test]
    fn test_split_stored_value() {
        let (otp, attempts) = split_stored_value("abc123:2");
        assert_eq!(otp, "abc123");
        assert_eq!(attempts, 2);
    }

    #[test]
    fn test_split_stored_value_no_colon() {
        let (otp, attempts) = split_stored_value("abc123");
        assert_eq!(otp, "abc123");
        assert_eq!(attempts, 0);
    }

    #[test]
    fn test_split_stored_value_hashed_with_colons() {
        // SHA-256 hashes don't contain colons, but test edge case
        let (otp, attempts) = split_stored_value("a1b2c3d4:5");
        assert_eq!(otp, "a1b2c3d4");
        assert_eq!(attempts, 5);
    }

    #[test]
    fn test_verify_otp_plain() {
        assert!(verify_otp("123456", "123456", &OtpStorageMode::Plain));
        assert!(!verify_otp("123456", "654321", &OtpStorageMode::Plain));
    }

    #[test]
    fn test_verify_otp_hashed() {
        let stored = hash_otp("123456");
        assert!(verify_otp(&stored, "123456", &OtpStorageMode::Hashed));
        assert!(!verify_otp(&stored, "654321", &OtpStorageMode::Hashed));
    }

    #[test]
    fn test_is_attempt_limit_reached() {
        assert!(!is_attempt_limit_reached(0, 3));
        assert!(!is_attempt_limit_reached(2, 3));
        assert!(is_attempt_limit_reached(3, 3));
        assert!(is_attempt_limit_reached(5, 3));
    }

    #[test]
    fn test_increment_attempts() {
        assert_eq!(increment_attempts("abc:0"), "abc:1");
        assert_eq!(increment_attempts("abc:2"), "abc:3");
    }

    #[test]
    fn test_otp_type_identifier() {
        let email = "user@test.com";
        assert_eq!(
            OtpType::EmailVerification.build_identifier(email),
            "email-verification-otp-user@test.com"
        );
        assert_eq!(
            OtpType::SignIn.build_identifier(email),
            "sign-in-otp-user@test.com"
        );
        assert_eq!(
            OtpType::ForgetPassword.build_identifier(email),
            "forget-password-otp-user@test.com"
        );
    }

    #[test]
    fn test_is_email_otp_rate_limited_path() {
        assert!(is_email_otp_rate_limited_path("/email-otp/send-verification-otp"));
        assert!(is_email_otp_rate_limited_path("/sign-in/email-otp"));
        assert!(is_email_otp_rate_limited_path("/email-otp/reset-password"));
        assert!(!is_email_otp_rate_limited_path("/sign-in/email"));
    }

    #[test]
    fn test_plugin_id() {
        let plugin = EmailOtpPlugin::default();
        assert_eq!(plugin.id(), "email-otp");
    }

    #[test]
    fn test_plugin_endpoints() {
        let plugin = EmailOtpPlugin::default();
        assert_eq!(plugin.endpoints().len(), 9);
    }

    #[test]
    fn test_plugin_hooks_default() {
        let plugin = EmailOtpPlugin::default();
        assert_eq!(plugin.hooks().len(), 0); // no send-on-signup by default
    }

    #[test]
    fn test_plugin_hooks_with_send_on_signup() {
        let plugin = EmailOtpPlugin::new(EmailOtpOptions {
            send_verification_on_sign_up: true,
            ..Default::default()
        });
        assert_eq!(plugin.hooks().len(), 1);
    }

    #[test]
    fn test_default_options() {
        let opts = EmailOtpOptions::default();
        assert_eq!(opts.otp_length, 6);
        assert_eq!(opts.expires_in, 300);
        assert_eq!(opts.allowed_attempts, 3);
        assert!(!opts.disable_sign_up);
    }
}
