// Captcha plugin — CAPTCHA verification for auth endpoints.
//
// Maps to: packages/better-auth/src/plugins/captcha/index.ts
//
// Hooks (before):
//   Configurable paths (default: /sign-up/email, /sign-in/email) — verify CAPTCHA token
//
// Features:
//   - Cloudflare Turnstile
//   - Google reCAPTCHA v2/v3
//   - hCaptcha
//   - Configurable protected endpoints
//   - Server-to-server token verification

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use better_auth_core::error::ErrorCode;
use better_auth_core::plugin::{BetterAuthPlugin, PluginHook};

// ─── Error codes ────────────────────────────────────────────────────────

pub struct CaptchaErrorCodes;

impl CaptchaErrorCodes {
    pub const CAPTCHA_TOKEN_MISSING: &str = "CAPTCHA token is missing";
    pub const CAPTCHA_VERIFICATION_FAILED: &str = "CAPTCHA verification failed";
    pub const INVALID_CAPTCHA_PROVIDER: &str = "Invalid CAPTCHA provider";
}

// ─── Provider types ────────────────────────────────────────────────────

/// Supported CAPTCHA providers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptchaProvider {
    CloudflareTurnstile,
    GoogleRecaptchaV2,
    GoogleRecaptchaV3,
    HCaptcha,
}

impl CaptchaProvider {
    /// Get the verification URL for this provider.
    pub fn verification_url(&self) -> &str {
        match self {
            Self::CloudflareTurnstile => "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            Self::GoogleRecaptchaV2 | Self::GoogleRecaptchaV3 => {
                "https://www.google.com/recaptcha/api/siteverify"
            }
            Self::HCaptcha => "https://hcaptcha.com/siteverify",
        }
    }

    /// Get the token field name in the request body/header.
    pub fn token_field_name(&self) -> &str {
        match self {
            Self::CloudflareTurnstile => "cf-turnstile-response",
            Self::GoogleRecaptchaV2 | Self::GoogleRecaptchaV3 => "g-recaptcha-response",
            Self::HCaptcha => "h-captcha-response",
        }
    }

    /// Get the response field name for the verification API.
    pub fn response_param_name(&self) -> &str {
        match self {
            Self::CloudflareTurnstile | Self::HCaptcha => "response",
            Self::GoogleRecaptchaV2 | Self::GoogleRecaptchaV3 => "response",
        }
    }

    /// Get the secret field name for the verification API.
    pub fn secret_param_name(&self) -> &str {
        "secret"
    }
}

// ─── Options ────────────────────────────────────────────────────────────

/// Configuration for the CAPTCHA plugin.
#[derive(Debug, Clone)]
pub struct CaptchaOptions {
    /// CAPTCHA provider.
    pub provider: CaptchaProvider,
    /// Secret key for server-to-server verification.
    pub secret_key: String,
    /// Minimum score threshold for reCAPTCHA v3 (0.0 - 1.0, default: 0.5).
    pub min_score: f64,
    /// Paths to protect with CAPTCHA (default: /sign-up/email, /sign-in/email).
    pub endpoints: Vec<String>,
}

impl CaptchaOptions {
    /// Create new options with the given provider and secret key.
    pub fn new(provider: CaptchaProvider, secret_key: impl Into<String>) -> Self {
        Self {
            provider,
            secret_key: secret_key.into(),
            min_score: 0.5,
            endpoints: vec!["/sign-up/email".into(), "/sign-in/email".into()],
        }
    }
}

// ─── Verification types ────────────────────────────────────────────────

/// Request body for CAPTCHA verification API.
#[derive(Debug, Serialize)]
pub struct CaptchaVerifyApiRequest {
    pub secret: String,
    pub response: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remoteip: Option<String>,
}

/// Response from CAPTCHA verification API.
#[derive(Debug, Deserialize)]
pub struct CaptchaVerifyApiResponse {
    pub success: bool,
    /// Only present for reCAPTCHA v3.
    #[serde(default)]
    pub score: Option<f64>,
    /// Error codes (if failed).
    #[serde(default, rename = "error-codes")]
    pub error_codes: Vec<String>,
    /// Action (reCAPTCHA v3).
    #[serde(default)]
    pub action: Option<String>,
    /// Hostname the token was generated on.
    #[serde(default)]
    pub hostname: Option<String>,
}

// ─── Core handler logic ────────────────────────────────────────────────

/// Check if a path should be protected by CAPTCHA.
pub fn is_captcha_protected_path(path: &str, endpoints: &[String]) -> bool {
    endpoints.iter().any(|ep| path == ep)
}

/// Extract the CAPTCHA token from the request body (as JSON value).
pub fn extract_captcha_token(
    body: &serde_json::Value,
    provider: &CaptchaProvider,
) -> Option<String> {
    // Try the provider-specific field name
    let field = provider.token_field_name();
    if let Some(val) = body.get(field).and_then(|v| v.as_str()) {
        return Some(val.to_string());
    }
    // Also try a generic "captchaToken" field
    if let Some(val) = body.get("captchaToken").and_then(|v| v.as_str()) {
        return Some(val.to_string());
    }
    None
}

/// Build the verification request for the CAPTCHA provider API.
pub fn build_verify_request(
    secret_key: &str,
    token: &str,
    remote_ip: Option<&str>,
) -> CaptchaVerifyApiRequest {
    CaptchaVerifyApiRequest {
        secret: secret_key.to_string(),
        response: token.to_string(),
        remoteip: remote_ip.map(|s| s.to_string()),
    }
}

/// Evaluate the verification response.
///
/// For reCAPTCHA v3, also checks if the score meets the minimum threshold.
pub fn evaluate_verification(
    response: &CaptchaVerifyApiResponse,
    provider: &CaptchaProvider,
    min_score: f64,
) -> Result<(), &'static str> {
    if !response.success {
        return Err(CaptchaErrorCodes::CAPTCHA_VERIFICATION_FAILED);
    }
    if *provider == CaptchaProvider::GoogleRecaptchaV3 {
        if let Some(score) = response.score {
            if score < min_score {
                return Err(CaptchaErrorCodes::CAPTCHA_VERIFICATION_FAILED);
            }
        }
    }
    Ok(())
}

// ─── Plugin struct ─────────────────────────────────────────────────────

#[derive(Debug)]
pub struct CaptchaPlugin {
    options: CaptchaOptions,
}

impl CaptchaPlugin {
    pub fn new(options: CaptchaOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &CaptchaOptions {
        &self.options
    }
}

// ─── Plugin trait ──────────────────────────────────────────────────────

#[async_trait]
impl BetterAuthPlugin for CaptchaPlugin {
    fn id(&self) -> &str {
        "captcha"
    }

    fn name(&self) -> &str {
        "CAPTCHA"
    }

    fn hooks(&self) -> Vec<PluginHook> {
        use better_auth_core::plugin::{HookOperation, HookTiming};
        vec![PluginHook {
            model: "request".to_string(),
            timing: HookTiming::Before,
            operation: HookOperation::Create,
        }]
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![ErrorCode::InvalidToken, ErrorCode::Unauthorized]
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_verification_urls() {
        assert!(CaptchaProvider::CloudflareTurnstile
            .verification_url()
            .contains("cloudflare.com"));
        assert!(CaptchaProvider::GoogleRecaptchaV2
            .verification_url()
            .contains("google.com"));
        assert!(CaptchaProvider::HCaptcha
            .verification_url()
            .contains("hcaptcha.com"));
    }

    #[test]
    fn test_provider_token_field_names() {
        assert_eq!(
            CaptchaProvider::CloudflareTurnstile.token_field_name(),
            "cf-turnstile-response"
        );
        assert_eq!(
            CaptchaProvider::GoogleRecaptchaV2.token_field_name(),
            "g-recaptcha-response"
        );
        assert_eq!(
            CaptchaProvider::HCaptcha.token_field_name(),
            "h-captcha-response"
        );
    }

    #[test]
    fn test_is_captcha_protected_path() {
        let endpoints = vec!["/sign-up/email".into(), "/sign-in/email".into()];
        assert!(is_captcha_protected_path("/sign-up/email", &endpoints));
        assert!(is_captcha_protected_path("/sign-in/email", &endpoints));
        assert!(!is_captcha_protected_path("/get-session", &endpoints));
    }

    #[test]
    fn test_extract_captcha_token() {
        let body = serde_json::json!({
            "cf-turnstile-response": "token-123",
            "email": "user@test.com"
        });
        let token =
            extract_captcha_token(&body, &CaptchaProvider::CloudflareTurnstile);
        assert_eq!(token, Some("token-123".into()));
    }

    #[test]
    fn test_extract_captcha_token_generic() {
        let body = serde_json::json!({
            "captchaToken": "generic-token"
        });
        let token =
            extract_captcha_token(&body, &CaptchaProvider::CloudflareTurnstile);
        assert_eq!(token, Some("generic-token".into()));
    }

    #[test]
    fn test_extract_captcha_token_missing() {
        let body = serde_json::json!({ "email": "user@test.com" });
        let token =
            extract_captcha_token(&body, &CaptchaProvider::CloudflareTurnstile);
        assert_eq!(token, None);
    }

    #[test]
    fn test_build_verify_request() {
        let req = build_verify_request("secret-key", "user-token", Some("1.2.3.4"));
        assert_eq!(req.secret, "secret-key");
        assert_eq!(req.response, "user-token");
        assert_eq!(req.remoteip, Some("1.2.3.4".into()));
    }

    #[test]
    fn test_evaluate_verification_success() {
        let response = CaptchaVerifyApiResponse {
            success: true,
            score: None,
            error_codes: vec![],
            action: None,
            hostname: None,
        };
        assert!(evaluate_verification(
            &response,
            &CaptchaProvider::CloudflareTurnstile,
            0.5
        )
        .is_ok());
    }

    #[test]
    fn test_evaluate_verification_failure() {
        let response = CaptchaVerifyApiResponse {
            success: false,
            score: None,
            error_codes: vec!["invalid-input-response".into()],
            action: None,
            hostname: None,
        };
        assert!(evaluate_verification(
            &response,
            &CaptchaProvider::CloudflareTurnstile,
            0.5
        )
        .is_err());
    }

    #[test]
    fn test_evaluate_recaptcha_v3_score_too_low() {
        let response = CaptchaVerifyApiResponse {
            success: true,
            score: Some(0.3),
            error_codes: vec![],
            action: None,
            hostname: None,
        };
        assert!(evaluate_verification(
            &response,
            &CaptchaProvider::GoogleRecaptchaV3,
            0.5
        )
        .is_err());
    }

    #[test]
    fn test_evaluate_recaptcha_v3_score_ok() {
        let response = CaptchaVerifyApiResponse {
            success: true,
            score: Some(0.9),
            error_codes: vec![],
            action: None,
            hostname: None,
        };
        assert!(evaluate_verification(
            &response,
            &CaptchaProvider::GoogleRecaptchaV3,
            0.5
        )
        .is_ok());
    }

    #[test]
    fn test_plugin_id() {
        let plugin = CaptchaPlugin::new(CaptchaOptions::new(
            CaptchaProvider::CloudflareTurnstile,
            "test-secret",
        ));
        assert_eq!(plugin.id(), "captcha");
    }

    #[test]
    fn test_plugin_no_endpoints() {
        let plugin = CaptchaPlugin::new(CaptchaOptions::new(
            CaptchaProvider::HCaptcha,
            "secret",
        ));
        // Captcha uses hooks, not endpoints
        assert!(plugin.endpoints().is_empty());
    }

    #[test]
    fn test_options_defaults() {
        let opts = CaptchaOptions::new(CaptchaProvider::CloudflareTurnstile, "secret");
        assert_eq!(opts.min_score, 0.5);
        assert_eq!(opts.endpoints.len(), 2);
    }

    #[test]
    fn test_api_response_deserialization() {
        let json = serde_json::json!({
            "success": true,
            "score": 0.9,
            "action": "login",
            "hostname": "example.com"
        });
        let resp: CaptchaVerifyApiResponse = serde_json::from_value(json).unwrap();
        assert!(resp.success);
        assert_eq!(resp.score, Some(0.9));
    }
}
