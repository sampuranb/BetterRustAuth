//! Two-factor authentication client plugin.
//! Maps to TS `plugins/two-factor/client.ts`.

use crate::BetterAuthClient;
use crate::error::ClientError;
use std::collections::HashMap;
use crate::plugin::{ClientPlugin, HttpMethod, SessionSignal};

/// Two-factor client plugin.
pub struct TwoFactorClient;

impl ClientPlugin for TwoFactorClient {
    fn id(&self) -> &str { "two-factor" }

    fn path_methods(&self) -> HashMap<String, HttpMethod> {
        let mut m = HashMap::new();
        m.insert("/two-factor/disable".into(), HttpMethod::Post);
        m.insert("/two-factor/enable".into(), HttpMethod::Post);
        m.insert("/two-factor/send-otp".into(), HttpMethod::Post);
        m.insert("/two-factor/generate-backup-codes".into(), HttpMethod::Post);
        m.insert("/two-factor/get-totp-uri".into(), HttpMethod::Post);
        m.insert("/two-factor/verify-totp".into(), HttpMethod::Post);
        m.insert("/two-factor/verify-otp".into(), HttpMethod::Post);
        m.insert("/two-factor/verify-backup-code".into(), HttpMethod::Post);
        m
    }

    fn session_signals(&self) -> Vec<SessionSignal> {
        vec![SessionSignal { paths: vec!["/two-factor/".into()], prefix_match: true }]
    }
}

impl BetterAuthClient {
    /// Enable TOTP-based two-factor authentication.
    pub async fn two_factor_enable(&self, password: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/two-factor/enable", &serde_json::json!({"password": password})).await
    }

    /// Disable two-factor authentication.
    pub async fn two_factor_disable(&self, password: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/two-factor/disable", &serde_json::json!({"password": password})).await
    }

    /// Get TOTP URI for QR code generation.
    pub async fn two_factor_get_totp_uri(&self, password: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/two-factor/get-totp-uri", &serde_json::json!({"password": password})).await
    }

    /// Verify a TOTP code during sign-in.
    pub async fn two_factor_verify_totp(&self, code: &str, trust_device: Option<bool>) -> Result<serde_json::Value, ClientError> {
        let mut body = serde_json::json!({"code": code});
        if let Some(trust) = trust_device { body["trustDevice"] = serde_json::Value::Bool(trust); }
        self.post("/two-factor/verify-totp", &body).await
    }

    /// Send an OTP for two-factor verification.
    pub async fn two_factor_send_otp(&self) -> Result<serde_json::Value, ClientError> {
        self.post_empty("/two-factor/send-otp").await
    }

    /// Verify an OTP for two-factor.
    pub async fn two_factor_verify_otp(&self, code: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/two-factor/verify-otp", &serde_json::json!({"code": code})).await
    }

    /// Generate backup codes.
    pub async fn two_factor_generate_backup_codes(&self) -> Result<serde_json::Value, ClientError> {
        self.post_empty("/two-factor/generate-backup-codes").await
    }

    /// Verify a backup code.
    pub async fn two_factor_verify_backup_code(&self, code: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/two-factor/verify-backup-code", &serde_json::json!({"code": code})).await
    }
}
