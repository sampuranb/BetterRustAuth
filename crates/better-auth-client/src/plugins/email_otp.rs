//! Email OTP client plugin. Maps to TS `plugins/email-otp/client.ts`.
use crate::BetterAuthClient;
use crate::error::ClientError;
use crate::plugin::{ClientPlugin, SessionSignal};

pub struct EmailOtpClient;
impl ClientPlugin for EmailOtpClient {
    fn id(&self) -> &str { "email-otp" }
    fn session_signals(&self) -> Vec<SessionSignal> {
        vec![SessionSignal {
            paths: vec!["/email-otp/verify-email".into(), "/sign-in/email-otp".into()],
            prefix_match: false,
        }]
    }
}

impl BetterAuthClient {
    pub async fn email_otp_send(&self, email: &str, otp_type: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/email-otp/send-verification-otp", &serde_json::json!({"email": email, "type": otp_type})).await
    }
    pub async fn email_otp_verify(&self, email: &str, otp: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/email-otp/verify-email", &serde_json::json!({"email": email, "otp": otp})).await
    }
    pub async fn sign_in_email_otp(&self, email: &str, otp: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/sign-in/email-otp", &serde_json::json!({"email": email, "otp": otp})).await
    }
}
