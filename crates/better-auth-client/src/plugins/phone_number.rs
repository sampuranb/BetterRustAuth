//! Phone Number client plugin. Maps to TS `plugins/phone-number/client.ts`.
use crate::BetterAuthClient;
use crate::error::ClientError;
use crate::plugin::{ClientPlugin, SessionSignal};

pub struct PhoneNumberClient;
impl ClientPlugin for PhoneNumberClient {
    fn id(&self) -> &str { "phoneNumber" }
    fn session_signals(&self) -> Vec<SessionSignal> {
        vec![SessionSignal {
            paths: vec!["/phone-number/update".into(), "/phone-number/verify".into(), "/sign-in/phone-number".into()],
            prefix_match: false,
        }]
    }
}

impl BetterAuthClient {
    pub async fn phone_send_otp(&self, phone_number: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/phone-number/send-otp", &serde_json::json!({"phoneNumber": phone_number})).await
    }
    pub async fn phone_verify(&self, phone_number: &str, code: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/phone-number/verify", &serde_json::json!({"phoneNumber": phone_number, "code": code})).await
    }
    pub async fn phone_update(&self, phone_number: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/phone-number/update", &serde_json::json!({"phoneNumber": phone_number})).await
    }
    pub async fn sign_in_phone(&self, phone_number: &str, code: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/sign-in/phone-number", &serde_json::json!({"phoneNumber": phone_number, "code": code})).await
    }
}
