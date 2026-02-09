//! SIWE client plugin. Maps to TS `plugins/siwe/client.ts`.
use crate::BetterAuthClient;
use crate::error::ClientError;
use crate::plugin::ClientPlugin;

pub struct SiweClient;
impl ClientPlugin for SiweClient {
    fn id(&self) -> &str { "siwe" }
}

impl BetterAuthClient {
    pub async fn siwe_get_nonce(&self) -> Result<serde_json::Value, ClientError> {
        self.get("/siwe/get-nonce").await
    }
    pub async fn siwe_verify(&self, message: &str, signature: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/siwe/verify", &serde_json::json!({"message": message, "signature": signature})).await
    }
    pub async fn siwe_get_session(&self) -> Result<serde_json::Value, ClientError> {
        self.get("/siwe/get-session").await
    }
}
