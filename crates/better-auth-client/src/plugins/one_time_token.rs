//! One-Time Token client plugin. Maps to TS `plugins/one-time-token/client.ts`.
use crate::BetterAuthClient;
use crate::error::ClientError;
use crate::plugin::ClientPlugin;

pub struct OneTimeTokenClient;
impl ClientPlugin for OneTimeTokenClient {
    fn id(&self) -> &str { "one-time-token" }
}

impl BetterAuthClient {
    pub async fn one_time_token_generate(&self, user_id: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/one-time-token/generate", &serde_json::json!({"userId": user_id})).await
    }
    pub async fn one_time_token_verify(&self, token: &str) -> Result<serde_json::Value, ClientError> {
        self.get_with_query("/one-time-token/verify", &[("token", token)]).await
    }
}
