//! Magic Link client plugin. Maps to TS `plugins/magic-link/client.ts`.
use crate::BetterAuthClient;
use crate::error::ClientError;
use crate::plugin::ClientPlugin;

pub struct MagicLinkClient;
impl ClientPlugin for MagicLinkClient {
    fn id(&self) -> &str { "magic-link" }
}

impl BetterAuthClient {
    pub async fn magic_link_send(&self, email: &str, callback_url: Option<&str>) -> Result<serde_json::Value, ClientError> {
        let mut body = serde_json::json!({"email": email});
        if let Some(u) = callback_url { body["callbackURL"] = u.into(); }
        self.post("/magic-link/send", &body).await
    }
    pub async fn magic_link_verify(&self, token: &str) -> Result<serde_json::Value, ClientError> {
        self.get_with_query("/magic-link/verify", &[("token", token)]).await
    }
}
