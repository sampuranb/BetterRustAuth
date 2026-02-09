//! Multi-Session client plugin. Maps to TS `plugins/multi-session/client.ts`.
use crate::BetterAuthClient;
use crate::error::ClientError;
use crate::plugin::{ClientPlugin, SessionSignal};

pub struct MultiSessionClient;
impl ClientPlugin for MultiSessionClient {
    fn id(&self) -> &str { "multi-session" }
    fn session_signals(&self) -> Vec<SessionSignal> {
        vec![SessionSignal { paths: vec!["/multi-session/set-active".into()], prefix_match: false }]
    }
}

impl BetterAuthClient {
    pub async fn multi_session_list(&self) -> Result<serde_json::Value, ClientError> {
        self.get("/multi-session/list-device-sessions").await
    }
    pub async fn multi_session_set_active(&self, session_token: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/multi-session/set-active", &serde_json::json!({"sessionToken": session_token})).await
    }
    pub async fn multi_session_revoke(&self, session_token: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/multi-session/revoke", &serde_json::json!({"sessionToken": session_token})).await
    }
}
