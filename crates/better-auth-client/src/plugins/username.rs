//! Username client plugin. Maps to TS `plugins/username/client.ts`.
use crate::BetterAuthClient;
use crate::error::ClientError;
use crate::plugin::{ClientPlugin, SessionSignal};

pub struct UsernameClient;
impl ClientPlugin for UsernameClient {
    fn id(&self) -> &str { "username" }
    fn session_signals(&self) -> Vec<SessionSignal> {
        vec![SessionSignal { paths: vec!["/sign-in/username".into()], prefix_match: false }]
    }
}

impl BetterAuthClient {
    pub async fn sign_in_username(&self, username: &str, password: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/sign-in/username", &serde_json::json!({"username": username, "password": password})).await
    }
    pub async fn update_username(&self, username: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/username/update", &serde_json::json!({"username": username})).await
    }
}
