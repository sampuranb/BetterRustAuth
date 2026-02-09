//! Anonymous client plugin. Maps to TS `plugins/anonymous/client.ts`.
use crate::BetterAuthClient;
use crate::error::ClientError;
use std::collections::HashMap;
use crate::plugin::{ClientPlugin, HttpMethod, SessionSignal};

pub struct AnonymousClient;
impl ClientPlugin for AnonymousClient {
    fn id(&self) -> &str { "anonymous" }
    fn path_methods(&self) -> HashMap<String, HttpMethod> {
        let mut m = HashMap::new();
        m.insert("/sign-in/anonymous".into(), HttpMethod::Post);
        m.insert("/delete-anonymous-user".into(), HttpMethod::Post);
        m
    }
    fn session_signals(&self) -> Vec<SessionSignal> {
        vec![SessionSignal { paths: vec!["/sign-in/anonymous".into()], prefix_match: false }]
    }
}

impl BetterAuthClient {
    pub async fn sign_in_anonymous(&self) -> Result<serde_json::Value, ClientError> {
        self.post_empty("/sign-in/anonymous").await
    }
    pub async fn delete_anonymous_user(&self) -> Result<serde_json::Value, ClientError> {
        self.post_empty("/delete-anonymous-user").await
    }
}
