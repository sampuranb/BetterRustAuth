//! Device Authorization client plugin. Maps to TS `plugins/device-authorization/client.ts`.
use crate::BetterAuthClient;
use crate::error::ClientError;
use std::collections::HashMap;
use crate::plugin::{ClientPlugin, HttpMethod};

pub struct DeviceAuthClient;
impl ClientPlugin for DeviceAuthClient {
    fn id(&self) -> &str { "device-authorization" }
    fn path_methods(&self) -> HashMap<String, HttpMethod> {
        let mut m = HashMap::new();
        m.insert("/device/code".into(), HttpMethod::Post);
        m.insert("/device/token".into(), HttpMethod::Post);
        m.insert("/device".into(), HttpMethod::Get);
        m.insert("/device/approve".into(), HttpMethod::Post);
        m.insert("/device/deny".into(), HttpMethod::Post);
        m
    }
}

impl BetterAuthClient {
    pub async fn device_request_code(&self, client_id: &str, scope: Option<&str>) -> Result<serde_json::Value, ClientError> {
        let mut body = serde_json::json!({"clientId": client_id});
        if let Some(s) = scope { body["scope"] = s.into(); }
        self.post("/device/code", &body).await
    }
    pub async fn device_poll_token(&self, device_code: &str, client_id: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/device/token", &serde_json::json!({"deviceCode": device_code, "clientId": client_id})).await
    }
    pub async fn device_get(&self, user_code: &str) -> Result<serde_json::Value, ClientError> {
        self.get_with_query("/device", &[("userCode", user_code)]).await
    }
    pub async fn device_approve(&self, user_code: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/device/approve", &serde_json::json!({"userCode": user_code})).await
    }
    pub async fn device_deny(&self, user_code: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/device/deny", &serde_json::json!({"userCode": user_code})).await
    }
}
