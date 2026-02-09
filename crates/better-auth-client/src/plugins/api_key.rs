//! API Key client plugin. Maps to TS `plugins/api-key/client.ts`.
use crate::BetterAuthClient;
use crate::error::ClientError;
use std::collections::HashMap;
use crate::plugin::{ClientPlugin, HttpMethod};

pub struct ApiKeyClient;
impl ClientPlugin for ApiKeyClient {
    fn id(&self) -> &str { "api-key" }
    fn path_methods(&self) -> HashMap<String, HttpMethod> {
        let mut m = HashMap::new();
        m.insert("/api-key/create".into(), HttpMethod::Post);
        m.insert("/api-key/delete".into(), HttpMethod::Post);
        m.insert("/api-key/delete-all-expired-api-keys".into(), HttpMethod::Post);
        m
    }
}

impl BetterAuthClient {
    pub async fn api_key_create(&self, name: Option<&str>, expires_in: Option<u64>, prefix: Option<&str>) -> Result<serde_json::Value, ClientError> {
        let mut body = serde_json::json!({});
        if let Some(n) = name { body["name"] = n.into(); }
        if let Some(e) = expires_in { body["expiresIn"] = e.into(); }
        if let Some(p) = prefix { body["prefix"] = p.into(); }
        self.post("/api-key/create", &body).await
    }
    pub async fn api_key_list(&self) -> Result<serde_json::Value, ClientError> {
        self.get("/api-key/list").await
    }
    pub async fn api_key_get(&self, key_id: &str) -> Result<serde_json::Value, ClientError> {
        self.get_with_query("/api-key/get", &[("id", key_id)]).await
    }
    pub async fn api_key_update(&self, key_id: &str, data: serde_json::Value) -> Result<serde_json::Value, ClientError> {
        let mut body = data; body["id"] = key_id.into();
        self.post("/api-key/update", &body).await
    }
    pub async fn api_key_delete(&self, key_id: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/api-key/delete", &serde_json::json!({"id": key_id})).await
    }
    pub async fn api_key_delete_all_expired(&self) -> Result<serde_json::Value, ClientError> {
        self.post_empty("/api-key/delete-all-expired-api-keys").await
    }
}
