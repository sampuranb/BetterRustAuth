//! JWT client plugin. Maps to TS `plugins/jwt/client.ts`.
use crate::BetterAuthClient;
use crate::error::ClientError;
use std::collections::HashMap;
use crate::plugin::{ClientPlugin, HttpMethod};

pub struct JwtClient {
    jwks_path: String,
}

impl JwtClient {
    pub fn new(jwks_path: Option<&str>) -> Self {
        Self { jwks_path: jwks_path.unwrap_or("/jwks").to_string() }
    }
}

impl Default for JwtClient {
    fn default() -> Self { Self::new(None) }
}

impl ClientPlugin for JwtClient {
    fn id(&self) -> &str { "better-auth-client" }
    fn path_methods(&self) -> HashMap<String, HttpMethod> {
        let mut m = HashMap::new();
        m.insert(self.jwks_path.clone(), HttpMethod::Get);
        m
    }
}

impl BetterAuthClient {
    pub async fn jwt_get_token(&self) -> Result<serde_json::Value, ClientError> {
        self.get("/token").await
    }
    pub async fn jwt_jwks(&self) -> Result<serde_json::Value, ClientError> {
        self.get("/jwks").await
    }
    pub async fn jwt_sign(&self, payload: serde_json::Value) -> Result<serde_json::Value, ClientError> {
        self.post("/sign-jwt", &payload).await
    }
    pub async fn jwt_verify(&self, token: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/verify-jwt", &serde_json::json!({"token": token})).await
    }
}
