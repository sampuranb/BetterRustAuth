//! Admin client plugin.
//! Maps to TS `plugins/admin/client.ts`.

use crate::BetterAuthClient;
use crate::error::ClientError;
use std::collections::HashMap;
use crate::plugin::{ClientPlugin, HttpMethod};

pub struct AdminClient;

impl ClientPlugin for AdminClient {
    fn id(&self) -> &str { "admin-client" }
    fn path_methods(&self) -> HashMap<String, HttpMethod> {
        let mut m = HashMap::new();
        m.insert("/admin/list-users".into(), HttpMethod::Get);
        m.insert("/admin/stop-impersonating".into(), HttpMethod::Post);
        m
    }
}

impl BetterAuthClient {
    pub async fn admin_list_users(&self, limit: Option<u32>, offset: Option<u32>) -> Result<serde_json::Value, ClientError> {
        let mut query = Vec::new();
        if let Some(l) = limit { query.push(("limit", l.to_string())); }
        if let Some(o) = offset { query.push(("offset", o.to_string())); }
        let q: Vec<(&str, &str)> = query.iter().map(|(k, v)| (*k, v.as_str())).collect();
        if q.is_empty() { self.get("/admin/list-users").await } else { self.get_with_query("/admin/list-users", &q).await }
    }

    pub async fn admin_ban_user(&self, user_id: &str, reason: Option<&str>) -> Result<serde_json::Value, ClientError> {
        let mut body = serde_json::json!({"userId": user_id});
        if let Some(r) = reason { body["banReason"] = serde_json::Value::String(r.into()); }
        self.post("/admin/ban-user", &body).await
    }

    pub async fn admin_unban_user(&self, user_id: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/admin/unban-user", &serde_json::json!({"userId": user_id})).await
    }

    pub async fn admin_impersonate_user(&self, user_id: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/admin/impersonate-user", &serde_json::json!({"userId": user_id})).await
    }

    pub async fn admin_stop_impersonating(&self) -> Result<serde_json::Value, ClientError> {
        self.post_empty("/admin/stop-impersonating").await
    }

    pub async fn admin_set_role(&self, user_id: &str, role: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/admin/set-role", &serde_json::json!({"userId": user_id, "role": role})).await
    }

    pub async fn admin_remove_user(&self, user_id: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/admin/remove-user", &serde_json::json!({"userId": user_id})).await
    }

    pub async fn admin_set_user_password(&self, user_id: &str, new_password: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/admin/set-user-password", &serde_json::json!({"userId": user_id, "newPassword": new_password})).await
    }

    pub async fn admin_create_user(&self, email: &str, password: &str, name: &str, role: Option<&str>) -> Result<serde_json::Value, ClientError> {
        let mut body = serde_json::json!({"email": email, "password": password, "name": name});
        if let Some(r) = role { body["role"] = serde_json::Value::String(r.into()); }
        self.post("/admin/create-user", &body).await
    }

    pub async fn admin_revoke_user_sessions(&self, user_id: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/admin/revoke-user-sessions", &serde_json::json!({"userId": user_id})).await
    }

    pub async fn admin_revoke_user_session(&self, session_token: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/admin/revoke-user-session", &serde_json::json!({"sessionToken": session_token})).await
    }

    pub async fn admin_list_user_sessions(&self, user_id: &str) -> Result<serde_json::Value, ClientError> {
        self.get_with_query("/admin/list-user-sessions", &[("userId", user_id)]).await
    }

    pub async fn admin_unban_user_by_id(&self, user_id: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/admin/unban-user", &serde_json::json!({"userId": user_id})).await
    }
}
