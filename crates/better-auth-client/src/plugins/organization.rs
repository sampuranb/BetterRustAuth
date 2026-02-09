//! Organization client plugin.
//! Maps to TS `plugins/organization/client.ts`.

use crate::BetterAuthClient;
use crate::error::ClientError;
use std::collections::HashMap;
use crate::plugin::{ClientPlugin, HttpMethod, SessionSignal};

pub struct OrganizationClient;

impl ClientPlugin for OrganizationClient {
    fn id(&self) -> &str { "organization" }
    fn path_methods(&self) -> HashMap<String, HttpMethod> {
        let mut m = HashMap::new();
        m.insert("/organization/get-full-organization".into(), HttpMethod::Get);
        m.insert("/organization/list-user-teams".into(), HttpMethod::Get);
        m
    }
    fn session_signals(&self) -> Vec<SessionSignal> {
        vec![
            SessionSignal { paths: vec!["/organization/set-active".into()], prefix_match: true },
            SessionSignal { paths: vec!["/organization/".into()], prefix_match: true },
        ]
    }
}

impl BetterAuthClient {
    pub async fn org_create(&self, name: &str, slug: Option<&str>) -> Result<serde_json::Value, ClientError> {
        let mut body = serde_json::json!({"name": name});
        if let Some(s) = slug { body["slug"] = s.into(); }
        self.post("/organization/create", &body).await
    }

    pub async fn org_update(&self, org_id: &str, data: serde_json::Value) -> Result<serde_json::Value, ClientError> {
        let mut body = data;
        body["organizationId"] = org_id.into();
        self.post("/organization/update", &body).await
    }

    pub async fn org_delete(&self, org_id: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/organization/delete", &serde_json::json!({"organizationId": org_id})).await
    }

    pub async fn org_get_full(&self) -> Result<serde_json::Value, ClientError> {
        self.get("/organization/get-full-organization").await
    }

    pub async fn org_list(&self) -> Result<serde_json::Value, ClientError> {
        self.get("/organization/list").await
    }

    pub async fn org_set_active(&self, org_id: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/organization/set-active", &serde_json::json!({"organizationId": org_id})).await
    }

    pub async fn org_invite_member(&self, org_id: &str, email: &str, role: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/organization/invite-member", &serde_json::json!({"organizationId": org_id, "email": email, "role": role})).await
    }

    pub async fn org_accept_invitation(&self, invitation_id: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/organization/accept-invitation", &serde_json::json!({"invitationId": invitation_id})).await
    }

    pub async fn org_reject_invitation(&self, invitation_id: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/organization/reject-invitation", &serde_json::json!({"invitationId": invitation_id})).await
    }

    pub async fn org_cancel_invitation(&self, invitation_id: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/organization/cancel-invitation", &serde_json::json!({"invitationId": invitation_id})).await
    }

    pub async fn org_remove_member(&self, org_id: &str, member_id: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/organization/remove-member", &serde_json::json!({"organizationId": org_id, "memberId": member_id})).await
    }

    pub async fn org_update_member_role(&self, org_id: &str, member_id: &str, role: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/organization/update-member-role", &serde_json::json!({"organizationId": org_id, "memberId": member_id, "role": role})).await
    }

    pub async fn org_leave(&self, org_id: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/organization/leave", &serde_json::json!({"organizationId": org_id})).await
    }

    pub async fn org_get_active_member(&self) -> Result<serde_json::Value, ClientError> {
        self.get("/organization/get-active-member").await
    }

    pub async fn org_get_active_member_role(&self) -> Result<serde_json::Value, ClientError> {
        self.get("/organization/get-active-member-role").await
    }

    pub async fn org_list_members(&self, org_id: &str) -> Result<serde_json::Value, ClientError> {
        self.get_with_query("/organization/list-members", &[("organizationId", org_id)]).await
    }

    pub async fn org_list_invitations(&self, org_id: &str) -> Result<serde_json::Value, ClientError> {
        self.get_with_query("/organization/list-invitations", &[("organizationId", org_id)]).await
    }

    pub async fn org_has_permission(&self, permission: serde_json::Value) -> Result<serde_json::Value, ClientError> {
        self.post("/organization/has-permission", &permission).await
    }

    pub async fn org_create_team(&self, org_id: &str, name: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/organization/create-team", &serde_json::json!({"organizationId": org_id, "name": name})).await
    }

    pub async fn org_list_teams(&self, org_id: &str) -> Result<serde_json::Value, ClientError> {
        self.get_with_query("/organization/list-teams", &[("organizationId", org_id)]).await
    }

    pub async fn org_list_user_teams(&self) -> Result<serde_json::Value, ClientError> {
        self.get("/organization/list-user-teams").await
    }
}
