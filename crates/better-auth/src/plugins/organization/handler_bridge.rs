// Organization plugin handler bridge.
//
// Bridges the type-erased `PluginHandlerFn` dispatch to the concrete
// organization handler functions in routes_org.rs, routes_members.rs,
// routes_access.rs, and routes_teams.rs.
//
// Each function captures OrganizationOptions at registration time and
// receives AuthContext (via type-erased Arc) + PluginHandlerRequest at runtime.

use std::sync::Arc;

use better_auth_core::plugin::{
    PluginHandlerFn, PluginHandlerRequest, PluginHandlerResponse,
};

use crate::context::AuthContext;
use super::adapter::OrgAdapter;
use super::OrganizationOptions;
use super::routes_org;
use super::routes_members;
use super::routes_access;
use super::routes_teams;
use super::types::*;

// ─── Context extraction helpers ─────────────────────────────────

/// Extract the typed `AuthContext` from the type-erased `Arc<dyn Any>`.
fn extract_ctx(ctx: &Arc<dyn std::any::Any + Send + Sync>) -> Arc<AuthContext> {
    ctx.clone()
        .downcast::<AuthContext>()
        .expect("Plugin handler received wrong context type; expected AuthContext")
}

/// Build OrgAdapter from the AuthContext.
fn build_adapter(ctx: &AuthContext) -> OrgAdapter {
    OrgAdapter::new(ctx.adapter.clone())
}

/// Extract user_id from the session in the request.
fn extract_user_id(req: &PluginHandlerRequest) -> Option<String> {
    req.session.as_ref().and_then(|s| {
        s.get("user").and_then(|u| u.get("id")).and_then(|id| id.as_str()).map(|s| s.to_string())
    })
}

/// Extract active organization ID from the session.
fn extract_active_org_id(req: &PluginHandlerRequest) -> Option<String> {
    req.session.as_ref().and_then(|s| {
        s.get("session")
            .and_then(|sess| sess.get("activeOrganizationId"))
            .and_then(|id| id.as_str())
            .map(|s| s.to_string())
    })
}

/// Convert an OrgRouteError to a PluginHandlerResponse.
fn org_error_to_response(e: routes_org::OrgRouteError) -> PluginHandlerResponse {
    match e {
        routes_org::OrgRouteError::Unauthorized(msg) => PluginHandlerResponse::error(401, "UNAUTHORIZED", &msg),
        routes_org::OrgRouteError::Forbidden(msg) => PluginHandlerResponse::error(403, "FORBIDDEN", &msg),
        routes_org::OrgRouteError::BadRequest(msg) => PluginHandlerResponse::error(400, "BAD_REQUEST", &msg),
        routes_org::OrgRouteError::NotFound(msg) => PluginHandlerResponse::error(404, "NOT_FOUND", &msg),
        routes_org::OrgRouteError::Adapter(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
    }
}

// ─── Org CRUD handlers ──────────────────────────────────────────

/// POST /organization/create
pub fn create_organization_handler(options: OrganizationOptions) -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        let options = options.clone();
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let body: CreateOrganizationRequest = match serde_json::from_value(req.body.clone()) {
                Ok(b) => b,
                Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
            };
            match routes_org::handle_create_organization(
                &adapter, &user_id, &options, req.session_token.as_deref(), body,
            ).await {
                Ok(result) => PluginHandlerResponse::created(result),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// GET /organization/get-full-organization
pub fn get_full_organization_handler(options: OrganizationOptions) -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        let options = options.clone();
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let active_org_id = extract_active_org_id(&req);
            let org_id = req.query.get("organizationId").and_then(|v| v.as_str()).map(|s| s.to_string());
            let org_slug = req.query.get("organizationSlug").and_then(|v| v.as_str()).map(|s| s.to_string());
            match routes_org::handle_get_full_organization(
                &adapter, &user_id, req.session_token.as_deref(),
                active_org_id.as_deref(), &options,
                org_id.as_deref(), org_slug.as_deref(), None,
            ).await {
                Ok(Some(org)) => PluginHandlerResponse::ok(serde_json::to_value(org).unwrap_or_default()),
                Ok(None) => PluginHandlerResponse::error(404, "NOT_FOUND", "Organization not found"),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// POST /organization/update
pub fn update_organization_handler(options: OrganizationOptions) -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        let options = options.clone();
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let active_org_id = extract_active_org_id(&req);
            let body: UpdateOrganizationRequest = match serde_json::from_value(req.body.clone()) {
                Ok(b) => b,
                Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
            };
            match routes_org::handle_update_organization(
                &adapter, &user_id, active_org_id.as_deref(), &options, body,
            ).await {
                Ok(org) => PluginHandlerResponse::ok(serde_json::to_value(org).unwrap_or_default()),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// POST /organization/delete
pub fn delete_organization_handler(options: OrganizationOptions) -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        let options = options.clone();
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let active_org_id = extract_active_org_id(&req);
            let body: DeleteOrganizationRequest = match serde_json::from_value(req.body.clone()) {
                Ok(b) => b,
                Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
            };
            match routes_org::handle_delete_organization(
                &adapter, &user_id, req.session_token.as_deref(),
                active_org_id.as_deref(), &options, body,
            ).await {
                Ok(org) => PluginHandlerResponse::ok(serde_json::to_value(org).unwrap_or_default()),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// GET /organization/list
pub fn list_organizations_handler() -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            match routes_org::handle_list_organizations(&adapter, &user_id).await {
                Ok(orgs) => PluginHandlerResponse::ok(serde_json::to_value(orgs).unwrap_or_default()),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// GET /organization/get-by-slug
pub fn get_by_slug_handler() -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let adapter = build_adapter(&ctx);
            let slug = match req.query.get("slug").and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None => return PluginHandlerResponse::error(400, "BAD_REQUEST", "Missing 'slug' query parameter"),
            };
            match routes_org::handle_get_by_slug(&adapter, &slug).await {
                Ok(org) => PluginHandlerResponse::ok(serde_json::to_value(org).unwrap_or_default()),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// POST /organization/check-slug
pub fn check_slug_handler() -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let adapter = build_adapter(&ctx);
            let body: CheckSlugRequest = match serde_json::from_value(req.body.clone()) {
                Ok(b) => b,
                Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
            };
            match routes_org::handle_check_slug(&adapter, body).await {
                Ok(result) => PluginHandlerResponse::ok(result),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// POST /organization/set-active
pub fn set_active_organization_handler() -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let active_org_id = extract_active_org_id(&req);
            let session_token = match &req.session_token {
                Some(t) => t.clone(),
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "No session token"),
            };
            let body: SetActiveOrganizationRequest = match serde_json::from_value(req.body.clone()) {
                Ok(b) => b,
                Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
            };
            match routes_org::handle_set_active_organization(
                &adapter, &user_id, &session_token, active_org_id.as_deref(), body,
            ).await {
                Ok(Some(org)) => PluginHandlerResponse::ok(serde_json::to_value(org).unwrap_or_default()),
                Ok(None) => PluginHandlerResponse::ok(serde_json::json!(null)),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// GET /organization/get-active
pub fn get_active_organization_handler(options: OrganizationOptions) -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        let options = options.clone();
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let active_org_id = extract_active_org_id(&req);
            match active_org_id {
                Some(org_id) => {
                    match routes_org::handle_get_full_organization(
                        &adapter, &user_id, req.session_token.as_deref(),
                        Some(&org_id), &options, Some(&org_id), None, None,
                    ).await {
                        Ok(Some(org)) => PluginHandlerResponse::ok(serde_json::to_value(org).unwrap_or_default()),
                        Ok(None) => PluginHandlerResponse::ok(serde_json::json!(null)),
                        Err(e) => org_error_to_response(e),
                    }
                }
                None => PluginHandlerResponse::ok(serde_json::json!(null)),
            }
        })
    })
}

// ─── Member management handlers ─────────────────────────────────

/// POST /organization/invite-member
pub fn invite_member_handler(options: OrganizationOptions) -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        let options = options.clone();
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let active_org_id = extract_active_org_id(&req);
            let body: InviteMemberRequest = match serde_json::from_value(req.body.clone()) {
                Ok(b) => b,
                Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
            };
            match routes_members::handle_invite_member(
                &adapter, &user_id, active_org_id.as_deref(), &options, body,
            ).await {
                Ok(invitation) => PluginHandlerResponse::ok(serde_json::to_value(invitation).unwrap_or_default()),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// POST /organization/accept-invitation
pub fn accept_invitation_handler() -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let body: AcceptInvitationRequest = match serde_json::from_value(req.body.clone()) {
                Ok(b) => b,
                Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
            };
            match routes_members::handle_accept_invitation(&adapter, &user_id, body).await {
                Ok(member) => PluginHandlerResponse::ok(serde_json::to_value(member).unwrap_or_default()),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// POST /organization/reject-invitation
pub fn reject_invitation_handler() -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let body: RejectInvitationRequest = match serde_json::from_value(req.body.clone()) {
                Ok(b) => b,
                Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
            };
            match routes_members::handle_reject_invitation(&adapter, &user_id, body).await {
                Ok(invitation) => PluginHandlerResponse::ok(serde_json::to_value(invitation).unwrap_or_default()),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// POST /organization/cancel-invitation
pub fn cancel_invitation_handler(options: OrganizationOptions) -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        let options = options.clone();
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let active_org_id = extract_active_org_id(&req);
            let body: CancelInvitationRequest = match serde_json::from_value(req.body.clone()) {
                Ok(b) => b,
                Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
            };
            match routes_members::handle_cancel_invitation(
                &adapter, &user_id, active_org_id.as_deref(), &options, body,
            ).await {
                Ok(invitation) => PluginHandlerResponse::ok(serde_json::to_value(invitation).unwrap_or_default()),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// GET /organization/get-invitation
pub fn get_invitation_handler() -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let adapter = build_adapter(&ctx);
            let invitation_id = match req.query.get("invitationId").and_then(|v| v.as_str()) {
                Some(id) => id.to_string(),
                None => return PluginHandlerResponse::error(400, "BAD_REQUEST", "Missing 'invitationId' query parameter"),
            };
            match routes_members::handle_get_invitation(&adapter, &invitation_id).await {
                Ok(invitation) => PluginHandlerResponse::ok(serde_json::to_value(invitation).unwrap_or_default()),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// POST /organization/remove-member
pub fn remove_member_handler(options: OrganizationOptions) -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        let options = options.clone();
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let active_org_id = extract_active_org_id(&req);
            let body: RemoveMemberRequest = match serde_json::from_value(req.body.clone()) {
                Ok(b) => b,
                Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
            };
            match routes_members::handle_remove_member(
                &adapter, &user_id, active_org_id.as_deref(), &options, body,
            ).await {
                Ok(member) => PluginHandlerResponse::ok(serde_json::to_value(member).unwrap_or_default()),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// POST /organization/update-member-role
pub fn update_member_role_handler(options: OrganizationOptions) -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        let options = options.clone();
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let active_org_id = extract_active_org_id(&req);
            let body: UpdateMemberRoleRequest = match serde_json::from_value(req.body.clone()) {
                Ok(b) => b,
                Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
            };
            match routes_members::handle_update_member_role(
                &adapter, &user_id, active_org_id.as_deref(), &options, body,
            ).await {
                Ok(member) => PluginHandlerResponse::ok(serde_json::to_value(member).unwrap_or_default()),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// POST /organization/leave
pub fn leave_organization_handler(options: OrganizationOptions) -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        let options = options.clone();
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let active_org_id = extract_active_org_id(&req);
            let body: LeaveOrganizationRequest = match serde_json::from_value(req.body.clone()) {
                Ok(b) => b,
                Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
            };
            match routes_members::handle_leave_organization(
                &adapter, &user_id, active_org_id.as_deref(), &options, body,
            ).await {
                Ok(_) => PluginHandlerResponse::ok(serde_json::json!({"success": true})),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// GET /organization/list-members
pub fn list_members_handler() -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let active_org_id = extract_active_org_id(&req);
            let org_id = req.query.get("organizationId").and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .or(active_org_id);
            let org_id = match org_id {
                Some(id) => id,
                None => return PluginHandlerResponse::error(400, "BAD_REQUEST", "Missing organizationId"),
            };
            match routes_members::handle_list_members(&adapter, &org_id, &user_id).await {
                Ok(members) => PluginHandlerResponse::ok(serde_json::to_value(members).unwrap_or_default()),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

// ─── Access control handlers ────────────────────────────────────

/// POST /organization/has-permission
pub fn has_permission_handler(options: OrganizationOptions) -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        let options = options.clone();
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let active_org_id = extract_active_org_id(&req);
            let body: HasPermissionRequest = match serde_json::from_value(req.body.clone()) {
                Ok(b) => b,
                Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
            };
            match routes_access::handle_has_permission(
                &adapter, &user_id, active_org_id.as_deref(), &options, body,
            ).await {
                Ok(result) => PluginHandlerResponse::ok(result),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

// ─── Team handlers ──────────────────────────────────────────────

/// POST /organization/create-team
pub fn create_team_handler(options: OrganizationOptions) -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        let options = options.clone();
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let active_org_id = extract_active_org_id(&req);
            let body: CreateTeamRequest = match serde_json::from_value(req.body.clone()) {
                Ok(b) => b,
                Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
            };
            match routes_teams::handle_create_team(
                &adapter, &user_id, active_org_id.as_deref(), &options, body,
            ).await {
                Ok(team) => PluginHandlerResponse::created(serde_json::to_value(team).unwrap_or_default()),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// POST /organization/update-team
pub fn update_team_handler(options: OrganizationOptions) -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        let options = options.clone();
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let active_org_id = extract_active_org_id(&req);
            let body: UpdateTeamRequest = match serde_json::from_value(req.body.clone()) {
                Ok(b) => b,
                Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
            };
            match routes_teams::handle_update_team(
                &adapter, &user_id, active_org_id.as_deref(), &options, body,
            ).await {
                Ok(team) => PluginHandlerResponse::ok(serde_json::to_value(team).unwrap_or_default()),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// POST /organization/delete-team
pub fn delete_team_handler(options: OrganizationOptions) -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        let options = options.clone();
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let active_org_id = extract_active_org_id(&req);
            let body: DeleteTeamRequest = match serde_json::from_value(req.body.clone()) {
                Ok(b) => b,
                Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
            };
            match routes_teams::handle_delete_team(
                &adapter, &user_id, active_org_id.as_deref(), &options, body,
            ).await {
                Ok(team) => PluginHandlerResponse::ok(serde_json::to_value(team).unwrap_or_default()),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// POST /organization/add-team-member
pub fn add_team_member_handler(options: OrganizationOptions) -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        let options = options.clone();
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let active_org_id = extract_active_org_id(&req);
            let body: AddTeamMemberRequest = match serde_json::from_value(req.body.clone()) {
                Ok(b) => b,
                Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
            };
            match routes_teams::handle_add_team_member(
                &adapter, &user_id, active_org_id.as_deref(), &options, body,
            ).await {
                Ok(member) => PluginHandlerResponse::ok(serde_json::to_value(member).unwrap_or_default()),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// POST /organization/remove-team-member
pub fn remove_team_member_handler(options: OrganizationOptions) -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        let options = options.clone();
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let active_org_id = extract_active_org_id(&req);
            let body: RemoveTeamMemberRequest = match serde_json::from_value(req.body.clone()) {
                Ok(b) => b,
                Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
            };
            match routes_teams::handle_remove_team_member(
                &adapter, &user_id, active_org_id.as_deref(), &options, body,
            ).await {
                Ok(_) => PluginHandlerResponse::ok(serde_json::json!({"success": true})),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// GET /organization/list-teams
pub fn list_teams_handler() -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let active_org_id = extract_active_org_id(&req);
            let org_id = req.query.get("organizationId").and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .or(active_org_id);
            let org_id = match org_id {
                Some(id) => id,
                None => return PluginHandlerResponse::error(400, "BAD_REQUEST", "Missing organizationId"),
            };
            match routes_teams::handle_list_teams(&adapter, &org_id, &user_id).await {
                Ok(teams) => PluginHandlerResponse::ok(serde_json::to_value(teams).unwrap_or_default()),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

// ─── Dynamic access control handlers ────────────────────────────

/// GET /organization/get-permissions
pub fn get_permissions_handler(options: OrganizationOptions) -> PluginHandlerFn {
    Arc::new(move |_ctx_any, _req| {
        let options = options.clone();
        Box::pin(async move {
            match routes_access::handle_get_permissions(&options) {
                Ok(result) => PluginHandlerResponse::ok(result),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// POST /organization/check-permission
pub fn check_permission_handler(options: OrganizationOptions) -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        let options = options.clone();
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let active_org_id = extract_active_org_id(&req);
            let body: HasPermissionRequest = match serde_json::from_value(req.body.clone()) {
                Ok(b) => b,
                Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
            };
            match routes_access::handle_check_permission(
                &adapter, &user_id, active_org_id.as_deref(), &options, body,
            ).await {
                Ok(result) => PluginHandlerResponse::ok(result),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// POST /organization/create-role
pub fn create_role_handler(options: OrganizationOptions) -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        let options = options.clone();
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let active_org_id = extract_active_org_id(&req);
            let body: CreateOrgRoleRequest = match serde_json::from_value(req.body.clone()) {
                Ok(b) => b,
                Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
            };
            match routes_access::handle_create_org_role(
                &adapter, &user_id, active_org_id.as_deref(), &options, body,
            ).await {
                Ok(result) => PluginHandlerResponse::created(result),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// POST /organization/delete-role
pub fn delete_role_handler(options: OrganizationOptions) -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        let options = options.clone();
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let active_org_id = extract_active_org_id(&req);
            let body: DeleteOrgRoleRequest = match serde_json::from_value(req.body.clone()) {
                Ok(b) => b,
                Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
            };
            match routes_access::handle_delete_org_role(
                &adapter, &user_id, active_org_id.as_deref(), &options, body,
            ).await {
                Ok(result) => PluginHandlerResponse::ok(result),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// POST /organization/update-role
pub fn update_role_handler(options: OrganizationOptions) -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        let options = options.clone();
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let active_org_id = extract_active_org_id(&req);
            let body: UpdateOrgRoleRequest = match serde_json::from_value(req.body.clone()) {
                Ok(b) => b,
                Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
            };
            match routes_access::handle_update_org_role(
                &adapter, &user_id, active_org_id.as_deref(), &options, body,
            ).await {
                Ok(result) => PluginHandlerResponse::ok(result),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// GET /organization/list-roles
pub fn list_roles_handler(options: OrganizationOptions) -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        let options = options.clone();
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let active_org_id = extract_active_org_id(&req);
            let org_id_query = req.query.get("organizationId").and_then(|v| v.as_str()).map(|s| s.to_string());
            match routes_access::handle_list_org_roles(
                &adapter, &user_id, active_org_id.as_deref(), &options, org_id_query.as_deref(),
            ).await {
                Ok(result) => PluginHandlerResponse::ok(result),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

/// GET /organization/get-role
pub fn get_role_handler(options: OrganizationOptions) -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        let options = options.clone();
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let adapter = build_adapter(&ctx);
            let active_org_id = extract_active_org_id(&req);
            let org_id_query = req.query.get("organizationId").and_then(|v| v.as_str()).map(|s| s.to_string());
            let role_name = req.query.get("roleName").and_then(|v| v.as_str()).map(|s| s.to_string());
            let role_id = req.query.get("roleId").and_then(|v| v.as_str()).map(|s| s.to_string());
            match routes_access::handle_get_org_role(
                &adapter, &user_id, active_org_id.as_deref(), &options,
                org_id_query.as_deref(), role_name.as_deref(), role_id.as_deref(),
            ).await {
                Ok(result) => PluginHandlerResponse::ok(result),
                Err(e) => org_error_to_response(e),
            }
        })
    })
}

// ── Missing endpoints from TS reference ────────────────────────────────

/// GET /organization/list-invitations — List all invitations for an organization
pub fn list_invitations_handler() -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let _user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let org_id = req.query.get("organizationId").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if org_id.is_empty() {
                return PluginHandlerResponse::error(400, "BAD_REQUEST", "organizationId is required");
            }
            let status = req.query.get("status").and_then(|v| v.as_str()).unwrap_or("pending").to_string();
            match ctx.adapter.find_many("invitation", serde_json::json!({
                "organizationId": org_id,
                "status": status,
            })).await {
                Ok(invitations) => PluginHandlerResponse::ok(serde_json::json!(invitations)),
                Err(_) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", "Failed to list invitations"),
            }
        })
    })
}

/// GET /organization/list-user-invitations — List all invitations for the current user
pub fn list_user_invitations_handler() -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let user_email = req.session.as_ref()
                .and_then(|s| s.get("user"))
                .and_then(|u| u.get("email"))
                .and_then(|e| e.as_str())
                .unwrap_or("")
                .to_string();
            if user_email.is_empty() {
                return PluginHandlerResponse::error(400, "BAD_REQUEST", "User email not found");
            }
            match ctx.adapter.find_many("invitation", serde_json::json!({
                "email": user_email,
                "status": "pending",
            })).await {
                Ok(invitations) => PluginHandlerResponse::ok(serde_json::json!(invitations)),
                Err(_) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", "Failed to list user invitations"),
            }
        })
    })
}

/// GET /organization/get-active-member — Get the active member for the current user in org
pub fn get_active_member_handler() -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let org_id = extract_active_org_id(&req)
                .or_else(|| req.query.get("organizationId").and_then(|v| v.as_str()).map(String::from));
            let org_id = match org_id {
                Some(id) => id,
                None => return PluginHandlerResponse::error(400, "BAD_REQUEST", "No active organization"),
            };
            match ctx.adapter.find_many("member", serde_json::json!({
                "organizationId": org_id,
                "userId": user_id,
            })).await {
                Ok(members) if !members.is_empty() => PluginHandlerResponse::ok(members[0].clone()),
                _ => PluginHandlerResponse::error(404, "NOT_FOUND", "Not a member of this organization"),
            }
        })
    })
}

/// GET /organization/get-active-member-role — Get the role of the active member
pub fn get_active_member_role_handler(options: OrganizationOptions) -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        let options = options.clone();
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let org_id = extract_active_org_id(&req)
                .or_else(|| req.query.get("organizationId").and_then(|v| v.as_str()).map(String::from));
            let org_id = match org_id {
                Some(id) => id,
                None => return PluginHandlerResponse::error(400, "BAD_REQUEST", "No active organization"),
            };
            match ctx.adapter.find_many("member", serde_json::json!({
                "organizationId": org_id.clone(),
                "userId": user_id,
            })).await {
                Ok(members) if !members.is_empty() => {
                    let role = members[0].get("role").and_then(|v| v.as_str()).unwrap_or("member");
                    PluginHandlerResponse::ok(serde_json::json!({
                        "role": role,
                        "organizationId": org_id,
                    }))
                }
                _ => PluginHandlerResponse::error(404, "NOT_FOUND", "Not a member of this organization"),
            }
        })
    })
}

/// POST /organization/remove-team — Remove (delete) a team (TS alias for delete-team)
pub fn remove_team_handler(options: OrganizationOptions) -> PluginHandlerFn {
    // Delegates to delete_team_handler — same logic
    delete_team_handler(options)
}

/// POST /organization/set-active-team — Set the active team for the current session
pub fn set_active_team_handler() -> PluginHandlerFn {
    Arc::new(move |_ctx_any, req| {
        Box::pin(async move {
            let _user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let team_id = req.body.get("teamId").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if team_id.is_empty() {
                return PluginHandlerResponse::error(400, "BAD_REQUEST", "teamId is required");
            }
            // Active team is stored as a cookie/session attribute
            PluginHandlerResponse {
                status: 200,
                body: serde_json::json!({"activeTeamId": team_id}),
                headers: vec![
                    ("Set-Cookie".into(), format!("active_team_id={}; Path=/; HttpOnly; SameSite=Lax", team_id)),
                ],
                redirect: None,
            }
        })
    })
}

/// GET /organization/list-user-teams — List teams the current user belongs to
pub fn list_user_teams_handler() -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let org_id = extract_active_org_id(&req)
                .or_else(|| req.query.get("organizationId").and_then(|v| v.as_str()).map(String::from));
            // Find all teamMember records for this user, then resolve team details
            let mut query = serde_json::json!({"userId": user_id});
            if let Some(ref oid) = org_id {
                query.as_object_mut().unwrap().insert("organizationId".to_string(), serde_json::json!(oid.clone()));
            }
            match ctx.adapter.find_many("teamMember", query).await {
                Ok(memberships) => {
                    // Collect team IDs and fetch team details
                    let team_ids: Vec<String> = memberships.iter()
                        .filter_map(|m| m.get("teamId").and_then(|v| v.as_str()).map(String::from))
                        .collect();
                    let mut teams = Vec::new();
                    for tid in &team_ids {
                        if let Ok(Some(team)) = ctx.adapter.find_by_id("team", tid).await {
                            teams.push(team);
                        }
                    }
                    PluginHandlerResponse::ok(serde_json::json!(teams))
                }
                Err(_) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", "Failed to list user teams"),
            }
        })
    })
}

/// GET /organization/list-team-members — List members of a specific team
pub fn list_team_members_handler() -> PluginHandlerFn {
    Arc::new(move |ctx_any, req| {
        Box::pin(async move {
            let ctx = extract_ctx(&ctx_any);
            let _user_id = match extract_user_id(&req) {
                Some(id) => id,
                None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
            };
            let team_id = req.query.get("teamId").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if team_id.is_empty() {
                return PluginHandlerResponse::error(400, "BAD_REQUEST", "teamId is required");
            }
            match ctx.adapter.find_many("teamMember", serde_json::json!({
                "teamId": team_id,
            })).await {
                Ok(members) => {
                    // Enrich with user data
                    let mut enriched = Vec::new();
                    for member in &members {
                        let mut m = member.clone();
                        if let Some(uid) = member.get("userId").and_then(|v| v.as_str()) {
                            if let Ok(Some(user)) = ctx.adapter.find_by_id("user", uid).await {
                                m.as_object_mut().map(|obj| obj.insert("user".to_string(), user));
                            }
                        }
                        enriched.push(m);
                    }
                    PluginHandlerResponse::ok(serde_json::json!(enriched))
                }
                Err(_) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", "Failed to list team members"),
            }
        })
    })
}
