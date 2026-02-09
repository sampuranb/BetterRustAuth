// Organization member route handlers.
//
// Maps to: packages/better-auth/src/plugins/organization/routes/crud-members.ts (1,054 lines)
//
// Handlers for member management: add, update role, remove, leave, list.

use super::adapter::OrgAdapter;
use super::helpers::*;
use super::routes_org::OrgRouteError;
use super::types::*;

// ── Invite Member ───────────────────────────────────────────────

/// Handle POST /organization/invite-member
///
/// Creates an invitation for a user to join the organization.
/// Checks permissions, validates the role, handles domain restrictions,
/// prevents duplicate invitations, and optionally sends an invitation email.
pub async fn handle_invite_member(
    adapter: &OrgAdapter,
    user_id: &str,
    options: &OrganizationOptions,
    body: InviteMemberRequest,
) -> Result<OrganizationInvitation, OrgRouteError> {
    let organization_id = &body.organization_id;

    // Validate email
    let email = body.email.trim().to_lowercase();
    if !email.contains('@') || email.split('@').count() != 2 {
        return Err(OrgRouteError::BadRequest("INVALID_EMAIL".to_string()));
    }

    // Check membership
    let member = adapter
        .find_member_by_org_id(user_id, organization_id)
        .await?
        .ok_or_else(|| {
            OrgRouteError::BadRequest(
                "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION".to_string(),
            )
        })?;

    // Check permission to invite
    let roles = resolve_roles(options);
    if !has_org_permission(&member.role, "invitation", "create", &roles) {
        return Err(OrgRouteError::Forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION".to_string(),
        ));
    }

    // Validate the requested role(s)
    let role_str = body.role.trim().to_string();
    let role_parts: Vec<&str> = role_str.split(',').map(|r| r.trim()).filter(|r| !r.is_empty()).collect();

    for role_name in &role_parts {
        if !roles.contains_key(*role_name) {
            // Check dynamic roles if enabled
            if options.enable_dynamic_access_control {
                let dynamic_role = adapter
                    .find_org_role_by_name(organization_id, role_name)
                    .await?;
                if dynamic_role.is_none() {
                    return Err(OrgRouteError::BadRequest(format!(
                        "ROLE_NOT_FOUND: {}", role_name
                    )));
                }
            } else {
                return Err(OrgRouteError::BadRequest(format!(
                    "ROLE_NOT_FOUND: {}", role_name
                )));
            }
        }
    }

    // Cannot invite someone as creator_role unless you are the creator_role yourself
    if member.role != options.creator_role
        && role_parts.contains(&options.creator_role.as_str())
    {
        return Err(OrgRouteError::Forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE".to_string(),
        ));
    }

    // Check domain restrictions
    if let Some(allowed_domains) = &options.allowed_domains {
        let email_domain = email.split('@').last().unwrap_or_default();
        if !allowed_domains.iter().any(|d| d == email_domain) {
            return Err(OrgRouteError::Forbidden(
                "EMAIL_DOMAIN_NOT_ALLOWED".to_string(),
            ));
        }
    }

    // Check for existing pending invitation
    let existing_pending = adapter
        .find_pending_invitation(&email, organization_id)
        .await?;

    if let Some(ref existing) = existing_pending {
        if body.resend.unwrap_or(false) {
            // Resend: update the existing invitation's expiry instead of creating a new one
            let new_expires_at = calculate_invitation_expiry(options.invitation_expiry);
            let _ = adapter
                .update_invitation_expiry(&existing.id, &new_expires_at)
                .await;
            // Return the updated invitation
            if let Some(updated) = adapter.find_invitation_by_id(&existing.id).await? {
                return Ok(updated);
            }
        } else if options.cancel_pending_invitations_on_re_invite {
            let _ = adapter
                .update_invitation_status(&existing.id, "canceled")
                .await;
        } else {
            return Err(OrgRouteError::BadRequest(
                "USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION".to_string(),
            ));
        }
    }

    // Check invitation limit
    let pending_invitations = adapter.list_invitations(organization_id).await?;
    let pending_count = pending_invitations
        .iter()
        .filter(|inv| inv.status == InvitationStatus::Pending)
        .count();
    if pending_count >= options.invitation_limit {
        return Err(OrgRouteError::Forbidden(
            "INVITATION_LIMIT_REACHED".to_string(),
        ));
    }

    // Verify the organization exists
    let _org = adapter
        .find_organization_by_id(organization_id)
        .await?
        .ok_or_else(|| {
            OrgRouteError::BadRequest("ORGANIZATION_NOT_FOUND".to_string())
        })?;

    // Check team capacity if teamId specified and max_members_per_team is configured
    if let Some(ref team_id) = body.team_id {
        if let Some(max_per_team) = options.max_members_per_team {
            let team_members = adapter.list_team_members(team_id).await?;
            if team_members.len() >= max_per_team {
                return Err(OrgRouteError::Forbidden(
                    "TEAM_MEMBER_LIMIT_REACHED".to_string(),
                ));
            }
        }
    }

    // Create the invitation
    let expires_at = calculate_invitation_expiry(options.invitation_expiry);
    let inv_data = CreateInvitationData {
        organization_id: organization_id.clone(),
        email: email.clone(),
        role: role_str,
        inviter_id: user_id.to_string(),
        team_id: body.team_id.clone(),
        expires_at,
    };

    let invitation = adapter.create_invitation(&inv_data).await?;

    Ok(invitation)
}


// ── Accept Invitation ───────────────────────────────────────────

/// Handle POST /organization/accept-invitation
///
/// Accepts a pending invitation, creating a member record for the user.
pub async fn handle_accept_invitation(
    adapter: &OrgAdapter,
    user_id: &str,
    session_token: Option<&str>,
    _options: &OrganizationOptions,
    body: InvitationActionRequest,
) -> Result<OrganizationMember, OrgRouteError> {
    let invitation = adapter
        .find_invitation_by_id(&body.invitation_id)
        .await?
        .ok_or_else(|| OrgRouteError::NotFound("INVITATION_NOT_FOUND".to_string()))?;

    // Validate invitation status
    if invitation.status != InvitationStatus::Pending {
        let msg = match invitation.status {
            InvitationStatus::Accepted => "INVITATION_ALREADY_ACCEPTED",
            InvitationStatus::Rejected => "INVITATION_ALREADY_REJECTED",
            InvitationStatus::Canceled => "INVITATION_ALREADY_CANCELED",
            _ => "INVITATION_INVALID",
        };
        return Err(OrgRouteError::BadRequest(msg.to_string()));
    }

    // Check expiry
    if is_invitation_expired(&invitation.expires_at) {
        return Err(OrgRouteError::BadRequest(
            "INVITATION_EXPIRED".to_string(),
        ));
    }

    // Check if already a member
    if adapter
        .check_membership(user_id, &invitation.organization_id)
        .await?
    {
        return Err(OrgRouteError::BadRequest(
            "USER_IS_ALREADY_A_MEMBER".to_string(),
        ));
    }

    // Update invitation status
    adapter
        .update_invitation_status(&invitation.id, "accepted")
        .await?;

    // Create member
    let member_data = CreateMemberData {
        organization_id: invitation.organization_id.clone(),
        user_id: user_id.to_string(),
        role: invitation.role.clone(),
        team_id: invitation.team_id.clone(),
    };
    let member = adapter.create_member(&member_data).await?;

    // Set as active organization
    if let Some(token) = session_token {
        let _ = adapter
            .set_active_organization(token, Some(&invitation.organization_id))
            .await;
    }

    Ok(member)
}

// ── Reject Invitation ───────────────────────────────────────────

/// Handle POST /organization/reject-invitation
///
/// Rejects a pending invitation.
pub async fn handle_reject_invitation(
    adapter: &OrgAdapter,
    body: InvitationActionRequest,
) -> Result<OrganizationInvitation, OrgRouteError> {
    let invitation = adapter
        .find_invitation_by_id(&body.invitation_id)
        .await?
        .ok_or_else(|| OrgRouteError::NotFound("INVITATION_NOT_FOUND".to_string()))?;

    if invitation.status != InvitationStatus::Pending {
        return Err(OrgRouteError::BadRequest(
            "INVITATION_NOT_PENDING".to_string(),
        ));
    }

    let updated = adapter
        .update_invitation_status(&invitation.id, "rejected")
        .await?;

    Ok(updated)
}

// ── Cancel Invitation ───────────────────────────────────────────

/// Handle POST /organization/cancel-invitation
///
/// Cancels a pending invitation. Requires appropriate permissions.
pub async fn handle_cancel_invitation(
    adapter: &OrgAdapter,
    user_id: &str,
    options: &OrganizationOptions,
    body: InvitationActionRequest,
) -> Result<OrganizationInvitation, OrgRouteError> {
    let invitation = adapter
        .find_invitation_by_id(&body.invitation_id)
        .await?
        .ok_or_else(|| OrgRouteError::NotFound("INVITATION_NOT_FOUND".to_string()))?;

    if invitation.status != InvitationStatus::Pending {
        return Err(OrgRouteError::BadRequest(
            "INVITATION_NOT_PENDING".to_string(),
        ));
    }

    // Check permission — only inviter or someone with invite permission can cancel
    let member = adapter
        .find_member_by_org_id(user_id, &invitation.organization_id)
        .await?
        .ok_or_else(|| {
            OrgRouteError::BadRequest(
                "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION".to_string(),
            )
        })?;

    let roles = resolve_roles(options);
    if invitation.inviter_id != user_id
        && !has_org_permission(&member.role, "member", "create", &roles)
    {
        return Err(OrgRouteError::Forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_CANCEL_INVITATION".to_string(),
        ));
    }

    let updated = adapter
        .update_invitation_status(&invitation.id, "canceled")
        .await?;

    Ok(updated)
}

// ── Get Invitation ──────────────────────────────────────────────

/// Handle GET /organization/get-invitation
///
/// Gets an invitation by ID (does not require auth).
pub async fn handle_get_invitation(
    adapter: &OrgAdapter,
    invitation_id: &str,
) -> Result<OrganizationInvitation, OrgRouteError> {
    adapter
        .find_invitation_by_id(invitation_id)
        .await?
        .ok_or_else(|| OrgRouteError::NotFound("INVITATION_NOT_FOUND".to_string()))
}

// ── Remove Member ───────────────────────────────────────────────

/// Handle POST /organization/remove-member
///
/// Removes a member from an organization. Cannot remove the only owner.
pub async fn handle_remove_member(
    adapter: &OrgAdapter,
    user_id: &str,
    options: &OrganizationOptions,
    body: RemoveMemberRequest,
) -> Result<serde_json::Value, OrgRouteError> {
    let organization_id = &body.organization_id;

    // Check permission
    let current_member = adapter
        .find_member_by_org_id(user_id, organization_id)
        .await?
        .ok_or_else(|| {
            OrgRouteError::BadRequest(
                "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION".to_string(),
            )
        })?;

    let roles = resolve_roles(options);
    if !has_org_permission(&current_member.role, "member", "delete", &roles) {
        return Err(OrgRouteError::Forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_REMOVE_MEMBERS".to_string(),
        ));
    }

    // Find the target member
    let target_member = adapter
        .find_member_by_id(&body.member_id)
        .await?
        .ok_or_else(|| OrgRouteError::NotFound("MEMBER_NOT_FOUND".to_string()))?;

    // Cannot remove the only owner
    let all_members = adapter.list_members(organization_id).await?;
    if is_only_owner(&all_members, &target_member.user_id) {
        return Err(OrgRouteError::BadRequest(
            "YOU_CANNOT_REMOVE_THE_ONLY_OWNER".to_string(),
        ));
    }

    // Cannot remove yourself via this endpoint (use /leave instead)
    if target_member.user_id == user_id {
        return Err(OrgRouteError::BadRequest(
            "CANNOT_REMOVE_YOURSELF_USE_LEAVE".to_string(),
        ));
    }

    adapter.remove_member(&target_member.id).await?;

    Ok(serde_json::json!({
        "success": true,
        "memberId": target_member.id,
    }))
}

// ── Update Member Role ──────────────────────────────────────────

/// Handle POST /organization/update-member-role
///
/// Updates a member's role. Cannot demote the only owner.
pub async fn handle_update_member_role(
    adapter: &OrgAdapter,
    user_id: &str,
    active_org_id: Option<&str>,
    options: &OrganizationOptions,
    body: UpdateMemberRoleRequest,
) -> Result<OrganizationMember, OrgRouteError> {
    let organization_id = body
        .organization_id
        .as_deref()
        .or(active_org_id)
        .ok_or_else(|| OrgRouteError::BadRequest("ORGANIZATION_NOT_FOUND".to_string()))?;

    // Check permission
    let current_member = adapter
        .find_member_by_org_id(user_id, organization_id)
        .await?
        .ok_or_else(|| {
            OrgRouteError::BadRequest(
                "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION".to_string(),
            )
        })?;

    let roles = resolve_roles(options);
    if !has_org_permission(&current_member.role, "member", "update", &roles) {
        return Err(OrgRouteError::Forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_UPDATE_MEMBER_ROLE".to_string(),
        ));
    }

    // Validate the role
    if !roles.contains_key(&body.role) {
        return Err(OrgRouteError::BadRequest(format!(
            "Invalid role: {}",
            body.role
        )));
    }

    // Find the target member
    let target_member = adapter
        .find_member_by_id(&body.member_id)
        .await?
        .ok_or_else(|| OrgRouteError::NotFound("MEMBER_NOT_FOUND".to_string()))?;

    // Cannot demote the only owner
    if target_member.role == "owner" && body.role != "owner" {
        let all_members = adapter.list_members(organization_id).await?;
        if is_only_owner(&all_members, &target_member.user_id) {
            return Err(OrgRouteError::BadRequest(
                "CANNOT_DEMOTE_THE_ONLY_OWNER".to_string(),
            ));
        }
    }

    let updated = adapter
        .update_member_role(&target_member.id, &body.role)
        .await?;

    Ok(updated)
}

// ── Leave Organization ──────────────────────────────────────────

/// Handle POST /organization/leave
///
/// Allows a member to leave an organization. The only owner cannot leave.
pub async fn handle_leave_organization(
    adapter: &OrgAdapter,
    user_id: &str,
    session_token: Option<&str>,
    active_org_id: Option<&str>,
    body: LeaveOrganizationRequest,
) -> Result<serde_json::Value, OrgRouteError> {
    let organization_id = &body.organization_id;

    let member = adapter
        .find_member_by_org_id(user_id, organization_id)
        .await?
        .ok_or_else(|| {
            OrgRouteError::BadRequest("YOU_ARE_NOT_A_MEMBER".to_string())
        })?;

    // Cannot leave if only owner
    let all_members = adapter.list_members(organization_id).await?;
    if is_only_owner(&all_members, user_id) {
        return Err(OrgRouteError::BadRequest(
            "YOU_CANNOT_LEAVE_AS_ONLY_OWNER".to_string(),
        ));
    }

    // Remove the member
    adapter.remove_member(&member.id).await?;

    // Clear active org if it was this one
    if active_org_id == Some(organization_id.as_str()) {
        if let Some(token) = session_token {
            let _ = adapter.set_active_organization(token, None).await;
        }
    }

    Ok(serde_json::json!({
        "success": true,
    }))
}

// ── List Members ────────────────────────────────────────────────

/// Handle GET /organization/list-members
///
/// Lists all members of an organization.
pub async fn handle_list_members(
    adapter: &OrgAdapter,
    user_id: &str,
    organization_id: &str,
) -> Result<Vec<OrganizationMember>, OrgRouteError> {
    // Verify the requester is a member
    if !adapter.check_membership(user_id, organization_id).await? {
        return Err(OrgRouteError::Forbidden(
            "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION".to_string(),
        ));
    }

    let members = adapter.list_members(organization_id).await?;
    Ok(members)
}

// ── List Invitations ────────────────────────────────────────────

/// Handle GET /organization/list-invitations
///
/// Lists all invitations for an organization. Requires the requester
/// to be a member of the organization.
///
/// Maps to: TS `listInvitations` in crud-invites.ts
pub async fn handle_list_invitations(
    adapter: &OrgAdapter,
    user_id: &str,
    session_active_org_id: Option<&str>,
    organization_id: Option<&str>,
) -> Result<Vec<OrganizationInvitation>, OrgRouteError> {
    let org_id = organization_id
        .or(session_active_org_id)
        .ok_or_else(|| {
            OrgRouteError::BadRequest("ORGANIZATION_NOT_FOUND".to_string())
        })?;

    // Verify the requester is a member
    if !adapter.check_membership(user_id, org_id).await? {
        return Err(OrgRouteError::Forbidden(
            "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION".to_string(),
        ));
    }

    let invitations = adapter.list_invitations(org_id).await?;
    Ok(invitations)
}

// ── List User Invitations ───────────────────────────────────────

/// Handle GET /organization/list-user-invitations
///
/// Lists all pending invitations for a specific user (by email).
/// Returns only invitations with "pending" status.
///
/// Maps to: TS `listUserInvitations` in crud-invites.ts
pub async fn handle_list_user_invitations(
    adapter: &OrgAdapter,
    user_email: &str,
    email_override: Option<&str>,
    is_server_side: bool,
) -> Result<Vec<OrganizationInvitation>, OrgRouteError> {
    // Email override (via query param) is only allowed for server-side calls
    let target_email = if is_server_side {
        email_override.unwrap_or(user_email)
    } else {
        if email_override.is_some() {
            return Err(OrgRouteError::BadRequest(
                "User email cannot be passed for client side API calls.".to_string(),
            ));
        }
        user_email
    };

    if target_email.is_empty() {
        return Err(OrgRouteError::BadRequest(
            "Missing session headers, or email query parameter.".to_string(),
        ));
    }

    let all_invitations = adapter.find_invitations_by_email(target_email).await?;
    let pending = all_invitations
        .into_iter()
        .filter(|inv| inv.status == InvitationStatus::Pending)
        .collect();
    Ok(pending)
}
