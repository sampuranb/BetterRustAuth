// Organization team route handlers.
//
// Maps to: packages/better-auth/src/plugins/organization/routes/crud-team.ts (1,255 lines)
//
// Handlers for team management: create, update, delete, list, add/remove members.

use super::adapter::OrgAdapter;
use super::helpers::*;
use super::routes_org::OrgRouteError;
use super::types::*;

// ── Create Team ─────────────────────────────────────────────────

/// Handle POST /organization/create-team
///
/// Creates a new team within an organization.
pub async fn handle_create_team(
    adapter: &OrgAdapter,
    user_id: &str,
    _active_org_id: Option<&str>,
    options: &OrganizationOptions,
    body: CreateTeamRequest,
) -> Result<Team, OrgRouteError> {
    let organization_id = body
        .organization_id
        .as_str();

    // Check membership and permission
    let member = adapter
        .find_member_by_org_id(user_id, organization_id)
        .await?
        .ok_or_else(|| {
            OrgRouteError::BadRequest(
                "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION".to_string(),
            )
        })?;

    let roles = resolve_roles(options);
    if !has_org_permission(&member.role, "team", "create", &roles) {
        return Err(OrgRouteError::Forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS".to_string(),
        ));
    }

    // Verify the organization exists
    let _org = adapter
        .find_organization_by_id(organization_id)
        .await?
        .ok_or_else(|| OrgRouteError::NotFound("ORGANIZATION_NOT_FOUND".to_string()))?;

    // Create the team
    let team_data = CreateTeamData {
        name: body.name.clone(),
        organization_id: organization_id.to_string(),
    };
    let team = adapter.create_team(&team_data).await?;

    Ok(team)
}

// ── Update Team ─────────────────────────────────────────────────

/// Handle POST /organization/update-team
///
/// Updates a team's name.
pub async fn handle_update_team(
    adapter: &OrgAdapter,
    user_id: &str,
    _active_org_id: Option<&str>,
    options: &OrganizationOptions,
    body: UpdateTeamRequest,
) -> Result<Team, OrgRouteError> {
    // Find the team
    let team = adapter
        .find_team_by_id(&body.team_id)
        .await?
        .ok_or_else(|| OrgRouteError::NotFound("TEAM_NOT_FOUND".to_string()))?;

    let organization_id = body
        .organization_id
        .as_deref()
        .unwrap_or(&team.organization_id);

    // Check membership and permission
    let member = adapter
        .find_member_by_org_id(user_id, organization_id)
        .await?
        .ok_or_else(|| {
            OrgRouteError::BadRequest(
                "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION".to_string(),
            )
        })?;

    let roles = resolve_roles(options);
    if !has_org_permission(&member.role, "team", "update", &roles) {
        return Err(OrgRouteError::Forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_UPDATE_TEAMS".to_string(),
        ));
    }

    let updated = adapter.update_team(&body.team_id, &body.name).await?;

    Ok(updated)
}

// ── Delete Team ─────────────────────────────────────────────────

/// Handle POST /organization/delete-team
///
/// Deletes a team and removes team assignments from members.
pub async fn handle_delete_team(
    adapter: &OrgAdapter,
    user_id: &str,
    _active_org_id: Option<&str>,
    options: &OrganizationOptions,
    body: DeleteTeamRequest,
) -> Result<serde_json::Value, OrgRouteError> {
    let team = adapter
        .find_team_by_id(&body.team_id)
        .await?
        .ok_or_else(|| OrgRouteError::NotFound("TEAM_NOT_FOUND".to_string()))?;

    let organization_id = body
        .organization_id
        .as_deref()
        .unwrap_or(&team.organization_id);

    // Check membership and permission
    let member = adapter
        .find_member_by_org_id(user_id, organization_id)
        .await?
        .ok_or_else(|| {
            OrgRouteError::BadRequest(
                "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION".to_string(),
            )
        })?;

    let roles = resolve_roles(options);
    if !has_org_permission(&member.role, "team", "delete", &roles) {
        return Err(OrgRouteError::Forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS".to_string(),
        ));
    }

    adapter.delete_team(&body.team_id).await?;

    Ok(serde_json::json!({
        "success": true,
        "teamId": body.team_id,
    }))
}

// ── List Teams ──────────────────────────────────────────────────

/// Handle GET /organization/list-teams
///
/// Lists all teams in an organization.
pub async fn handle_list_teams(
    adapter: &OrgAdapter,
    user_id: &str,
    organization_id: &str,
) -> Result<Vec<Team>, OrgRouteError> {
    // Verify membership
    if !adapter.check_membership(user_id, organization_id).await? {
        return Err(OrgRouteError::Forbidden(
            "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION".to_string(),
        ));
    }

    let teams = adapter.list_teams(organization_id).await?;
    Ok(teams)
}

// ── Add Team Member ─────────────────────────────────────────────

/// Handle POST /organization/add-team-member
///
/// Adds an existing organization member to a team.
pub async fn handle_add_team_member(
    adapter: &OrgAdapter,
    user_id: &str,
    _active_org_id: Option<&str>,
    options: &OrganizationOptions,
    body: AddTeamMemberRequest,
) -> Result<OrganizationMember, OrgRouteError> {
    let team = adapter
        .find_team_by_id(&body.team_id)
        .await?
        .ok_or_else(|| OrgRouteError::NotFound("TEAM_NOT_FOUND".to_string()))?;

    let organization_id = body
        .organization_id
        .as_deref()
        .unwrap_or(&team.organization_id);

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
    if !has_org_permission(&current_member.role, "team", "update", &roles) {
        return Err(OrgRouteError::Forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_MANAGE_TEAM_MEMBERS".to_string(),
        ));
    }

    // Verify target member exists and is in the org
    let target_member = adapter
        .find_member_by_id(&body.member_id)
        .await?
        .ok_or_else(|| OrgRouteError::NotFound("MEMBER_NOT_FOUND".to_string()))?;

    if target_member.organization_id != organization_id {
        return Err(OrgRouteError::BadRequest(
            "MEMBER_NOT_IN_ORGANIZATION".to_string(),
        ));
    }

    let updated = adapter
        .add_team_member(&body.member_id, &body.team_id)
        .await?;

    Ok(updated)
}

// ── Remove Team Member ──────────────────────────────────────────

/// Handle POST /organization/remove-team-member
///
/// Removes a member from a team (clears their team assignment).
pub async fn handle_remove_team_member(
    adapter: &OrgAdapter,
    user_id: &str,
    _active_org_id: Option<&str>,
    options: &OrganizationOptions,
    body: RemoveTeamMemberRequest,
) -> Result<OrganizationMember, OrgRouteError> {
    let team = adapter
        .find_team_by_id(&body.team_id)
        .await?
        .ok_or_else(|| OrgRouteError::NotFound("TEAM_NOT_FOUND".to_string()))?;

    let organization_id = body
        .organization_id
        .as_deref()
        .unwrap_or(&team.organization_id);

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
    if !has_org_permission(&current_member.role, "team", "update", &roles) {
        return Err(OrgRouteError::Forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_MANAGE_TEAM_MEMBERS".to_string(),
        ));
    }

    let updated = adapter.remove_team_member(&body.member_id).await?;

    Ok(updated)
}
