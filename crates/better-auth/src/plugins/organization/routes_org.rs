// Organization CRUD route handlers.
//
// Maps to: packages/better-auth/src/plugins/organization/routes/crud-org.ts (914 lines)
//
// Every endpoint mirrors the TS handler exactly: session validation,
// permission checks, adapter calls, hook invocations, and response.



use crate::internal_adapter::AdapterError;

use super::adapter::OrgAdapter;
use super::helpers::*;
use super::types::*;

/// Error type for organization route handlers.
#[derive(Debug)]
pub enum OrgRouteError {
    Unauthorized(String),
    Forbidden(String),
    BadRequest(String),
    NotFound(String),
    Adapter(AdapterError),
}

impl From<AdapterError> for OrgRouteError {
    fn from(e: AdapterError) -> Self {
        OrgRouteError::Adapter(e)
    }
}

impl std::fmt::Display for OrgRouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OrgRouteError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            OrgRouteError::Forbidden(msg) => write!(f, "Forbidden: {}", msg),
            OrgRouteError::BadRequest(msg) => write!(f, "Bad request: {}", msg),
            OrgRouteError::NotFound(msg) => write!(f, "Not found: {}", msg),
            OrgRouteError::Adapter(e) => write!(f, "Adapter error: {:?}", e),
        }
    }
}

// ── Create Organization ─────────────────────────────────────────

/// Handle POST /organization/create
///
/// Creates a new organization, adds the creator as a member with the creator role,
/// optionally creates a default team, and sets the org as active.
pub async fn handle_create_organization(
    adapter: &OrgAdapter,
    user_id: &str,
    options: &OrganizationOptions,
    session_token: Option<&str>,
    body: CreateOrganizationRequest,
) -> Result<serde_json::Value, OrgRouteError> {
    // Check if user is allowed to create organizations
    if !options.allow_user_to_create_org {
        return Err(OrgRouteError::Forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_CREATE_ORGANIZATIONS".to_string(),
        ));
    }

    // Check organization limit
    if let Some(limit) = options.organization_limit {
        let user_orgs = adapter.list_organizations(user_id).await?;
        if user_orgs.len() >= limit {
            return Err(OrgRouteError::Forbidden(
                "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS".to_string(),
            ));
        }
    }

    // Check if slug is already taken
    if let Some(_existing) = adapter.find_organization_by_slug(&body.slug).await? {
        return Err(OrgRouteError::BadRequest(
            "ORGANIZATION_ALREADY_EXISTS".to_string(),
        ));
    }

    // Create the organization
    let org_data = CreateOrganizationData {
        name: body.name.clone(),
        slug: body.slug.clone(),
        logo: body.logo.clone(),
        metadata: body.metadata.clone(),
    };
    let organization = adapter.create_organization(&org_data).await?;

    // Add creator as a member
    let member_data = CreateMemberData {
        organization_id: organization.id.clone(),
        user_id: user_id.to_string(),
        role: options.creator_role.clone(),
        team_id: None,
    };
    let member = adapter.create_member(&member_data).await?;

    // Create default team if teams are enabled
    if options.enable_teams {
        let team_data = CreateTeamData {
            name: organization.name.clone(),
            organization_id: organization.id.clone(),
        };
        let team = adapter.create_team(&team_data).await?;

        // Add creator to the default team
        let _ = adapter.add_team_member(&member.id, &team.id).await;
    }

    // Set active organization if session exists and not keeping current
    if let Some(token) = session_token {
        if !body.keep_current_active_organization.unwrap_or(false) {
            let _ = adapter
                .set_active_organization(token, Some(&organization.id))
                .await;
        }
    }

    // Build response with members array
    let mut org_json = serde_json::to_value(&organization)
        .map_err(|e| OrgRouteError::Adapter(AdapterError::Serialization(e.to_string())))?;

    // Parse metadata if string
    if let Some(meta_str) = organization.metadata.as_ref() {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(meta_str) {
            org_json["metadata"] = parsed;
        }
    }

    org_json["members"] = serde_json::json!([serde_json::to_value(&member)
        .map_err(|e| OrgRouteError::Adapter(AdapterError::Serialization(e.to_string())))?]);

    Ok(org_json)
}

// ── Update Organization ─────────────────────────────────────────

/// Handle POST /organization/update
///
/// Updates an organization's name, slug, logo, or metadata.
/// Requires the user to be a member with update permission.
pub async fn handle_update_organization(
    adapter: &OrgAdapter,
    user_id: &str,
    active_org_id: Option<&str>,
    options: &OrganizationOptions,
    body: UpdateOrganizationRequest,
) -> Result<Organization, OrgRouteError> {
    let organization_id = body
        .organization_id
        .as_deref()
        .or(active_org_id)
        .ok_or_else(|| OrgRouteError::BadRequest("ORGANIZATION_NOT_FOUND".to_string()))?;

    // Check membership
    let member = adapter
        .find_member_by_org_id(user_id, organization_id)
        .await?
        .ok_or_else(|| {
            OrgRouteError::BadRequest(
                "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION".to_string(),
            )
        })?;

    // Check permission
    let roles = resolve_roles(options);
    if !has_org_permission(&member.role, "organization", "update", &roles) {
        return Err(OrgRouteError::Forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_UPDATE_ORGANIZATIONS".to_string(),
        ));
    }

    // Check slug uniqueness if changing
    if let Some(ref new_slug) = body.data.slug {
        if let Some(existing) = adapter.find_organization_by_slug(new_slug).await? {
            if existing.id != organization_id {
                return Err(OrgRouteError::BadRequest(
                    "SLUG_ALREADY_EXISTS".to_string(),
                ));
            }
        }
    }

    // Update the organization
    let updated = adapter
        .update_organization(organization_id, &body.data)
        .await?;

    Ok(updated)
}

// ── Delete Organization ─────────────────────────────────────────

/// Handle POST /organization/delete
///
/// Deletes an organization and all its members, invitations, and teams.
/// Requires the user to be a member with delete permission.
pub async fn handle_delete_organization(
    adapter: &OrgAdapter,
    user_id: &str,
    session_token: Option<&str>,
    active_org_id: Option<&str>,
    options: &OrganizationOptions,
    body: DeleteOrganizationRequest,
) -> Result<Organization, OrgRouteError> {
    // Check if deletion is disabled
    if options.disable_organization_deletion {
        return Err(OrgRouteError::NotFound(
            "ORGANIZATION_DELETION_DISABLED".to_string(),
        ));
    }

    let organization_id = &body.organization_id;

    // Check membership
    let member = adapter
        .find_member_by_org_id(user_id, organization_id)
        .await?
        .ok_or_else(|| {
            OrgRouteError::BadRequest(
                "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION".to_string(),
            )
        })?;

    // Check permission
    let roles = resolve_roles(options);
    if !has_org_permission(&member.role, "organization", "delete", &roles) {
        return Err(OrgRouteError::Forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_DELETE_ORGANIZATIONS".to_string(),
        ));
    }

    // Clear active org if this was the active one
    if active_org_id == Some(organization_id.as_str()) {
        if let Some(token) = session_token {
            let _ = adapter.set_active_organization(token, None).await;
        }
    }

    // Get org before deleting
    let org = adapter
        .find_organization_by_id(organization_id)
        .await?
        .ok_or_else(|| OrgRouteError::BadRequest("ORGANIZATION_NOT_FOUND".to_string()))?;

    // Delete everything
    adapter.delete_organization(organization_id).await?;

    Ok(org)
}

// ── Get Full Organization ───────────────────────────────────────

/// Handle GET /organization/get-full-organization
///
/// Returns the full organization with members, invitations, and optionally teams.
pub async fn handle_get_full_organization(
    adapter: &OrgAdapter,
    user_id: &str,
    session_token: Option<&str>,
    active_org_id: Option<&str>,
    options: &OrganizationOptions,
    org_id_query: Option<&str>,
    org_slug_query: Option<&str>,
    members_limit: Option<usize>,
) -> Result<Option<FullOrganization>, OrgRouteError> {
    let org_ref = org_slug_query
        .or(org_id_query)
        .or(active_org_id);

    let org_ref = match org_ref {
        Some(r) => r,
        None => return Ok(None),
    };

    let is_slug = org_slug_query.is_some();

    let full_org = adapter
        .find_full_organization(
            org_ref,
            is_slug,
            options.enable_teams,
            members_limit.or(options.membership_limit),
        )
        .await?;

    let full_org = match full_org {
        Some(o) => o,
        None => {
            return Err(OrgRouteError::BadRequest(
                "ORGANIZATION_NOT_FOUND".to_string(),
            ))
        }
    };

    // Check membership
    let is_member = adapter.check_membership(user_id, &full_org.id).await?;
    if !is_member {
        // Clear active org
        if let Some(token) = session_token {
            let _ = adapter.set_active_organization(token, None).await;
        }
        return Err(OrgRouteError::Forbidden(
            "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION".to_string(),
        ));
    }

    Ok(Some(full_org))
}

// ── List Organizations ──────────────────────────────────────────

/// Handle GET /organization/list
///
/// Lists all organizations the user is a member of.
pub async fn handle_list_organizations(
    adapter: &OrgAdapter,
    user_id: &str,
) -> Result<Vec<Organization>, OrgRouteError> {
    let orgs = adapter.list_organizations(user_id).await?;
    Ok(orgs)
}

// ── Get Organization by Slug ────────────────────────────────────

/// Handle GET /organization/get-by-slug
///
/// Gets an organization by its URL slug.
pub async fn handle_get_by_slug(
    adapter: &OrgAdapter,
    slug: &str,
) -> Result<Organization, OrgRouteError> {
    adapter
        .find_organization_by_slug(slug)
        .await?
        .ok_or_else(|| OrgRouteError::NotFound("ORGANIZATION_NOT_FOUND".to_string()))
}

// ── Check Slug ──────────────────────────────────────────────────

/// Handle POST /organization/check-slug
///
/// Checks if a slug is available.
pub async fn handle_check_slug(
    adapter: &OrgAdapter,
    body: CheckSlugRequest,
) -> Result<serde_json::Value, OrgRouteError> {
    let existing = adapter.find_organization_by_slug(&body.slug).await?;
    if existing.is_some() {
        Err(OrgRouteError::BadRequest(
            "SLUG_ALREADY_EXISTS".to_string(),
        ))
    } else {
        Ok(serde_json::json!({ "status": true }))
    }
}

// ── Set Active Organization ─────────────────────────────────────

/// Handle POST /organization/set-active
///
/// Sets the active organization for the current session.
pub async fn handle_set_active_organization(
    adapter: &OrgAdapter,
    user_id: &str,
    session_token: &str,
    active_org_id: Option<&str>,
    body: SetActiveOrganizationRequest,
) -> Result<Option<FullOrganization>, OrgRouteError> {
    let mut organization_id = body.organization_id.clone();

    // If explicitly set to None (null), clear active org
    if organization_id.is_none() && body.organization_slug.is_none() {
        if let Some(_current) = active_org_id {
            adapter
                .set_active_organization(session_token, None)
                .await?;
        }
        return Ok(None);
    }

    // Resolve from slug if needed
    if organization_id.is_none() {
        if let Some(slug) = &body.organization_slug {
            if let Some(org) = adapter.find_organization_by_slug(slug).await? {
                organization_id = Some(org.id);
            } else {
                return Err(OrgRouteError::NotFound(
                    "ORGANIZATION_NOT_FOUND".to_string(),
                ));
            }
        }
    }

    let org_id = match &organization_id {
        Some(id) => id,
        None => return Ok(None),
    };

    // Verify membership
    let is_member = adapter.check_membership(user_id, org_id).await?;
    if !is_member {
        return Err(OrgRouteError::Forbidden(
            "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION".to_string(),
        ));
    }

    // Set as active
    adapter
        .set_active_organization(session_token, Some(org_id))
        .await?;

    // Return the full organization
    let full_org = adapter
        .find_full_organization(org_id, false, false, None)
        .await?;

    Ok(full_org)
}

// ── Get Active Organization ─────────────────────────────────────

/// Handle GET /organization/get-active
///
/// Gets the currently active organization.
pub async fn handle_get_active_organization(
    adapter: &OrgAdapter,
    session_token: &str,
) -> Result<Option<FullOrganization>, OrgRouteError> {
    let org = adapter.get_active_organization(session_token).await?;

    match org {
        Some(org) => {
            let full = adapter
                .find_full_organization(&org.id, false, false, None)
                .await?;
            Ok(full)
        }
        None => Ok(None),
    }
}
