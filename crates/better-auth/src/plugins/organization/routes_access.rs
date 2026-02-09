// Organization access control route handlers.
//
// Maps to: packages/better-auth/src/plugins/organization/routes/crud-access-control.ts (1,276 lines)
//
// Handlers for permission checking, dynamic role CRUD, and access control.

use std::collections::HashMap;

use super::adapter::OrgAdapter;
use super::helpers::*;
use super::routes_org::OrgRouteError;
use super::types::*;

// ── Has Permission ──────────────────────────────────────────────

/// Handle POST /organization/has-permission
///
/// Checks if the current user has a specific permission within the organization.
/// This is the main permission check endpoint used by clients.
pub async fn handle_has_permission(
    adapter: &OrgAdapter,
    user_id: &str,
    active_org_id: Option<&str>,
    options: &OrganizationOptions,
    body: HasPermissionRequest,
) -> Result<serde_json::Value, OrgRouteError> {
    let organization_id = body
        .organization_id
        .as_deref()
        .or(active_org_id)
        .ok_or_else(|| OrgRouteError::BadRequest("ORGANIZATION_NOT_FOUND".to_string()))?;

    // Find the member
    let member = adapter
        .find_member_by_org_id(user_id, organization_id)
        .await?
        .ok_or_else(|| {
            OrgRouteError::Forbidden(
                "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION".to_string(),
            )
        })?;

    let roles = resolve_roles(options);

    // Build the permission requirements
    let has_perm = if let Some(resource) = &body.permission.resource {
        let actions = body
            .permission
            .action
            .clone()
            .unwrap_or_else(|| vec!["read".to_string()]);
        has_org_permission(&member.role, resource, &actions.join(","), &roles)
    } else {
        false
    };

    Ok(serde_json::json!({
        "success": has_perm,
        "role": member.role,
    }))
}

// ── Get Permissions ─────────────────────────────────────────────

/// Handle GET /organization/get-permissions
///
/// Returns the available roles and their permissions.
pub async fn handle_get_permissions(
    options: &OrganizationOptions,
) -> Result<serde_json::Value, OrgRouteError> {
    let roles = resolve_roles(options);

    let mut role_list: Vec<serde_json::Value> = Vec::new();
    for (name, role) in &roles {
        role_list.push(serde_json::json!({
            "role": name,
            "permissions": format!("{:?}", role),
        }));
    }

    Ok(serde_json::json!({
        "roles": role_list,
    }))
}

// ── Check Permission (detailed) ─────────────────────────────────

/// Handle POST /organization/check-permission
///
/// Detailed permission check — returns the full authorization result
/// including which specific permissions matched.
pub async fn handle_check_permission(
    adapter: &OrgAdapter,
    user_id: &str,
    active_org_id: Option<&str>,
    options: &OrganizationOptions,
    body: HasPermissionRequest,
) -> Result<serde_json::Value, OrgRouteError> {
    let organization_id = body
        .organization_id
        .as_deref()
        .or(active_org_id)
        .ok_or_else(|| OrgRouteError::BadRequest("ORGANIZATION_NOT_FOUND".to_string()))?;

    let member = adapter
        .find_member_by_org_id(user_id, organization_id)
        .await?
        .ok_or_else(|| {
            OrgRouteError::Forbidden(
                "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION".to_string(),
            )
        })?;

    let roles = resolve_roles(options);

    let role = match roles.get(&member.role) {
        Some(r) => r,
        None => {
            return Ok(serde_json::json!({
                "success": false,
                "error": "ROLE_NOT_FOUND",
                "role": member.role,
            }));
        }
    };

    let resource = body
        .permission
        .resource
        .as_deref()
        .unwrap_or("organization");
    let actions = body
        .permission
        .action
        .clone()
        .unwrap_or_else(|| vec!["read".to_string()]);

    let mut required = HashMap::new();
    required.insert(resource.to_string(), actions.clone());

    let check_type = body
        .permission
        .check_type
        .as_deref()
        .unwrap_or("AND");

    let result = role.authorize(&required, check_type);

    Ok(serde_json::json!({
        "success": result.is_success(),
        "role": member.role,
        "resource": resource,
        "actions": actions,
    }))
}

// ── Dynamic Access Control: Create Role ─────────────────────────

/// Handle POST /organization/create-role
///
/// Creates a new dynamic role for an organization.
/// Requires ac (access control) instance and appropriate permissions.
pub async fn handle_create_org_role(
    adapter: &OrgAdapter,
    user_id: &str,
    active_org_id: Option<&str>,
    options: &OrganizationOptions,
    body: CreateOrgRoleRequest,
) -> Result<serde_json::Value, OrgRouteError> {
    if !options.enable_access_control {
        return Err(OrgRouteError::BadRequest(
            OrgErrorCodes::MISSING_AC_INSTANCE.to_string(),
        ));
    }

    let organization_id = body
        .organization_id
        .as_deref()
        .or(active_org_id)
        .ok_or_else(|| {
            OrgRouteError::BadRequest(
                OrgErrorCodes::YOU_MUST_BE_IN_AN_ORG_TO_CREATE_ROLE.to_string(),
            )
        })?;

    let role_name = body.role.to_lowercase();

    // Check that the role name isn't a pre-defined role
    let roles = resolve_roles(options);
    if roles.contains_key(&role_name) {
        return Err(OrgRouteError::BadRequest(
            OrgErrorCodes::ROLE_NAME_ALREADY_TAKEN.to_string(),
        ));
    }

    // Verify user is a member
    let member = adapter
        .find_member_by_org_id(user_id, organization_id)
        .await?
        .ok_or_else(|| {
            OrgRouteError::Forbidden(
                OrgErrorCodes::YOU_ARE_NOT_A_MEMBER.to_string(),
            )
        })?;

    // Check permission to create roles
    let can_create = has_org_permission(&member.role, "ac", "create", &roles);
    if !can_create {
        return Err(OrgRouteError::Forbidden(
            OrgErrorCodes::YOU_ARE_NOT_ALLOWED_TO_CREATE_ROLE.to_string(),
        ));
    }

    // Check maximum roles per organization
    let max_roles = options.max_roles_per_org.unwrap_or(usize::MAX);
    let existing_roles = adapter
        .list_org_roles(organization_id)
        .await?;
    if existing_roles.len() >= max_roles {
        return Err(OrgRouteError::BadRequest(
            OrgErrorCodes::TOO_MANY_ROLES.to_string(),
        ));
    }

    // Check that role name isn't already taken in DB
    let existing = adapter
        .find_org_role_by_name(organization_id, &role_name)
        .await?;
    if existing.is_some() {
        return Err(OrgRouteError::BadRequest(
            OrgErrorCodes::ROLE_NAME_ALREADY_TAKEN.to_string(),
        ));
    }

    // Validate that resources in permissions are valid
    for resource in body.permission.keys() {
        // Basic validation: resources should be non-empty strings
        if resource.is_empty() {
            return Err(OrgRouteError::BadRequest(
                OrgErrorCodes::INVALID_RESOURCE.to_string(),
            ));
        }
    }

    // Create the role
    let data = CreateOrgRoleData {
        organization_id: organization_id.to_string(),
        role: role_name.clone(),
        permission: serde_json::to_string(&body.permission)
            .unwrap_or_default(),
    };

    let org_role = adapter.create_org_role(&data).await?;

    Ok(serde_json::json!({
        "success": true,
        "roleData": {
            "id": org_role.id,
            "organizationId": org_role.organization_id,
            "role": org_role.role,
            "permission": body.permission,
            "createdAt": org_role.created_at,
        },
    }))
}

// ── Dynamic Access Control: Delete Role ─────────────────────────

/// Handle POST /organization/delete-role
///
/// Deletes a dynamic role from an organization.
/// Cannot delete pre-defined roles or roles assigned to members.
pub async fn handle_delete_org_role(
    adapter: &OrgAdapter,
    user_id: &str,
    active_org_id: Option<&str>,
    options: &OrganizationOptions,
    body: DeleteOrgRoleRequest,
) -> Result<serde_json::Value, OrgRouteError> {
    let organization_id = body
        .organization_id
        .as_deref()
        .or(active_org_id)
        .ok_or_else(|| {
            OrgRouteError::BadRequest(OrgErrorCodes::NO_ACTIVE_ORGANIZATION.to_string())
        })?;

    // Verify user is a member
    let member = adapter
        .find_member_by_org_id(user_id, organization_id)
        .await?
        .ok_or_else(|| {
            OrgRouteError::Forbidden(
                OrgErrorCodes::YOU_ARE_NOT_A_MEMBER.to_string(),
            )
        })?;

    let roles = resolve_roles(options);

    // Check permission to delete roles
    let can_delete = has_org_permission(&member.role, "ac", "delete", &roles);
    if !can_delete {
        return Err(OrgRouteError::Forbidden(
            OrgErrorCodes::YOU_ARE_NOT_ALLOWED_TO_DELETE_ROLE.to_string(),
        ));
    }

    // Check that it's not a pre-defined role
    if let Some(ref role_name) = body.role_name {
        if roles.contains_key(role_name) {
            return Err(OrgRouteError::BadRequest(
                OrgErrorCodes::CANNOT_DELETE_PREDEFINED_ROLE.to_string(),
            ));
        }
    }

    // Find the role in DB
    let org_role = if let Some(ref role_name) = body.role_name {
        adapter
            .find_org_role_by_name(organization_id, role_name)
            .await?
    } else if let Some(ref role_id) = body.role_id {
        adapter.find_org_role_by_id(role_id).await?
    } else {
        return Err(OrgRouteError::BadRequest(
            OrgErrorCodes::ROLE_NOT_FOUND.to_string(),
        ));
    };

    let org_role = org_role.ok_or_else(|| {
        OrgRouteError::BadRequest(OrgErrorCodes::ROLE_NOT_FOUND.to_string())
    })?;

    // Check if any members are assigned to this role
    let members = adapter.list_members(organization_id).await?;
    let role_to_delete = &org_role.role;
    let member_with_role = members.iter().find(|m| {
        m.role
            .split(',')
            .map(|r| r.trim())
            .any(|r| r == role_to_delete)
    });
    if member_with_role.is_some() {
        return Err(OrgRouteError::BadRequest(
            OrgErrorCodes::ROLE_ASSIGNED_TO_MEMBERS.to_string(),
        ));
    }

    // Delete the role
    adapter.delete_org_role(&org_role.id).await?;

    Ok(serde_json::json!({
        "success": true,
    }))
}

// ── Dynamic Access Control: Update Role ─────────────────────────

/// Handle POST /organization/update-role
///
/// Updates a dynamic role's permissions.
pub async fn handle_update_org_role(
    adapter: &OrgAdapter,
    user_id: &str,
    active_org_id: Option<&str>,
    options: &OrganizationOptions,
    body: UpdateOrgRoleRequest,
) -> Result<serde_json::Value, OrgRouteError> {
    let organization_id = body
        .organization_id
        .as_deref()
        .or(active_org_id)
        .ok_or_else(|| {
            OrgRouteError::BadRequest(OrgErrorCodes::NO_ACTIVE_ORGANIZATION.to_string())
        })?;

    // Verify user is a member
    let member = adapter
        .find_member_by_org_id(user_id, organization_id)
        .await?
        .ok_or_else(|| {
            OrgRouteError::Forbidden(
                OrgErrorCodes::YOU_ARE_NOT_A_MEMBER.to_string(),
            )
        })?;

    let roles = resolve_roles(options);

    // Check permission to update roles
    let can_update = has_org_permission(&member.role, "ac", "update", &roles);
    if !can_update {
        return Err(OrgRouteError::Forbidden(
            OrgErrorCodes::YOU_ARE_NOT_ALLOWED_TO_UPDATE_ROLE.to_string(),
        ));
    }

    // Find the role
    let org_role = if let Some(ref role_name) = body.role_name {
        adapter
            .find_org_role_by_name(organization_id, role_name)
            .await?
    } else if let Some(ref role_id) = body.role_id {
        adapter.find_org_role_by_id(role_id).await?
    } else {
        return Err(OrgRouteError::BadRequest(
            OrgErrorCodes::ROLE_NOT_FOUND.to_string(),
        ));
    };

    let org_role = org_role.ok_or_else(|| {
        OrgRouteError::BadRequest(OrgErrorCodes::ROLE_NOT_FOUND.to_string())
    })?;

    // Validate resources
    for resource in body.permission.keys() {
        if resource.is_empty() {
            return Err(OrgRouteError::BadRequest(
                OrgErrorCodes::INVALID_RESOURCE.to_string(),
            ));
        }
    }

    // Update the role
    let permission_str = serde_json::to_string(&body.permission)
        .unwrap_or_default();
    let updated_role = adapter
        .update_org_role(&org_role.id, &permission_str)
        .await?;

    Ok(serde_json::json!({
        "success": true,
        "roleData": {
            "id": updated_role.id,
            "organizationId": updated_role.organization_id,
            "role": updated_role.role,
            "permission": body.permission,
            "createdAt": updated_role.created_at,
        },
    }))
}

// ── Dynamic Access Control: List Roles ──────────────────────────

/// Handle GET /organization/list-roles
///
/// Lists all dynamic roles for an organization.
pub async fn handle_list_org_roles(
    adapter: &OrgAdapter,
    user_id: &str,
    active_org_id: Option<&str>,
    options: &OrganizationOptions,
    organization_id_query: Option<&str>,
) -> Result<serde_json::Value, OrgRouteError> {
    let organization_id = organization_id_query
        .or(active_org_id)
        .ok_or_else(|| {
            OrgRouteError::BadRequest(OrgErrorCodes::NO_ACTIVE_ORGANIZATION.to_string())
        })?;

    // Verify user is a member
    let member = adapter
        .find_member_by_org_id(user_id, organization_id)
        .await?
        .ok_or_else(|| {
            OrgRouteError::Forbidden(
                OrgErrorCodes::YOU_ARE_NOT_A_MEMBER.to_string(),
            )
        })?;

    let roles = resolve_roles(options);

    // Check permission to list roles
    let can_read = has_org_permission(&member.role, "ac", "read", &roles);
    if !can_read {
        return Err(OrgRouteError::Forbidden(
            OrgErrorCodes::YOU_ARE_NOT_ALLOWED_TO_LIST_ROLES.to_string(),
        ));
    }

    let org_roles = adapter.list_org_roles(organization_id).await?;
    let role_data: Vec<serde_json::Value> = org_roles
        .into_iter()
        .map(|r| {
            let permission: serde_json::Value =
                serde_json::from_str(&r.permission).unwrap_or(serde_json::json!({}));
            serde_json::json!({
                "id": r.id,
                "organizationId": r.organization_id,
                "role": r.role,
                "permission": permission,
                "createdAt": r.created_at,
            })
        })
        .collect();

    Ok(serde_json::json!(role_data))
}

// ── Dynamic Access Control: Get Role ────────────────────────────

/// Handle GET /organization/get-role
///
/// Gets a single dynamic role by name or ID.
pub async fn handle_get_org_role(
    adapter: &OrgAdapter,
    user_id: &str,
    active_org_id: Option<&str>,
    options: &OrganizationOptions,
    organization_id_query: Option<&str>,
    role_name: Option<&str>,
    role_id: Option<&str>,
) -> Result<serde_json::Value, OrgRouteError> {
    let organization_id = organization_id_query
        .or(active_org_id)
        .ok_or_else(|| {
            OrgRouteError::BadRequest(OrgErrorCodes::NO_ACTIVE_ORGANIZATION.to_string())
        })?;

    // Verify user is a member
    let member = adapter
        .find_member_by_org_id(user_id, organization_id)
        .await?
        .ok_or_else(|| {
            OrgRouteError::Forbidden(
                OrgErrorCodes::YOU_ARE_NOT_A_MEMBER.to_string(),
            )
        })?;

    let roles = resolve_roles(options);

    // Check permission to read roles
    let can_read = has_org_permission(&member.role, "ac", "read", &roles);
    if !can_read {
        return Err(OrgRouteError::Forbidden(
            OrgErrorCodes::YOU_ARE_NOT_ALLOWED_TO_READ_ROLE.to_string(),
        ));
    }

    let org_role = if let Some(name) = role_name {
        adapter
            .find_org_role_by_name(organization_id, name)
            .await?
    } else if let Some(id) = role_id {
        adapter.find_org_role_by_id(id).await?
    } else {
        return Err(OrgRouteError::BadRequest(
            OrgErrorCodes::ROLE_NOT_FOUND.to_string(),
        ));
    };

    let org_role = org_role.ok_or_else(|| {
        OrgRouteError::BadRequest(OrgErrorCodes::ROLE_NOT_FOUND.to_string())
    })?;

    let permission: serde_json::Value =
        serde_json::from_str(&org_role.permission).unwrap_or(serde_json::json!({}));

    Ok(serde_json::json!({
        "id": org_role.id,
        "organizationId": org_role.organization_id,
        "role": org_role.role,
        "permission": permission,
        "createdAt": org_role.created_at,
    }))
}
