// Organization helpers — shared utility functions used across route handlers.
//
// Maps to: packages/better-auth/src/plugins/organization/has-permission.ts
//          packages/better-auth/src/plugins/organization/error-codes.ts
//          packages/better-auth/src/plugins/organization/utils.ts

use std::collections::HashMap;

use crate::plugins::access::{default_org_roles, Role};

use super::types::*;

// ── Permission checking ─────────────────────────────────────────

/// Check if a member has a given permission within an organization.
///
/// Resolves the member's role from the role map and checks if the role
/// grants the requested permission on the given resource.
pub fn has_org_permission(
    member_role: &str,
    resource: &str,
    action: &str,
    roles: &HashMap<String, Role>,
) -> bool {
    // Support comma-separated multi-role (dynamic access control)
    let member_roles: Vec<&str> = member_role
        .split(',')
        .map(|r| r.trim())
        .collect();

    for r in &member_roles {
        if let Some(role) = roles.get(*r) {
            let mut req = HashMap::new();
            req.insert(resource.to_string(), vec![action.to_string()]);
            if role.authorize(&req, "AND").is_success() {
                return true;
            }
        }
    }
    false
}

/// Check if the user is the only owner of the organization.
pub fn is_only_owner(members: &[OrganizationMember], user_id: &str) -> bool {
    let owners: Vec<&OrganizationMember> = members
        .iter()
        .filter(|m| {
            m.role
                .split(',')
                .map(|r| r.trim())
                .any(|r| r == "owner")
        })
        .collect();
    owners.len() == 1 && owners[0].user_id == user_id
}

/// Resolve the roles from options or use defaults.
pub fn resolve_roles(options: &OrganizationOptions) -> HashMap<String, Role> {
    options
        .roles
        .clone()
        .unwrap_or_else(default_org_roles)
}

/// Check if a given role exists in the predefined roles.
pub fn is_predefined_role(role_name: &str, options: &OrganizationOptions) -> bool {
    let roles = resolve_roles(options);
    roles.contains_key(role_name)
}

/// Validate that a role name is valid (exists in predefined roles or dynamic roles).
pub fn validate_role(role: &str, options: &OrganizationOptions) -> bool {
    let roles = resolve_roles(options);
    let role_parts: Vec<&str> = role.split(',').map(|r| r.trim()).collect();
    role_parts.iter().all(|r| roles.contains_key(*r) || !r.is_empty())
}

/// Check if the invitation domain is allowed.
pub fn is_domain_allowed(email: &str, allowed_domains: &Option<Vec<String>>) -> bool {
    match allowed_domains {
        Some(domains) if !domains.is_empty() => {
            if let Some(domain) = email.split('@').nth(1) {
                domains.iter().any(|d| d.eq_ignore_ascii_case(domain))
            } else {
                false
            }
        }
        _ => true,
    }
}

// ── Slug generation ─────────────────────────────────────────────

/// Generate a URL-safe slug from an organization name.
pub fn generate_slug(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Generate a unique slug by appending a random suffix.
pub fn generate_unique_slug(name: &str) -> String {
    use rand::Rng;
    let base = generate_slug(name);
    let mut rng = rand::thread_rng();
    let suffix: String = (0..4)
        .map(|_| {
            let idx = rng.gen_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect();
    format!("{}-{}", base, suffix)
}

// ── Invitation helpers ──────────────────────────────────────────

/// Calculate invitation expiry date.
pub fn calculate_invitation_expiry(seconds: u64) -> String {
    let expiry = chrono::Utc::now() + chrono::Duration::seconds(seconds as i64);
    expiry.to_rfc3339()
}

/// Check if an invitation has expired.
pub fn is_invitation_expired(expires_at: &str) -> bool {
    if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(expires_at) {
        chrono::Utc::now() > expiry
    } else {
        true // If unparseable, treat as expired
    }
}

// ── Error codes ─────────────────────────────────────────────────
//
// Maps to: packages/better-auth/src/plugins/organization/error-codes.ts (94 lines)
//
// All 30+ error codes from the TS implementation.

pub struct OrgErrorCodes;

impl OrgErrorCodes {
    // ── Organization CRUD errors ─────────────────────────
    pub const ORGANIZATION_NOT_FOUND: &'static str = "ORGANIZATION_NOT_FOUND";
    pub const YOU_ARE_NOT_ALLOWED_TO_CREATE_ORGANIZATIONS: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_ORGANIZATIONS";
    pub const YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS: &'static str =
        "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS";
    pub const ORGANIZATION_ALREADY_EXISTS: &'static str = "ORGANIZATION_ALREADY_EXISTS";
    pub const SLUG_ALREADY_EXISTS: &'static str = "SLUG_ALREADY_EXISTS";
    pub const YOU_ARE_NOT_ALLOWED_TO_UPDATE_ORGANIZATIONS: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_ORGANIZATIONS";
    pub const YOU_ARE_NOT_ALLOWED_TO_DELETE_ORGANIZATIONS: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_ORGANIZATIONS";
    pub const ORGANIZATION_DELETION_DISABLED: &'static str =
        "ORGANIZATION_DELETION_DISABLED";
    pub const NO_ACTIVE_ORGANIZATION: &'static str = "NO_ACTIVE_ORGANIZATION";

    // ── Member errors ────────────────────────────────────
    pub const MEMBER_NOT_FOUND: &'static str = "MEMBER_NOT_FOUND";
    pub const YOU_ARE_NOT_A_MEMBER: &'static str =
        "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION";
    pub const YOU_ARE_NOT_ALLOWED_TO_INVITE_MEMBERS: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_INVITE_MEMBERS";
    pub const YOU_ARE_NOT_ALLOWED_TO_REMOVE_MEMBERS: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_REMOVE_MEMBERS";
    pub const YOU_ARE_NOT_ALLOWED_TO_UPDATE_MEMBER_ROLE: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_MEMBER_ROLE";
    pub const USER_IS_ALREADY_A_MEMBER: &'static str = "USER_IS_ALREADY_A_MEMBER";
    pub const YOU_CANNOT_LEAVE_AS_ONLY_OWNER: &'static str =
        "YOU_CANNOT_LEAVE_AS_ONLY_OWNER";
    pub const CANNOT_DELETE_OWNER_ROLE: &'static str = "CANNOT_DELETE_OWNER_ROLE";
    pub const CANNOT_ASSIGN_HIGHER_ROLE: &'static str = "CANNOT_ASSIGN_HIGHER_ROLE";
    pub const DOMAIN_NOT_ALLOWED: &'static str = "DOMAIN_NOT_ALLOWED";

    // ── Invitation errors ────────────────────────────────
    pub const INVITATION_NOT_FOUND: &'static str = "INVITATION_NOT_FOUND";
    pub const INVITATION_EXPIRED: &'static str = "INVITATION_EXPIRED";
    pub const INVITATION_ALREADY_ACCEPTED: &'static str = "INVITATION_ALREADY_ACCEPTED";
    pub const INVITATION_ALREADY_REJECTED: &'static str = "INVITATION_ALREADY_REJECTED";
    pub const INVITATION_ALREADY_CANCELED: &'static str = "INVITATION_ALREADY_CANCELED";
    pub const INVITATION_HAS_ALREADY_BEEN_SENT: &'static str =
        "INVITATION_HAS_ALREADY_BEEN_SENT";
    pub const YOU_CANNOT_CANCEL_YOUR_OWN_INVITATION: &'static str =
        "YOU_CANNOT_CANCEL_YOUR_OWN_INVITATION";
    pub const YOU_ARE_NOT_ALLOWED_TO_CANCEL_INVITATIONS: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_CANCEL_INVITATIONS";

    // ── Team errors ──────────────────────────────────────
    pub const TEAM_NOT_FOUND: &'static str = "TEAM_NOT_FOUND";
    pub const YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS";
    pub const YOU_ARE_NOT_ALLOWED_TO_UPDATE_TEAMS: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_TEAMS";
    pub const YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS";
    pub const MEMBER_NOT_ON_TEAM: &'static str = "MEMBER_NOT_ON_TEAM";
    pub const MEMBER_ALREADY_ON_TEAM: &'static str = "MEMBER_ALREADY_ON_TEAM";

    // ── Dynamic access control errors ────────────────────
    pub const MISSING_AC_INSTANCE: &'static str = "MISSING_AC_INSTANCE";
    pub const ROLE_NOT_FOUND: &'static str = "ROLE_NOT_FOUND";
    pub const ROLE_NAME_ALREADY_TAKEN: &'static str = "ROLE_NAME_ALREADY_TAKEN";
    pub const TOO_MANY_ROLES: &'static str = "TOO_MANY_ROLES";
    pub const INVALID_RESOURCE: &'static str = "INVALID_RESOURCE";
    pub const ROLE_ASSIGNED_TO_MEMBERS: &'static str = "ROLE_IS_ASSIGNED_TO_MEMBERS";
    pub const CANNOT_DELETE_PREDEFINED_ROLE: &'static str =
        "CANNOT_DELETE_A_PRE_DEFINED_ROLE";
    pub const YOU_ARE_NOT_ALLOWED_TO_CREATE_ROLE: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE";
    pub const YOU_ARE_NOT_ALLOWED_TO_DELETE_ROLE: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE";
    pub const YOU_ARE_NOT_ALLOWED_TO_UPDATE_ROLE: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE";
    pub const YOU_ARE_NOT_ALLOWED_TO_LIST_ROLES: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE";
    pub const YOU_ARE_NOT_ALLOWED_TO_READ_ROLE: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE";
    pub const YOU_MUST_BE_IN_AN_ORG_TO_CREATE_ROLE: &'static str =
        "YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE";
}

pub fn org_error_message(code: &str) -> &'static str {
    match code {
        "ORGANIZATION_NOT_FOUND" => "Organization not found",
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_ORGANIZATIONS" => "You are not allowed to create organizations",
        "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS" => "You have reached the maximum number of organizations",
        "ORGANIZATION_ALREADY_EXISTS" => "Organization already exists",
        "SLUG_ALREADY_EXISTS" => "An organization with this slug already exists",
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_ORGANIZATIONS" => "You are not allowed to update this organization",
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_ORGANIZATIONS" => "You are not allowed to delete this organization",
        "ORGANIZATION_DELETION_DISABLED" => "Organization deletion is disabled",
        "NO_ACTIVE_ORGANIZATION" => "No active organization set on this session",
        "MEMBER_NOT_FOUND" => "Member not found",
        "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION" => "You are not a member of this organization",
        "YOU_ARE_NOT_ALLOWED_TO_INVITE_MEMBERS" => "You are not allowed to invite members",
        "YOU_ARE_NOT_ALLOWED_TO_REMOVE_MEMBERS" => "You are not allowed to remove members",
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_MEMBER_ROLE" => "You are not allowed to update member roles",
        "USER_IS_ALREADY_A_MEMBER" => "User is already a member of this organization",
        "YOU_CANNOT_LEAVE_AS_ONLY_OWNER" => "You cannot leave the organization as the only owner",
        "CANNOT_DELETE_OWNER_ROLE" => "Cannot delete the owner role",
        "CANNOT_ASSIGN_HIGHER_ROLE" => "Cannot assign a role higher than your own",
        "DOMAIN_NOT_ALLOWED" => "The email domain is not allowed for this organization",
        "INVITATION_NOT_FOUND" => "Invitation not found",
        "INVITATION_EXPIRED" => "The invitation has expired",
        "INVITATION_ALREADY_ACCEPTED" => "The invitation has already been accepted",
        "INVITATION_ALREADY_REJECTED" => "The invitation has already been rejected",
        "INVITATION_ALREADY_CANCELED" => "The invitation has already been canceled",
        "INVITATION_HAS_ALREADY_BEEN_SENT" => "An invitation has already been sent to this email",
        "YOU_CANNOT_CANCEL_YOUR_OWN_INVITATION" => "You cannot cancel your own invitation",
        "YOU_ARE_NOT_ALLOWED_TO_CANCEL_INVITATIONS" => "You are not allowed to cancel invitations",
        "TEAM_NOT_FOUND" => "Team not found",
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS" => "You are not allowed to create teams",
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_TEAMS" => "You are not allowed to update teams",
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS" => "You are not allowed to delete teams",
        "MEMBER_NOT_ON_TEAM" => "Member is not on this team",
        "MEMBER_ALREADY_ON_TEAM" => "Member is already on this team",
        "MISSING_AC_INSTANCE" => "The organization plugin is missing a pre-defined access control instance",
        "ROLE_NOT_FOUND" => "Role not found",
        "ROLE_NAME_ALREADY_TAKEN" => "A role with this name already exists",
        "TOO_MANY_ROLES" => "The organization has reached the maximum number of roles",
        "INVALID_RESOURCE" => "Invalid resource specified in permission",
        "ROLE_IS_ASSIGNED_TO_MEMBERS" => "Cannot delete a role that is assigned to members",
        "CANNOT_DELETE_A_PRE_DEFINED_ROLE" => "Cannot delete a pre-defined role",
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE" => "You are not allowed to create a role",
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE" => "You are not allowed to delete a role",
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE" => "You are not allowed to update a role",
        "YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE" => "You are not allowed to list roles",
        "YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE" => "You are not allowed to read a role",
        "YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE" => "You must be in an organization to create a role",
        _ => "Unknown organization error",
    }
}
