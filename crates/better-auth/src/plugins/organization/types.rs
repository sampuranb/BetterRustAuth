// Organization plugin types — models, request/response types, and options.
//
// Maps to: packages/better-auth/src/plugins/organization/schema.ts
//          packages/better-auth/src/plugins/organization/types.ts

use std::collections::HashMap;

use crate::plugins::access::Role;

// ── Organization models ─────────────────────────────────────────────────────

/// Organization record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    pub metadata: Option<String>,
    pub created_at: String,
}

/// Organization member record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationMember {
    pub id: String,
    pub organization_id: String,
    pub user_id: String,
    pub role: String,
    pub team_id: Option<String>,
    pub created_at: String,
}

/// Organization invitation record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationInvitation {
    pub id: String,
    pub organization_id: String,
    pub email: String,
    pub role: String,
    pub status: InvitationStatus,
    pub inviter_id: String,
    pub team_id: Option<String>,
    pub expires_at: String,
}

/// Invitation status.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InvitationStatus {
    Pending,
    Accepted,
    Rejected,
    Canceled,
}

impl InvitationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Canceled => "canceled",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "accepted" => Some(Self::Accepted),
            "rejected" => Some(Self::Rejected),
            "canceled" => Some(Self::Canceled),
            _ => None,
        }
    }
}

/// Team record within an organization.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Team {
    pub id: String,
    pub name: String,
    pub organization_id: String,
    pub created_at: String,
}

/// Full organization with members, invitations, and optional teams.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FullOrganization {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    pub metadata: Option<String>,
    pub created_at: String,
    pub members: Vec<OrganizationMember>,
    pub invitations: Vec<OrganizationInvitation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub teams: Option<Vec<Team>>,
}

/// Dynamic organization role (stored in DB, used by dynamic access control).
///
/// Maps to: packages/better-auth/src/plugins/organization/schema.ts OrganizationRole
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationRole {
    pub id: String,
    pub organization_id: String,
    pub role: String,
    /// JSON stringified permission map: Record<string, string[]>
    pub permission: String,
    pub created_at: String,
}

// ── Request/Response types ──────────────────────────────────────────────────

/// Request body for creating an organization.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOrganizationRequest {
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub user_id: Option<String>,
    pub keep_current_active_organization: Option<bool>,
}

/// Internal data for creating an organization.
#[derive(Debug, Clone)]
pub struct CreateOrganizationData {
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Request body for updating an organization.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateOrganizationRequest {
    pub data: UpdateOrganizationData,
    pub organization_id: Option<String>,
}

/// Data fields for updating an organization.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct UpdateOrganizationData {
    pub name: Option<String>,
    pub slug: Option<String>,
    pub logo: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Request body for deleting an organization.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteOrganizationRequest {
    pub organization_id: String,
}

/// Request body for setting active organization.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetActiveOrganizationRequest {
    pub organization_id: Option<String>,
    pub organization_slug: Option<String>,
}

/// Request body for inviting a member.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteMemberRequest {
    pub email: String,
    pub role: String,
    pub organization_id: String,
    pub team_id: Option<String>,
    pub resend: Option<bool>,
}

/// Internal data for creating an invitation.
#[derive(Debug, Clone)]
pub struct CreateInvitationData {
    pub organization_id: String,
    pub email: String,
    pub role: String,
    pub inviter_id: String,
    pub team_id: Option<String>,
    pub expires_at: String,
}

/// Request body for accepting/rejecting/canceling an invitation.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitationActionRequest {
    pub invitation_id: String,
}

/// Request body for removing a member.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveMemberRequest {
    pub member_id: String,
    pub organization_id: String,
}

/// Request body for updating a member's role.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateMemberRoleRequest {
    pub member_id: String,
    pub role: String,
    pub organization_id: Option<String>,
}

/// Request body for leaving an organization.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeaveOrganizationRequest {
    pub organization_id: String,
}

/// Request body for creating a team.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTeamRequest {
    pub name: String,
    pub organization_id: String,
}

/// Internal data for creating a team.
#[derive(Debug, Clone)]
pub struct CreateTeamData {
    pub name: String,
    pub organization_id: String,
}

/// Request body for updating a team.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTeamRequest {
    pub team_id: String,
    pub name: String,
    pub organization_id: Option<String>,
}

/// Request body for deleting a team.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteTeamRequest {
    pub team_id: String,
    pub organization_id: Option<String>,
}

/// Request body for adding a member to a team.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddTeamMemberRequest {
    pub team_id: String,
    pub member_id: String,
    pub organization_id: Option<String>,
}

/// Request body for removing a member from a team.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveTeamMemberRequest {
    pub team_id: String,
    pub member_id: String,
    pub organization_id: Option<String>,
}

/// Request body for checking a slug.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CheckSlugRequest {
    pub slug: String,
}

/// Request body for has-permission check.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HasPermissionRequest {
    pub permission: PermissionCheck,
    pub organization_id: Option<String>,
}

/// Permission check specification.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PermissionCheck {
    pub resource: Option<String>,
    pub action: Option<Vec<String>>,
    #[serde(rename = "type")]
    pub check_type: Option<String>,
}

/// Internal member data for creation.
#[derive(Debug, Clone)]
pub struct CreateMemberData {
    pub organization_id: String,
    pub user_id: String,
    pub role: String,
    pub team_id: Option<String>,
}

// ── Dynamic access control request types ────────────────────────────────────

/// Request body for creating a dynamic organization role.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOrgRoleRequest {
    pub organization_id: Option<String>,
    pub role: String,
    pub permission: HashMap<String, Vec<String>>,
}

/// Internal data for creating a dynamic organization role.
#[derive(Debug, Clone)]
pub struct CreateOrgRoleData {
    pub organization_id: String,
    pub role: String,
    /// JSON stringified permission map.
    pub permission: String,
}

/// Request body for deleting a dynamic organization role.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteOrgRoleRequest {
    pub organization_id: Option<String>,
    pub role_name: Option<String>,
    pub role_id: Option<String>,
}

/// Request body for updating a dynamic organization role.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateOrgRoleRequest {
    pub organization_id: Option<String>,
    pub role_name: Option<String>,
    pub role_id: Option<String>,
    pub permission: HashMap<String, Vec<String>>,
}

/// Request body for getting active member (member record for the session's active org).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetActiveMemberRequest {
    pub organization_id: Option<String>,
}

/// Request body for listing invitations.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListInvitationsRequest {
    pub organization_id: Option<String>,
}

/// Query parameters for listing user invitations.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListUserInvitationsRequest {
    /// Optional email override (server-side only).
    pub email: Option<String>,
}

// ── Organization options ────────────────────────────────────────────────────

/// Organization plugin options.
#[derive(Debug, Clone)]
pub struct OrganizationOptions {
    /// Whether to enable teams within organizations.
    pub enable_teams: bool,
    /// Whether to allow users to create organizations.
    pub allow_user_to_create_org: bool,
    /// Maximum number of organizations a user can create.
    pub organization_limit: Option<usize>,
    /// Default role for new members (default: "member").
    pub default_member_role: String,
    /// Default role for the organization creator (default: "owner").
    pub creator_role: String,
    /// Whether to send invitation emails.
    pub send_invitation_email: bool,
    /// Invitation expiry in seconds (default: 48 hours).
    pub invitation_expiry: u64,
    /// Custom org access control roles.
    pub roles: Option<HashMap<String, Role>>,
    /// Whether to enable dynamic access control endpoints.
    pub enable_access_control: bool,
    /// Whether to disable organization deletion.
    pub disable_organization_deletion: bool,
    /// Membership limit per page for full org queries.
    pub membership_limit: Option<usize>,
    /// Allowed domains for invitations (if set, only these domains can be invited).
    pub allowed_domains: Option<Vec<String>>,
    /// Maximum number of dynamic roles per organization (for dynamic access control).
    pub max_roles_per_org: Option<usize>,
    /// Enable cancel on accept invitation (new inviter can cancel their invitation).
    pub cancel_pending_invitations_on_re_invite: bool,
    /// Number of members to return in a full organization query.
    pub members_limit: Option<usize>,
    /// Maximum number of pending invitations per organization (default: 100).
    pub invitation_limit: usize,
    /// Whether dynamic access control is enabled.
    pub enable_dynamic_access_control: bool,
    /// Maximum members per team (if set, limits team size).
    pub max_members_per_team: Option<usize>,
}

impl Default for OrganizationOptions {
    fn default() -> Self {
        Self {
            enable_teams: false,
            allow_user_to_create_org: true,
            organization_limit: None,
            default_member_role: "member".to_string(),
            creator_role: "owner".to_string(),
            send_invitation_email: false,
            invitation_expiry: DEFAULT_INVITATION_EXPIRY,
            roles: None,
            enable_access_control: false,
            disable_organization_deletion: false,
            membership_limit: None,
            allowed_domains: None,
            max_roles_per_org: None,
            cancel_pending_invitations_on_re_invite: false,
            members_limit: None,
            invitation_limit: 100,
            enable_dynamic_access_control: false,
            max_members_per_team: None,
        }
    }
}

/// Default invitation expiry in seconds (48 hours).
pub const DEFAULT_INVITATION_EXPIRY: u64 = 48 * 60 * 60;
