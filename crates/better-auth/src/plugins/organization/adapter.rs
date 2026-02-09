// Organization adapter — all database operations for the organization plugin.
//
// Maps to: packages/better-auth/src/plugins/organization/adapter.ts (1,064 lines)
//
// Provides CRUD operations for organizations, members, invitations, and teams
// via the InternalAdapter layer.

use std::sync::Arc;

use serde_json::Value;

use crate::internal_adapter::{AdapterError, InternalAdapter};

use super::types::*;

/// Organization database adapter.
///
/// Wraps the InternalAdapter to provide typed CRUD operations for all
/// organization-related tables.
pub struct OrgAdapter {
    adapter: Arc<dyn InternalAdapter>,
}

impl OrgAdapter {
    pub fn new(adapter: Arc<dyn InternalAdapter>) -> Self {
        Self { adapter }
    }

    // ─── Organization CRUD ──────────────────────────────────────────

    /// Create a new organization.
    pub async fn create_organization(
        &self,
        data: &CreateOrganizationData,
    ) -> Result<Organization, AdapterError> {
        let now = chrono::Utc::now().to_rfc3339();
        let id = crate::crypto::random::generate_random_string(32);
        let metadata_str = data
            .metadata
            .as_ref()
            .map(|m| serde_json::to_string(m).unwrap_or_default());

        let mut fields = serde_json::json!({
            "id": id,
            "name": data.name,
            "slug": data.slug,
            "createdAt": now,
        });
        if let Some(logo) = &data.logo {
            fields["logo"] = Value::String(logo.clone());
        }
        if let Some(meta) = &metadata_str {
            fields["metadata"] = Value::String(meta.clone());
        }

        let result = self
            .adapter
            .create("organization", fields)
            .await?;

        parse_organization(&result)
    }

    /// Find an organization by ID.
    pub async fn find_organization_by_id(
        &self,
        id: &str,
    ) -> Result<Option<Organization>, AdapterError> {
        match self.adapter.find_by_id("organization", id).await {
            Ok(val) => Ok(Some(parse_organization(&val)?)),
            Err(AdapterError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Find an organization by slug.
    pub async fn find_organization_by_slug(
        &self,
        slug: &str,
    ) -> Result<Option<Organization>, AdapterError> {
        let filter = serde_json::json!([{ "field": "slug", "value": slug }]);
        match self.adapter.find_one("organization", filter).await {
            Ok(val) => Ok(Some(parse_organization(&val)?)),
            Err(AdapterError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Update an organization.
    pub async fn update_organization(
        &self,
        id: &str,
        data: &UpdateOrganizationData,
    ) -> Result<Organization, AdapterError> {
        let mut updates = serde_json::Map::new();
        if let Some(name) = &data.name {
            updates.insert("name".to_string(), Value::String(name.clone()));
        }
        if let Some(slug) = &data.slug {
            updates.insert("slug".to_string(), Value::String(slug.clone()));
        }
        if let Some(logo) = &data.logo {
            updates.insert("logo".to_string(), Value::String(logo.clone()));
        }
        if let Some(metadata) = &data.metadata {
            let meta_str = serde_json::to_string(metadata).unwrap_or_default();
            updates.insert("metadata".to_string(), Value::String(meta_str));
        }

        let result = self
            .adapter
            .update_by_id("organization", id, Value::Object(updates))
            .await?;
        parse_organization(&result)
    }

    /// Delete an organization and all related data (members, invitations, teams).
    pub async fn delete_organization(&self, id: &str) -> Result<(), AdapterError> {
        // Delete all members
        let member_filter = serde_json::json!([{ "field": "organizationId", "value": id }]);
        let _ = self.adapter.delete_many("member", member_filter).await;

        // Delete all invitations
        let inv_filter = serde_json::json!([{ "field": "organizationId", "value": id }]);
        let _ = self.adapter.delete_many("invitation", inv_filter).await;

        // Delete all teams
        let team_filter = serde_json::json!([{ "field": "organizationId", "value": id }]);
        let _ = self.adapter.delete_many("team", team_filter).await;

        // Delete the organization itself
        self.adapter.delete_by_id("organization", id).await
    }

    /// List organizations for a user (through their memberships).
    pub async fn list_organizations(
        &self,
        user_id: &str,
    ) -> Result<Vec<Organization>, AdapterError> {
        let filter = serde_json::json!([{ "field": "userId", "value": user_id }]);
        let members = self.adapter.find_many("member", filter).await?;

        let mut orgs = Vec::new();
        for member in &members {
            if let Some(org_id) = member["organizationId"].as_str() {
                if let Ok(Some(org)) = self.find_organization_by_id(org_id).await {
                    orgs.push(org);
                }
            }
        }
        Ok(orgs)
    }

    /// Get a full organization with members, invitations, and optionally teams.
    pub async fn find_full_organization(
        &self,
        org_id_or_slug: &str,
        is_slug: bool,
        include_teams: bool,
        members_limit: Option<usize>,
    ) -> Result<Option<FullOrganization>, AdapterError> {
        let org = if is_slug {
            self.find_organization_by_slug(org_id_or_slug).await?
        } else {
            self.find_organization_by_id(org_id_or_slug).await?
        };

        let org = match org {
            Some(o) => o,
            None => return Ok(None),
        };

        let member_filter =
            serde_json::json!([{ "field": "organizationId", "value": org.id }]);
        let member_rows = self.adapter.find_many("member", member_filter).await?;
        let mut members: Vec<OrganizationMember> = member_rows
            .iter()
            .filter_map(|v| parse_member(v).ok())
            .collect();

        if let Some(limit) = members_limit {
            members.truncate(limit);
        }

        let inv_filter =
            serde_json::json!([{ "field": "organizationId", "value": org.id }]);
        let inv_rows = self.adapter.find_many("invitation", inv_filter).await?;
        let invitations: Vec<OrganizationInvitation> = inv_rows
            .iter()
            .filter_map(|v| parse_invitation(v).ok())
            .collect();

        let teams = if include_teams {
            let team_filter =
                serde_json::json!([{ "field": "organizationId", "value": org.id }]);
            let team_rows = self.adapter.find_many("team", team_filter).await?;
            Some(
                team_rows
                    .iter()
                    .filter_map(|v| parse_team(v).ok())
                    .collect(),
            )
        } else {
            None
        };

        Ok(Some(FullOrganization {
            id: org.id,
            name: org.name,
            slug: org.slug,
            logo: org.logo,
            metadata: org.metadata,
            created_at: org.created_at,
            members,
            invitations,
            teams,
        }))
    }

    // ─── Member CRUD ────────────────────────────────────────────────

    /// Create a new member.
    pub async fn create_member(
        &self,
        data: &CreateMemberData,
    ) -> Result<OrganizationMember, AdapterError> {
        let id = crate::crypto::random::generate_random_string(32);
        let now = chrono::Utc::now().to_rfc3339();
        let mut fields = serde_json::json!({
            "id": id,
            "organizationId": data.organization_id,
            "userId": data.user_id,
            "role": data.role,
            "createdAt": now,
        });
        if let Some(team_id) = &data.team_id {
            fields["teamId"] = Value::String(team_id.clone());
        }

        let result = self.adapter.create("member", fields).await?;
        parse_member(&result)
    }

    /// Find a member by user ID and organization ID.
    pub async fn find_member_by_org_id(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<Option<OrganizationMember>, AdapterError> {
        let filter = serde_json::json!([
            { "field": "userId", "value": user_id },
            { "field": "organizationId", "value": organization_id }
        ]);
        match self.adapter.find_one("member", filter).await {
            Ok(val) => Ok(Some(parse_member(&val)?)),
            Err(AdapterError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Find a member by ID.
    pub async fn find_member_by_id(
        &self,
        id: &str,
    ) -> Result<Option<OrganizationMember>, AdapterError> {
        match self.adapter.find_by_id("member", id).await {
            Ok(val) => Ok(Some(parse_member(&val)?)),
            Err(AdapterError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Update a member's role.
    pub async fn update_member_role(
        &self,
        member_id: &str,
        role: &str,
    ) -> Result<OrganizationMember, AdapterError> {
        let updates = serde_json::json!({ "role": role });
        let result = self
            .adapter
            .update_by_id("member", member_id, updates)
            .await?;
        parse_member(&result)
    }

    /// Remove a member from an organization.
    pub async fn remove_member(&self, member_id: &str) -> Result<(), AdapterError> {
        self.adapter.delete_by_id("member", member_id).await
    }

    /// List all members of an organization.
    pub async fn list_members(
        &self,
        organization_id: &str,
    ) -> Result<Vec<OrganizationMember>, AdapterError> {
        let filter =
            serde_json::json!([{ "field": "organizationId", "value": organization_id }]);
        let rows = self.adapter.find_many("member", filter).await?;
        Ok(rows.iter().filter_map(|v| parse_member(v).ok()).collect())
    }

    /// Check if a user is a member of an organization.
    pub async fn check_membership(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<bool, AdapterError> {
        Ok(self
            .find_member_by_org_id(user_id, organization_id)
            .await?
            .is_some())
    }

    // ─── Invitation CRUD ────────────────────────────────────────────

    /// Create a new invitation.
    pub async fn create_invitation(
        &self,
        data: &CreateInvitationData,
    ) -> Result<OrganizationInvitation, AdapterError> {
        let id = crate::crypto::random::generate_random_string(32);
        let mut fields = serde_json::json!({
            "id": id,
            "organizationId": data.organization_id,
            "email": data.email,
            "role": data.role,
            "status": "pending",
            "inviterId": data.inviter_id,
            "expiresAt": data.expires_at,
        });
        if let Some(team_id) = &data.team_id {
            fields["teamId"] = Value::String(team_id.clone());
        }

        let result = self.adapter.create("invitation", fields).await?;
        parse_invitation(&result)
    }

    /// Find an invitation by ID.
    pub async fn find_invitation_by_id(
        &self,
        id: &str,
    ) -> Result<Option<OrganizationInvitation>, AdapterError> {
        match self.adapter.find_by_id("invitation", id).await {
            Ok(val) => Ok(Some(parse_invitation(&val)?)),
            Err(AdapterError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Find a pending invitation by email and organization.
    pub async fn find_pending_invitation(
        &self,
        email: &str,
        organization_id: &str,
    ) -> Result<Option<OrganizationInvitation>, AdapterError> {
        let filter = serde_json::json!([
            { "field": "email", "value": email },
            { "field": "organizationId", "value": organization_id },
            { "field": "status", "value": "pending" }
        ]);
        match self.adapter.find_one("invitation", filter).await {
            Ok(val) => Ok(Some(parse_invitation(&val)?)),
            Err(AdapterError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Update invitation status.
    pub async fn update_invitation_status(
        &self,
        id: &str,
        status: &str,
    ) -> Result<OrganizationInvitation, AdapterError> {
        let updates = serde_json::json!({ "status": status });
        let result = self
            .adapter
            .update_by_id("invitation", id, updates)
            .await?;
        parse_invitation(&result)
    }

    /// Update invitation expiry date (for resend flow).
    pub async fn update_invitation_expiry(
        &self,
        id: &str,
        expires_at: &str,
    ) -> Result<OrganizationInvitation, AdapterError> {
        let updates = serde_json::json!({ "expiresAt": expires_at });
        let result = self
            .adapter
            .update_by_id("invitation", id, updates)
            .await?;
        parse_invitation(&result)
    }

    /// List invitations for an organization.
    pub async fn list_invitations(
        &self,
        organization_id: &str,
    ) -> Result<Vec<OrganizationInvitation>, AdapterError> {
        let filter =
            serde_json::json!([{ "field": "organizationId", "value": organization_id }]);
        let rows = self.adapter.find_many("invitation", filter).await?;
        Ok(rows
            .iter()
            .filter_map(|v| parse_invitation(v).ok())
            .collect())
    }

    // ─── Team CRUD ──────────────────────────────────────────────────

    /// Create a new team.
    pub async fn create_team(
        &self,
        data: &CreateTeamData,
    ) -> Result<Team, AdapterError> {
        let id = crate::crypto::random::generate_random_string(32);
        let now = chrono::Utc::now().to_rfc3339();
        let fields = serde_json::json!({
            "id": id,
            "name": data.name,
            "organizationId": data.organization_id,
            "createdAt": now,
        });

        let result = self.adapter.create("team", fields).await?;
        parse_team(&result)
    }

    /// Find a team by ID.
    pub async fn find_team_by_id(
        &self,
        id: &str,
    ) -> Result<Option<Team>, AdapterError> {
        match self.adapter.find_by_id("team", id).await {
            Ok(val) => Ok(Some(parse_team(&val)?)),
            Err(AdapterError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Update a team.
    pub async fn update_team(
        &self,
        id: &str,
        name: &str,
    ) -> Result<Team, AdapterError> {
        let updates = serde_json::json!({ "name": name });
        let result = self.adapter.update_by_id("team", id, updates).await?;
        parse_team(&result)
    }

    /// Delete a team.
    pub async fn delete_team(&self, id: &str) -> Result<(), AdapterError> {
        // Remove team assignments from members
        let member_filter = serde_json::json!([{ "field": "teamId", "value": id }]);
        let members = self.adapter.find_many("member", member_filter).await.unwrap_or_default();
        for member in &members {
            if let Some(mid) = member["id"].as_str() {
                let _ = self
                    .adapter
                    .update_by_id("member", mid, serde_json::json!({ "teamId": null }))
                    .await;
            }
        }
        self.adapter.delete_by_id("team", id).await
    }

    /// List teams in an organization.
    pub async fn list_teams(
        &self,
        organization_id: &str,
    ) -> Result<Vec<Team>, AdapterError> {
        let filter =
            serde_json::json!([{ "field": "organizationId", "value": organization_id }]);
        let rows = self.adapter.find_many("team", filter).await?;
        Ok(rows.iter().filter_map(|v| parse_team(v).ok()).collect())
    }

    /// Add a member to a team (update their teamId).
    pub async fn add_team_member(
        &self,
        member_id: &str,
        team_id: &str,
    ) -> Result<OrganizationMember, AdapterError> {
        let updates = serde_json::json!({ "teamId": team_id });
        let result = self
            .adapter
            .update_by_id("member", member_id, updates)
            .await?;
        parse_member(&result)
    }

    /// Remove a member from a team (clear their teamId).
    pub async fn remove_team_member(
        &self,
        member_id: &str,
    ) -> Result<OrganizationMember, AdapterError> {
        let updates = serde_json::json!({ "teamId": null });
        let result = self
            .adapter
            .update_by_id("member", member_id, updates)
            .await?;
        parse_member(&result)
    }

    // ─── Active organization ────────────────────────────────────────

    /// Set the active organization for a session.
    pub async fn set_active_organization(
        &self,
        session_token: &str,
        organization_id: Option<&str>,
    ) -> Result<(), AdapterError> {
        let org_value = match organization_id {
            Some(id) => Value::String(id.to_string()),
            None => Value::Null,
        };
        let filter = serde_json::json!([{ "field": "token", "value": session_token }]);
        match self.adapter.find_one("session", filter).await {
            Ok(session) => {
                if let Some(sid) = session["id"].as_str() {
                    self.adapter
                        .update_by_id(
                            "session",
                            sid,
                            serde_json::json!({ "activeOrganizationId": org_value }),
                        )
                        .await?;
                }
                Ok(())
            }
            Err(_) => Ok(()),
        }
    }

    /// Get the active organization for a session.
    pub async fn get_active_organization(
        &self,
        session_token: &str,
    ) -> Result<Option<Organization>, AdapterError> {
        let filter = serde_json::json!([{ "field": "token", "value": session_token }]);
        match self.adapter.find_one("session", filter).await {
            Ok(session) => {
                if let Some(org_id) = session["activeOrganizationId"].as_str() {
                    self.find_organization_by_id(org_id).await
                } else {
                    Ok(None)
                }
            }
            Err(_) => Ok(None),
        }
    }

    // ─── Dynamic Role CRUD ──────────────────────────────────────────

    /// Create a new dynamic organization role.
    pub async fn create_org_role(
        &self,
        data: &CreateOrgRoleData,
    ) -> Result<OrganizationRole, AdapterError> {
        let id = crate::crypto::random::generate_random_string(32);
        let now = chrono::Utc::now().to_rfc3339();
        let fields = serde_json::json!({
            "id": id,
            "organizationId": data.organization_id,
            "role": data.role,
            "permission": data.permission,
            "createdAt": now,
        });

        let result = self.adapter.create("organizationRole", fields).await?;
        parse_org_role(&result)
    }

    /// Find a dynamic role by ID.
    pub async fn find_org_role_by_id(
        &self,
        id: &str,
    ) -> Result<Option<OrganizationRole>, AdapterError> {
        match self.adapter.find_by_id("organizationRole", id).await {
            Ok(val) => Ok(Some(parse_org_role(&val)?)),
            Err(AdapterError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Find a dynamic role by name within an organization.
    pub async fn find_org_role_by_name(
        &self,
        organization_id: &str,
        role_name: &str,
    ) -> Result<Option<OrganizationRole>, AdapterError> {
        let filter = serde_json::json!([
            { "field": "organizationId", "value": organization_id },
            { "field": "role", "value": role_name }
        ]);
        match self.adapter.find_one("organizationRole", filter).await {
            Ok(val) => Ok(Some(parse_org_role(&val)?)),
            Err(AdapterError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Update a dynamic role's permissions.
    pub async fn update_org_role(
        &self,
        id: &str,
        permission: &str,
    ) -> Result<OrganizationRole, AdapterError> {
        let updates = serde_json::json!({ "permission": permission });
        let result = self
            .adapter
            .update_by_id("organizationRole", id, updates)
            .await?;
        parse_org_role(&result)
    }

    /// Delete a dynamic role.
    pub async fn delete_org_role(&self, id: &str) -> Result<(), AdapterError> {
        self.adapter.delete_by_id("organizationRole", id).await
    }

    /// List all dynamic roles for an organization.
    pub async fn list_org_roles(
        &self,
        organization_id: &str,
    ) -> Result<Vec<OrganizationRole>, AdapterError> {
        let filter =
            serde_json::json!([{ "field": "organizationId", "value": organization_id }]);
        let rows = self
            .adapter
            .find_many("organizationRole", filter)
            .await?;
        Ok(rows
            .iter()
            .filter_map(|v| parse_org_role(v).ok())
            .collect())
    }

    // ─── Additional query helpers ───────────────────────────────────

    /// Count the number of organizations a user belongs to.
    pub async fn count_user_organizations(
        &self,
        user_id: &str,
    ) -> Result<usize, AdapterError> {
        let filter = serde_json::json!([{ "field": "userId", "value": user_id }]);
        let members = self.adapter.find_many("member", filter).await?;
        // Deduplicate by organization_id
        let mut org_ids = std::collections::HashSet::new();
        for m in &members {
            if let Some(org_id) = m["organizationId"].as_str() {
                org_ids.insert(org_id.to_string());
            }
        }
        Ok(org_ids.len())
    }

    /// Count the number of members in an organization.
    pub async fn count_org_members(
        &self,
        organization_id: &str,
    ) -> Result<usize, AdapterError> {
        let filter =
            serde_json::json!([{ "field": "organizationId", "value": organization_id }]);
        let members = self.adapter.find_many("member", filter).await?;
        Ok(members.len())
    }

    /// Find all invitations for a specific email address.
    pub async fn find_invitations_by_email(
        &self,
        email: &str,
    ) -> Result<Vec<OrganizationInvitation>, AdapterError> {
        let filter = serde_json::json!([
            { "field": "email", "value": email },
            { "field": "status", "value": "pending" }
        ]);
        let rows = self.adapter.find_many("invitation", filter).await?;
        Ok(rows
            .iter()
            .filter_map(|v| parse_invitation(v).ok())
            .collect())
    }

    /// Delete an invitation by ID.
    pub async fn delete_invitation(&self, id: &str) -> Result<(), AdapterError> {
        self.adapter.delete_by_id("invitation", id).await
    }

    /// List team members (members with a specific teamId).
    pub async fn list_team_members(
        &self,
        team_id: &str,
    ) -> Result<Vec<OrganizationMember>, AdapterError> {
        let filter = serde_json::json!([{ "field": "teamId", "value": team_id }]);
        let rows = self.adapter.find_many("member", filter).await?;
        Ok(rows.iter().filter_map(|v| parse_member(v).ok()).collect())
    }
}

// ─── Parse helpers ──────────────────────────────────────────────────

fn parse_organization(value: &Value) -> Result<Organization, AdapterError> {
    Ok(Organization {
        id: value["id"]
            .as_str()
            .ok_or(AdapterError::Serialization("Missing org id".into()))?
            .to_string(),
        name: value["name"]
            .as_str()
            .ok_or(AdapterError::Serialization("Missing org name".into()))?
            .to_string(),
        slug: value["slug"]
            .as_str()
            .ok_or(AdapterError::Serialization("Missing org slug".into()))?
            .to_string(),
        logo: value["logo"].as_str().map(|s| s.to_string()),
        metadata: value["metadata"].as_str().map(|s| s.to_string()),
        created_at: value["createdAt"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    })
}

fn parse_member(value: &Value) -> Result<OrganizationMember, AdapterError> {
    Ok(OrganizationMember {
        id: value["id"]
            .as_str()
            .ok_or(AdapterError::Serialization("Missing member id".into()))?
            .to_string(),
        organization_id: value["organizationId"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        user_id: value["userId"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        role: value["role"]
            .as_str()
            .unwrap_or("member")
            .to_string(),
        team_id: value["teamId"].as_str().map(|s| s.to_string()),
        created_at: value["createdAt"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    })
}

fn parse_invitation(value: &Value) -> Result<OrganizationInvitation, AdapterError> {
    let status_str = value["status"].as_str().unwrap_or("pending");
    let status = InvitationStatus::from_str(status_str).unwrap_or(InvitationStatus::Pending);

    Ok(OrganizationInvitation {
        id: value["id"]
            .as_str()
            .ok_or(AdapterError::Serialization("Missing invitation id".into()))?
            .to_string(),
        organization_id: value["organizationId"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        email: value["email"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        role: value["role"]
            .as_str()
            .unwrap_or("member")
            .to_string(),
        status,
        inviter_id: value["inviterId"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        team_id: value["teamId"].as_str().map(|s| s.to_string()),
        expires_at: value["expiresAt"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    })
}

fn parse_team(value: &Value) -> Result<Team, AdapterError> {
    Ok(Team {
        id: value["id"]
            .as_str()
            .ok_or(AdapterError::Serialization("Missing team id".into()))?
            .to_string(),
        name: value["name"]
            .as_str()
            .ok_or(AdapterError::Serialization("Missing team name".into()))?
            .to_string(),
        organization_id: value["organizationId"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        created_at: value["createdAt"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    })
}

fn parse_org_role(value: &Value) -> Result<OrganizationRole, AdapterError> {
    Ok(OrganizationRole {
        id: value["id"]
            .as_str()
            .ok_or(AdapterError::Serialization("Missing role id".into()))?
            .to_string(),
        organization_id: value["organizationId"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        role: value["role"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        permission: value["permission"]
            .as_str()
            .unwrap_or("{}")
            .to_string(),
        created_at: value["createdAt"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    })
}

