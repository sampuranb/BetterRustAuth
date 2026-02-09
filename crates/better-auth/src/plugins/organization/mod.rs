// Organization plugin — multi-tenant organizations with teams, members, invitations.
//
// Maps to: packages/better-auth/src/plugins/organization/ (16 files, ~9,943 lines TS)
//
// This module re-exports the organization plugin from its submodule structure.
// The implementation is split into:
//   - types.rs:          Models, request/response types, options
//   - adapter.rs:        Database operations (OrgAdapter)
//   - helpers.rs:        Shared utilities (permissions, slugs, errors)
//   - routes_org.rs:     Organization CRUD handlers
//   - routes_members.rs: Member and invitation handlers
//   - routes_teams.rs:   Team CRUD handlers
//   - routes_access.rs:  Access control handlers

pub mod adapter;
pub mod handler_bridge;
pub mod helpers;
pub mod routes_access;
pub mod routes_members;
pub mod routes_org;
pub mod routes_teams;
pub mod types;

// Re-export key types for external use.
pub use helpers::{
    calculate_invitation_expiry, generate_slug, generate_unique_slug,
    has_org_permission, is_domain_allowed, is_invitation_expired,
    is_only_owner, is_predefined_role, org_error_message, resolve_roles,
    validate_role, OrgErrorCodes,
};
pub use routes_org::OrgRouteError;
pub use types::*;

use std::collections::HashMap;

use async_trait::async_trait;

use better_auth_core::db::schema::{AuthTable, SchemaField};
use better_auth_core::plugin::{BetterAuthPlugin, HttpMethod, PluginEndpoint};

use crate::plugins::access::default_org_roles;

// ── Schema ──────────────────────────────────────────────────────

/// Build the organization-related auth tables.
pub fn organization_tables(options: &OrganizationOptions) -> Vec<AuthTable> {
    let mut tables = vec![
        AuthTable {
            name: "organization".to_string(),
            fields: HashMap::from([
                ("id".to_string(), SchemaField::required_string()),
                ("name".to_string(), SchemaField::required_string()),
                ("slug".to_string(), SchemaField::required_string()),
                ("logo".to_string(), SchemaField::optional_string()),
                ("metadata".to_string(), SchemaField::optional_string()),
                ("createdAt".to_string(), SchemaField::required_string()),
            ]),
            order: None,
        },
        AuthTable {
            name: "member".to_string(),
            fields: HashMap::from([
                ("id".to_string(), SchemaField::required_string()),
                ("organizationId".to_string(), SchemaField::required_string()),
                ("userId".to_string(), SchemaField::required_string()),
                ("role".to_string(), SchemaField::required_string()),
                ("teamId".to_string(), SchemaField::optional_string()),
                ("createdAt".to_string(), SchemaField::required_string()),
            ]),
            order: None,
        },
        AuthTable {
            name: "invitation".to_string(),
            fields: HashMap::from([
                ("id".to_string(), SchemaField::required_string()),
                ("organizationId".to_string(), SchemaField::required_string()),
                ("email".to_string(), SchemaField::required_string()),
                ("role".to_string(), SchemaField::required_string()),
                ("status".to_string(), SchemaField::required_string()),
                ("inviterId".to_string(), SchemaField::required_string()),
                ("teamId".to_string(), SchemaField::optional_string()),
                ("expiresAt".to_string(), SchemaField::required_string()),
            ]),
            order: None,
        },
    ];

    if options.enable_teams {
        tables.push(AuthTable {
            name: "team".to_string(),
            fields: HashMap::from([
                ("id".to_string(), SchemaField::required_string()),
                ("name".to_string(), SchemaField::required_string()),
                ("organizationId".to_string(), SchemaField::required_string()),
                ("createdAt".to_string(), SchemaField::required_string()),
            ]),
            order: None,
        });
    }

    if options.enable_access_control {
        tables.push(AuthTable {
            name: "organizationRole".to_string(),
            fields: HashMap::from([
                ("id".to_string(), SchemaField::required_string()),
                ("organizationId".to_string(), SchemaField::required_string()),
                ("role".to_string(), SchemaField::required_string()),
                ("permission".to_string(), SchemaField::required_string()),
                ("createdAt".to_string(), SchemaField::required_string()),
            ]),
            order: None,
        });
    }

    tables
}

// ── Plugin ──────────────────────────────────────────────────────

/// Organization plugin.
#[derive(Debug)]
pub struct OrganizationPlugin {
    options: OrganizationOptions,
}

impl OrganizationPlugin {
    pub fn new(options: OrganizationOptions) -> Self {
        Self { options }
    }

    /// Access plugin options.
    pub fn options(&self) -> &OrganizationOptions {
        &self.options
    }

    /// Get the organization roles.
    pub fn roles(
        &self,
    ) -> HashMap<String, crate::plugins::access::Role> {
        self.options
            .roles
            .clone()
            .unwrap_or_else(default_org_roles)
    }
}

impl Default for OrganizationPlugin {
    fn default() -> Self {
        Self::new(OrganizationOptions::default())
    }
}

#[async_trait]
impl BetterAuthPlugin for OrganizationPlugin {
    fn id(&self) -> &str {
        "organization"
    }

    fn name(&self) -> &str {
        "Organization"
    }

    fn schema(&self) -> Vec<AuthTable> {
        organization_tables(&self.options)
    }

    fn additional_fields(
        &self,
    ) -> HashMap<String, HashMap<String, SchemaField>> {
        let mut fields = HashMap::new();
        let mut session_fields = HashMap::new();
        session_fields.insert(
            "activeOrganizationId".to_string(),
            SchemaField::optional_string(),
        );
        fields.insert("session".to_string(), session_fields);
        fields
    }

    fn endpoints(&self) -> Vec<PluginEndpoint> {
        use handler_bridge::*;
        let opts = self.options.clone();

        let mut endpoints = vec![
            // ── Org CRUD ────────────────────────────────────────────────
            PluginEndpoint::with_handler("/organization/create", HttpMethod::Post, true,
                create_organization_handler(opts.clone())),
            PluginEndpoint::with_handler("/organization/get-full-organization", HttpMethod::Get, true,
                get_full_organization_handler(opts.clone())),
            PluginEndpoint::with_handler("/organization/update", HttpMethod::Post, true,
                update_organization_handler(opts.clone())),
            PluginEndpoint::with_handler("/organization/delete", HttpMethod::Post, true,
                delete_organization_handler(opts.clone())),
            PluginEndpoint::with_handler("/organization/list", HttpMethod::Get, true,
                list_organizations_handler()),
            PluginEndpoint::with_handler("/organization/get-by-slug", HttpMethod::Get, true,
                get_by_slug_handler()),
            PluginEndpoint::with_handler("/organization/check-slug", HttpMethod::Post, true,
                check_slug_handler()),
            // ── Member management ───────────────────────────────────────
            PluginEndpoint::with_handler("/organization/invite-member", HttpMethod::Post, true,
                invite_member_handler(opts.clone())),
            PluginEndpoint::with_handler("/organization/accept-invitation", HttpMethod::Post, true,
                accept_invitation_handler()),
            PluginEndpoint::with_handler("/organization/reject-invitation", HttpMethod::Post, true,
                reject_invitation_handler()),
            PluginEndpoint::with_handler("/organization/cancel-invitation", HttpMethod::Post, true,
                cancel_invitation_handler(opts.clone())),
            PluginEndpoint::with_handler("/organization/get-invitation", HttpMethod::Get, false,
                get_invitation_handler()),
            PluginEndpoint::with_handler("/organization/remove-member", HttpMethod::Post, true,
                remove_member_handler(opts.clone())),
            PluginEndpoint::with_handler("/organization/update-member-role", HttpMethod::Post, true,
                update_member_role_handler(opts.clone())),
            PluginEndpoint::with_handler("/organization/leave", HttpMethod::Post, true,
                leave_organization_handler(opts.clone())),
            PluginEndpoint::with_handler("/organization/list-members", HttpMethod::Get, true,
                list_members_handler()),
            // ── Access control ──────────────────────────────────────────
            PluginEndpoint::with_handler("/organization/has-permission", HttpMethod::Post, true,
                has_permission_handler(opts.clone())),
            // ── Active organization ─────────────────────────────────────
            PluginEndpoint::with_handler("/organization/set-active", HttpMethod::Post, true,
                set_active_organization_handler()),
            PluginEndpoint::with_handler("/organization/get-active", HttpMethod::Get, true,
                get_active_organization_handler(opts.clone())),
            // ── Additional member/invitation endpoints ──────────────────
            PluginEndpoint::with_handler("/organization/list-invitations", HttpMethod::Get, true,
                list_invitations_handler()),
            PluginEndpoint::with_handler("/organization/list-user-invitations", HttpMethod::Get, true,
                list_user_invitations_handler()),
            PluginEndpoint::with_handler("/organization/get-active-member", HttpMethod::Get, true,
                get_active_member_handler()),
            PluginEndpoint::with_handler("/organization/get-active-member-role", HttpMethod::Get, true,
                get_active_member_role_handler(opts.clone())),
        ];

        // ── Team endpoints (conditional) ──────────────────────────────
        if self.options.enable_teams {
            endpoints.extend(vec![
                PluginEndpoint::with_handler("/organization/create-team", HttpMethod::Post, true,
                    create_team_handler(opts.clone())),
                PluginEndpoint::with_handler("/organization/update-team", HttpMethod::Post, true,
                    update_team_handler(opts.clone())),
                PluginEndpoint::with_handler("/organization/delete-team", HttpMethod::Post, true,
                    delete_team_handler(opts.clone())),
                PluginEndpoint::with_handler("/organization/list-teams", HttpMethod::Get, true,
                    list_teams_handler()),
                PluginEndpoint::with_handler("/organization/add-team-member", HttpMethod::Post, true,
                    add_team_member_handler(opts.clone())),
                PluginEndpoint::with_handler("/organization/remove-team-member", HttpMethod::Post, true,
                    remove_team_member_handler(opts.clone())),
                PluginEndpoint::with_handler("/organization/remove-team", HttpMethod::Post, true,
                    remove_team_handler(opts.clone())),
                PluginEndpoint::with_handler("/organization/set-active-team", HttpMethod::Post, true,
                    set_active_team_handler()),
                PluginEndpoint::with_handler("/organization/list-user-teams", HttpMethod::Get, true,
                    list_user_teams_handler()),
                PluginEndpoint::with_handler("/organization/list-team-members", HttpMethod::Get, true,
                    list_team_members_handler()),
            ]);
        }

        // ── Dynamic access control endpoints (conditional) ────────────
        if self.options.enable_access_control {
            endpoints.extend(vec![
                PluginEndpoint::with_handler("/organization/get-permissions", HttpMethod::Get, true,
                    get_permissions_handler(opts.clone())),
                PluginEndpoint::with_handler("/organization/check-permission", HttpMethod::Post, true,
                    check_permission_handler(opts.clone())),
                PluginEndpoint::with_handler("/organization/create-role", HttpMethod::Post, true,
                    create_role_handler(opts.clone())),
                PluginEndpoint::with_handler("/organization/delete-role", HttpMethod::Post, true,
                    delete_role_handler(opts.clone())),
                PluginEndpoint::with_handler("/organization/update-role", HttpMethod::Post, true,
                    update_role_handler(opts.clone())),
                PluginEndpoint::with_handler("/organization/list-roles", HttpMethod::Get, true,
                    list_roles_handler(opts.clone())),
                PluginEndpoint::with_handler("/organization/get-role", HttpMethod::Get, true,
                    get_role_handler(opts.clone())),
            ]);
        }

        endpoints
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_id() {
        let plugin = OrganizationPlugin::default();
        assert_eq!(plugin.id(), "organization");
    }

    #[test]
    fn test_plugin_name() {
        let plugin = OrganizationPlugin::default();
        assert_eq!(plugin.name(), "Organization");
    }

    #[test]
    fn test_base_endpoints() {
        let plugin = OrganizationPlugin::default();
        let endpoints = plugin.endpoints();
        assert_eq!(endpoints.len(), 19); // 19 base endpoints (added check-slug)
    }

    #[test]
    fn test_with_teams() {
        let plugin = OrganizationPlugin::new(OrganizationOptions {
            enable_teams: true,
            ..Default::default()
        });
        let endpoints = plugin.endpoints();
        assert_eq!(endpoints.len(), 25); // 19 base + 6 team
    }

    #[test]
    fn test_with_access_control() {
        let plugin = OrganizationPlugin::new(OrganizationOptions {
            enable_access_control: true,
            ..Default::default()
        });
        let endpoints = plugin.endpoints();
        assert_eq!(endpoints.len(), 26); // 19 base + 7 access (has-permission, check-permission, get-permissions, create/delete/update/list/get-role)
    }

    #[test]
    fn test_with_teams_and_access() {
        let plugin = OrganizationPlugin::new(OrganizationOptions {
            enable_teams: true,
            enable_access_control: true,
            ..Default::default()
        });
        let endpoints = plugin.endpoints();
        assert_eq!(endpoints.len(), 32); // 19 + 6 + 7
    }

    #[test]
    fn test_org_tables_without_teams() {
        let opts = OrganizationOptions::default();
        let tables = organization_tables(&opts);
        assert_eq!(tables.len(), 3);
        let names: Vec<&str> = tables.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"organization"));
        assert!(names.contains(&"member"));
        assert!(names.contains(&"invitation"));
    }

    #[test]
    fn test_org_tables_with_teams() {
        let opts = OrganizationOptions {
            enable_teams: true,
            ..Default::default()
        };
        let tables = organization_tables(&opts);
        assert_eq!(tables.len(), 4);
        let names: Vec<&str> = tables.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"team"));
    }

    #[test]
    fn test_generate_slug() {
        assert_eq!(generate_slug("My Organization"), "my-organization");
        assert_eq!(generate_slug("test--slug"), "test-slug");
        assert_eq!(generate_slug("UPPER CASE"), "upper-case");
        assert_eq!(generate_slug("a&b@c#d"), "a-b-c-d");
    }

    #[test]
    fn test_generate_unique_slug() {
        let slug = generate_unique_slug("My Org");
        assert!(slug.starts_with("my-org-"));
        assert!(slug.len() > "my-org-".len());
    }

    #[test]
    fn test_has_org_permission() {
        let roles = default_org_roles();
        assert!(has_org_permission("owner", "organization", "delete", &roles));
        assert!(!has_org_permission("member", "organization", "delete", &roles));
        assert!(has_org_permission("member", "organization", "read", &roles));
    }

    #[test]
    fn test_is_only_owner() {
        let members = vec![
            OrganizationMember {
                id: "m1".to_string(),
                organization_id: "org1".to_string(),
                user_id: "user1".to_string(),
                role: "owner".to_string(),
                team_id: None,
                created_at: chrono::Utc::now().to_rfc3339(),
            },
            OrganizationMember {
                id: "m2".to_string(),
                organization_id: "org1".to_string(),
                user_id: "user2".to_string(),
                role: "member".to_string(),
                team_id: None,
                created_at: chrono::Utc::now().to_rfc3339(),
            },
        ];

        assert!(is_only_owner(&members, "user1"));
        assert!(!is_only_owner(&members, "user2"));
    }

    #[test]
    fn test_is_only_owner_multiple_owners() {
        let members = vec![
            OrganizationMember {
                id: "m1".to_string(),
                organization_id: "org1".to_string(),
                user_id: "user1".to_string(),
                role: "owner".to_string(),
                team_id: None,
                created_at: chrono::Utc::now().to_rfc3339(),
            },
            OrganizationMember {
                id: "m2".to_string(),
                organization_id: "org1".to_string(),
                user_id: "user2".to_string(),
                role: "owner".to_string(),
                team_id: None,
                created_at: chrono::Utc::now().to_rfc3339(),
            },
        ];
        assert!(!is_only_owner(&members, "user1"));
    }

    #[test]
    fn test_invitation_status() {
        assert_eq!(InvitationStatus::Pending.as_str(), "pending");
        assert_eq!(InvitationStatus::Accepted.as_str(), "accepted");
        assert_eq!(InvitationStatus::Rejected.as_str(), "rejected");
        assert_eq!(InvitationStatus::Canceled.as_str(), "canceled");

        assert_eq!(
            InvitationStatus::from_str("pending"),
            Some(InvitationStatus::Pending)
        );
        assert_eq!(InvitationStatus::from_str("invalid"), None);
    }

    #[test]
    fn test_is_invitation_expired() {
        let yesterday =
            (chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339();
        assert!(is_invitation_expired(&yesterday));

        let tomorrow =
            (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339();
        assert!(!is_invitation_expired(&tomorrow));

        assert!(is_invitation_expired("not-a-date"));
    }

    #[test]
    fn test_calculate_invitation_expiry() {
        let expiry = calculate_invitation_expiry(DEFAULT_INVITATION_EXPIRY);
        assert!(!expiry.is_empty());
        assert!(chrono::DateTime::parse_from_rfc3339(&expiry).is_ok());
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(
            OrgErrorCodes::ORGANIZATION_NOT_FOUND,
            "ORGANIZATION_NOT_FOUND"
        );
        assert_eq!(OrgErrorCodes::MEMBER_NOT_FOUND, "MEMBER_NOT_FOUND");
    }

    #[test]
    fn test_error_messages() {
        assert!(org_error_message("ORGANIZATION_NOT_FOUND").contains("not found"));
        assert!(org_error_message("SLUG_ALREADY_EXISTS").contains("slug"));
    }

    #[test]
    fn test_default_options() {
        let opts = OrganizationOptions::default();
        assert!(!opts.enable_teams);
        assert!(opts.allow_user_to_create_org);
        assert_eq!(opts.default_member_role, "member");
        assert_eq!(opts.creator_role, "owner");
        assert_eq!(opts.invitation_expiry, 48 * 60 * 60);
        assert!(!opts.disable_organization_deletion);
    }

    #[test]
    fn test_plugin_roles() {
        let plugin = OrganizationPlugin::default();
        let roles = plugin.roles();
        assert!(roles.contains_key("owner"));
        assert!(roles.contains_key("admin"));
        assert!(roles.contains_key("member"));
    }

    #[test]
    fn test_additional_fields() {
        let plugin = OrganizationPlugin::default();
        let fields = plugin.additional_fields();
        assert!(fields.contains_key("session"));
        assert!(fields["session"].contains_key("activeOrganizationId"));
    }

    #[test]
    fn test_org_model_serde() {
        let org = Organization {
            id: "org1".to_string(),
            name: "Test Org".to_string(),
            slug: "test-org".to_string(),
            logo: None,
            metadata: Some("{\"key\":\"value\"}".to_string()),
            created_at: chrono::Utc::now().to_rfc3339(),
        };

        let json = serde_json::to_string(&org).unwrap();
        let parsed: Organization = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "org1");
        assert_eq!(parsed.name, "Test Org");
        assert_eq!(parsed.slug, "test-org");
    }

    #[test]
    fn test_full_organization_serde() {
        let full = FullOrganization {
            id: "org1".to_string(),
            name: "Test".to_string(),
            slug: "test".to_string(),
            logo: None,
            metadata: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            members: vec![],
            invitations: vec![],
            teams: None,
        };
        let json = serde_json::to_string(&full).unwrap();
        assert!(!json.contains("teams")); // Skipped when None
    }
}
