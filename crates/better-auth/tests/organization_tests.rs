//! Organization plugin integration tests.
//!
//! Covers: types, helpers, roles, permissions, slug generation,
//! invitation status, serde round-trips, options, request/response validation.

#[cfg(feature = "organization")]
mod org_type_tests {
    use better_auth::plugins::organization::types::*;
    use serde_json::json;

    // ── Organization struct ─────────────────────────────────────────

    #[test]
    fn org_serialize() {
        let org = Organization {
            id: "org-1".into(),
            name: "Acme Inc".into(),
            slug: "acme-inc".into(),
            logo: Some("https://example.com/logo.png".into()),
            metadata: None,
            created_at: "2024-01-01T00:00:00Z".into(),
        };
        let v = serde_json::to_value(&org).unwrap();
        assert_eq!(v["name"], "Acme Inc");
        assert_eq!(v["slug"], "acme-inc");
        assert!(v["logo"].is_string());
    }

    #[test]
    fn org_deserialize_full() {
        let v = json!({
            "id": "org-1",
            "name": "Test Org",
            "slug": "test-org",
            "logo": null,
            "metadata": null,
            "createdAt": "2024-01-01T00:00:00Z"
        });
        let org: Organization = serde_json::from_value(v).unwrap();
        assert_eq!(org.id, "org-1");
        assert_eq!(org.name, "Test Org");
        assert!(org.logo.is_none());
    }

    #[test]
    fn org_deserialize_minimal() {
        let v = json!({
            "id": "org-2",
            "name": "Minimal",
            "slug": "minimal",
            "createdAt": "2024-01-01T00:00:00Z"
        });
        let org: Organization = serde_json::from_value(v).unwrap();
        assert_eq!(org.slug, "minimal");
    }

    // ── Member struct ───────────────────────────────────────────────

    #[test]
    fn member_serde_round_trip() {
        let m = OrganizationMember {
            id: "mem-1".into(),
            organization_id: "org-1".into(),
            user_id: "user-1".into(),
            role: "admin".into(),
            created_at: "2024-01-01T00:00:00Z".into(),
        };
        let json_str = serde_json::to_string(&m).unwrap();
        let parsed: OrganizationMember = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.id, "mem-1");
        assert_eq!(parsed.role, "admin");
    }

    // ── Invitation struct ───────────────────────────────────────────

    #[test]
    fn invitation_status_serialize() {
        assert_eq!(
            serde_json::to_value(&InvitationStatus::Pending).unwrap(),
            json!("pending")
        );
        assert_eq!(
            serde_json::to_value(&InvitationStatus::Accepted).unwrap(),
            json!("accepted")
        );
        assert_eq!(
            serde_json::to_value(&InvitationStatus::Rejected).unwrap(),
            json!("rejected")
        );
        assert_eq!(
            serde_json::to_value(&InvitationStatus::Canceled).unwrap(),
            json!("canceled")
        );
    }

    #[test]
    fn invitation_status_as_str() {
        assert_eq!(InvitationStatus::Pending.as_str(), "pending");
        assert_eq!(InvitationStatus::Accepted.as_str(), "accepted");
        assert_eq!(InvitationStatus::Rejected.as_str(), "rejected");
        assert_eq!(InvitationStatus::Canceled.as_str(), "canceled");
    }

    #[test]
    fn invitation_status_from_str() {
        assert_eq!(InvitationStatus::from_str("pending"), Some(InvitationStatus::Pending));
        assert_eq!(InvitationStatus::from_str("accepted"), Some(InvitationStatus::Accepted));
        assert_eq!(InvitationStatus::from_str("rejected"), Some(InvitationStatus::Rejected));
        assert_eq!(InvitationStatus::from_str("canceled"), Some(InvitationStatus::Canceled));
        assert_eq!(InvitationStatus::from_str("unknown"), None);
        assert_eq!(InvitationStatus::from_str(""), None);
    }

    #[test]
    fn invitation_status_equality() {
        assert_eq!(InvitationStatus::Pending, InvitationStatus::Pending);
        assert_ne!(InvitationStatus::Pending, InvitationStatus::Accepted);
    }

    #[test]
    fn invitation_serde() {
        let inv = OrganizationInvitation {
            id: "inv-1".into(),
            organization_id: "org-1".into(),
            email: "test@example.com".into(),
            role: "member".into(),
            status: InvitationStatus::Pending,
            inviter_id: "user-1".into(),
            expires_at: "2024-12-31T23:59:59Z".into(),
            created_at: "2024-01-01T00:00:00Z".into(),
            team_id: None,
        };
        let v = serde_json::to_value(&inv).unwrap();
        assert_eq!(v["email"], "test@example.com");
        assert_eq!(v["status"], "pending");
        assert!(v["teamId"].is_null());
    }

    #[test]
    fn invitation_with_team() {
        let inv = OrganizationInvitation {
            id: "inv-2".into(),
            organization_id: "org-1".into(),
            email: "team@example.com".into(),
            role: "member".into(),
            status: InvitationStatus::Pending,
            inviter_id: "user-1".into(),
            expires_at: "2024-12-31T23:59:59Z".into(),
            created_at: "2024-01-01T00:00:00Z".into(),
            team_id: Some("team-1".into()),
        };
        let v = serde_json::to_value(&inv).unwrap();
        assert_eq!(v["teamId"], "team-1");
    }

    // ── Team struct ─────────────────────────────────────────────────

    #[test]
    fn team_serde() {
        let t = Team {
            id: "team-1".into(),
            name: "Engineering".into(),
            organization_id: "org-1".into(),
            created_at: "2024-01-01T00:00:00Z".into(),
        };
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["name"], "Engineering");
    }

    // ── FullOrganization struct ──────────────────────────────────────

    #[test]
    fn full_org_serde() {
        let full = FullOrganization {
            id: "org-1".into(),
            name: "Full Org".into(),
            slug: "full-org".into(),
            logo: None,
            metadata: None,
            created_at: "2024-01-01T00:00:00Z".into(),
            members: vec![],
            invitations: vec![],
            teams: None,
        };
        let v = serde_json::to_value(&full).unwrap();
        assert!(v["members"].as_array().unwrap().is_empty());
        assert!(v["teams"].is_null());
    }

    // ── Request types ───────────────────────────────────────────────

    #[test]
    fn create_org_request_deser() {
        let v = json!({
            "name": "New Org",
            "slug": "new-org"
        });
        let req: CreateOrganizationRequest = serde_json::from_value(v).unwrap();
        assert_eq!(req.name, "New Org");
        assert_eq!(req.slug, "new-org");
    }

    #[test]
    fn update_org_request_deser() {
        let v = json!({
            "organizationId": "org-1",
            "data": { "name": "Updated Name" }
        });
        let req: UpdateOrganizationRequest = serde_json::from_value(v).unwrap();
        assert_eq!(req.organization_id, "org-1");
    }

    #[test]
    fn delete_org_request_deser() {
        let v = json!({ "organizationId": "org-1" });
        let req: DeleteOrganizationRequest = serde_json::from_value(v).unwrap();
        assert_eq!(req.organization_id, "org-1");
    }

    #[test]
    fn set_active_org_request_deser() {
        let v = json!({ "organizationId": "org-1" });
        let req: SetActiveOrganizationRequest = serde_json::from_value(v).unwrap();
        assert_eq!(req.organization_id, "org-1");
    }

    #[test]
    fn invite_member_request_deser() {
        let v = json!({
            "organizationId": "org-1",
            "email": "user@example.com",
            "role": "member"
        });
        let req: InviteMemberRequest = serde_json::from_value(v).unwrap();
        assert_eq!(req.email, "user@example.com");
        assert_eq!(req.role, "member");
    }

    #[test]
    fn invite_member_request_with_team() {
        let v = json!({
            "organizationId": "org-1",
            "email": "user@example.com",
            "role": "member",
            "teamId": "team-1"
        });
        let req: InviteMemberRequest = serde_json::from_value(v).unwrap();
        assert_eq!(req.team_id, Some("team-1".into()));
    }

    // ── OrganizationRole ────────────────────────────────────────────

    #[test]
    fn org_role_serde() {
        let role = OrganizationRole {
            id: "role-1".into(),
            organization_id: Some("org-1".into()),
            name: "custom-role".into(),
            permissions: vec!["read".into(), "write".into()],
            is_default: false,
            created_at: "2024-01-01T00:00:00Z".into(),
        };
        let v = serde_json::to_value(&role).unwrap();
        assert_eq!(v["permissions"].as_array().unwrap().len(), 2);
    }

    // ── OrganizationOptions ─────────────────────────────────────────

    #[test]
    fn org_options_default() {
        let opts = OrganizationOptions::default();
        assert!(opts.allow_user_to_create_org);
        assert!(!opts.organization_limit.is_some() || opts.organization_limit == Some(0));
        assert!(!opts.creator_role.is_empty());
        assert!(!opts.member_role.is_empty());
    }

    #[test]
    fn org_options_custom() {
        let mut opts = OrganizationOptions::default();
        opts.allow_user_to_create_org = false;
        opts.organization_limit = Some(5);
        opts.creator_role = "owner".into();
        opts.member_role = "viewer".into();
        assert!(!opts.allow_user_to_create_org);
        assert_eq!(opts.organization_limit, Some(5));
    }
}

#[cfg(feature = "organization")]
mod org_helper_tests {
    use better_auth::plugins::organization::helpers::*;

    #[test]
    fn generate_slug_from_name() {
        assert_eq!(generate_slug("Acme Inc"), "acme-inc");
    }

    #[test]
    fn generate_slug_special_chars() {
        assert_eq!(generate_slug("Hello World! @2024"), "hello-world-2024");
    }

    #[test]
    fn generate_slug_unicode() {
        let slug = generate_slug("über cool");
        assert!(!slug.is_empty());
        assert!(slug.chars().all(|c| c.is_ascii_lowercase() || c == '-'));
    }

    #[test]
    fn generate_slug_empty() {
        let slug = generate_slug("");
        // Should still generate something or be empty
        assert!(slug.is_empty() || slug.chars().all(|c| c.is_ascii_lowercase() || c == '-'));
    }

    #[test]
    fn generate_slug_consecutive_spaces() {
        let slug = generate_slug("Hello    World");
        assert!(!slug.contains("--"));
    }
}

#[cfg(feature = "organization")]
mod org_access_tests {
    use better_auth::plugins::organization::helpers::*;

    #[test]
    fn default_roles_exist() {
        let roles = default_roles();
        assert!(roles.contains_key("owner"));
        assert!(roles.contains_key("admin"));
        assert!(roles.contains_key("member"));
    }

    #[test]
    fn owner_has_all_permissions() {
        let roles = default_roles();
        let owner_perms = &roles["owner"];
        assert!(owner_perms.contains(&"*".to_string()) || owner_perms.len() > 5);
    }

    #[test]
    fn member_has_limited_permissions() {
        let roles = default_roles();
        let member_perms = &roles["member"];
        let owner_perms = &roles["owner"];
        assert!(member_perms.len() <= owner_perms.len());
    }

    #[test]
    fn role_hierarchy_owner_above_admin() {
        let hierarchy = role_hierarchy();
        assert!(hierarchy["owner"] > hierarchy["admin"]);
        assert!(hierarchy["admin"] > hierarchy["member"]);
    }

    #[test]
    fn has_permission_owner_wildcard() {
        assert!(check_role_permission("owner", "organization:delete", &default_roles()));
    }

    #[test]
    fn has_permission_member_limited() {
        // Members should NOT be able to delete organizations
        assert!(!check_role_permission("member", "organization:delete", &default_roles()));
    }

    #[test]
    fn has_permission_unknown_role() {
        assert!(!check_role_permission("nonexistent", "anything", &default_roles()));
    }

    #[test]
    fn invitation_expired_past() {
        assert!(is_invitation_expired("2020-01-01T00:00:00Z"));
    }

    #[test]
    fn invitation_not_expired_future() {
        assert!(!is_invitation_expired("2099-12-31T23:59:59Z"));
    }

    #[test]
    fn invitation_expiry_default_duration() {
        let expires = default_invitation_expiry();
        // Should be in the future
        assert!(!is_invitation_expired(&expires));
    }
}
