//! SCIM 2.0 plugin integration tests.
//!
//! Covers: filter parsing, filter matching, patch operations,
//! type serialization, config, schema, and error types.

use better_auth_scim::*;
use better_auth_scim::filter::*;
use better_auth_scim::patch::*;
use serde_json::json;

// ── Filter parsing ──────────────────────────────────────────────

#[test]
fn parse_eq_filter() {
    let f = parse_filter(r#"userName eq "john""#).unwrap();
    assert_eq!(f, ScimFilter::Eq("userName".into(), "john".into()));
}

#[test]
fn parse_ne_filter() {
    let f = parse_filter(r#"active ne "false""#).unwrap();
    assert_eq!(f, ScimFilter::Ne("active".into(), "false".into()));
}

#[test]
fn parse_co_filter() {
    let f = parse_filter(r#"email co "example""#).unwrap();
    assert_eq!(f, ScimFilter::Co("email".into(), "example".into()));
}

#[test]
fn parse_sw_filter() {
    let f = parse_filter(r#"userName sw "J""#).unwrap();
    assert_eq!(f, ScimFilter::Sw("userName".into(), "J".into()));
}

#[test]
fn parse_ew_filter() {
    let f = parse_filter(r#"email ew ".com""#).unwrap();
    assert_eq!(f, ScimFilter::Ew("email".into(), ".com".into()));
}

#[test]
fn parse_pr_filter() {
    let f = parse_filter("emails pr").unwrap();
    assert_eq!(f, ScimFilter::Pr("emails".into()));
}

#[test]
fn parse_and_filter() {
    let f = parse_filter(r#"userName eq "john" and active eq "true""#).unwrap();
    match f {
        ScimFilter::And(left, right) => {
            assert_eq!(*left, ScimFilter::Eq("userName".into(), "john".into()));
            assert_eq!(*right, ScimFilter::Eq("active".into(), "true".into()));
        }
        _ => panic!("Expected And filter"),
    }
}

#[test]
fn parse_or_filter() {
    let f = parse_filter(r#"userName eq "john" or userName eq "jane""#).unwrap();
    match f {
        ScimFilter::Or(_, _) => {}
        _ => panic!("Expected Or filter"),
    }
}

#[test]
fn parse_empty_returns_none() {
    assert!(parse_filter("").is_none());
    assert!(parse_filter("   ").is_none());
}

#[test]
fn parse_invalid_returns_none() {
    assert!(parse_filter("just_a_word").is_none());
    assert!(parse_filter("invalid operator value").is_none());
}

// ── Filter matching ─────────────────────────────────────────────

#[test]
fn matches_eq_case_insensitive() {
    let user = json!({"userName": "John"});
    let filter = ScimFilter::Eq("userName".into(), "john".into());
    assert!(matches_filter(&user, &filter));
}

#[test]
fn matches_eq_no_match() {
    let user = json!({"userName": "Jane"});
    let filter = ScimFilter::Eq("userName".into(), "john".into());
    assert!(!matches_filter(&user, &filter));
}

#[test]
fn matches_ne() {
    let user = json!({"userName": "John"});
    let filter = ScimFilter::Ne("userName".into(), "jane".into());
    assert!(matches_filter(&user, &filter));
}

#[test]
fn matches_co_substring() {
    let user = json!({"email": "john.doe@example.com"});
    let filter = ScimFilter::Co("email".into(), "doe".into());
    assert!(matches_filter(&user, &filter));
}

#[test]
fn matches_sw_prefix() {
    let user = json!({"userName": "john.doe"});
    let filter = ScimFilter::Sw("userName".into(), "john".into());
    assert!(matches_filter(&user, &filter));
}

#[test]
fn matches_ew_suffix() {
    let user = json!({"email": "john@example.com"});
    let filter = ScimFilter::Ew("email".into(), ".com".into());
    assert!(matches_filter(&user, &filter));
}

#[test]
fn matches_pr_present() {
    let user = json!({"userName": "john", "email": "john@example.com"});
    assert!(matches_filter(&user, &ScimFilter::Pr("email".into())));
}

#[test]
fn matches_pr_not_present() {
    let user = json!({"userName": "john"});
    assert!(!matches_filter(&user, &ScimFilter::Pr("phone".into())));
}

#[test]
fn matches_and_both_true() {
    let user = json!({"userName": "john", "active": "true"});
    let filter = ScimFilter::And(
        Box::new(ScimFilter::Eq("userName".into(), "john".into())),
        Box::new(ScimFilter::Eq("active".into(), "true".into())),
    );
    assert!(matches_filter(&user, &filter));
}

#[test]
fn matches_and_one_false() {
    let user = json!({"userName": "john", "active": "false"});
    let filter = ScimFilter::And(
        Box::new(ScimFilter::Eq("userName".into(), "john".into())),
        Box::new(ScimFilter::Eq("active".into(), "true".into())),
    );
    assert!(!matches_filter(&user, &filter));
}

#[test]
fn matches_or_one_true() {
    let user = json!({"userName": "john"});
    let filter = ScimFilter::Or(
        Box::new(ScimFilter::Eq("userName".into(), "john".into())),
        Box::new(ScimFilter::Eq("userName".into(), "jane".into())),
    );
    assert!(matches_filter(&user, &filter));
}

#[test]
fn matches_not_inverts() {
    let user = json!({"userName": "john"});
    let filter = ScimFilter::Not(
        Box::new(ScimFilter::Eq("userName".into(), "jane".into())),
    );
    assert!(matches_filter(&user, &filter));
}

#[test]
fn matches_missing_field_eq_false() {
    let user = json!({"userName": "john"});
    let filter = ScimFilter::Eq("nonexistent".into(), "value".into());
    assert!(!matches_filter(&user, &filter));
}

#[test]
fn matches_missing_field_ne_true() {
    let user = json!({"userName": "john"});
    let filter = ScimFilter::Ne("nonexistent".into(), "value".into());
    assert!(matches_filter(&user, &filter));
}

// ── Patch operations ────────────────────────────────────────────

#[test]
fn parse_patch_add() {
    let v = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "add",
                "path": "emails",
                "value": [{"value": "new@example.com"}]
            }
        ]
    });
    let req: PatchRequest = serde_json::from_value(v).unwrap();
    assert_eq!(req.operations.len(), 1);
    assert_eq!(req.operations[0].op, PatchOp::Add);
}

#[test]
fn parse_patch_replace() {
    let v = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "replace",
                "path": "displayName",
                "value": "New Name"
            }
        ]
    });
    let req: PatchRequest = serde_json::from_value(v).unwrap();
    assert_eq!(req.operations[0].op, PatchOp::Replace);
}

#[test]
fn parse_patch_remove() {
    let v = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "remove",
                "path": "emails[type eq \"work\"]"
            }
        ]
    });
    let req: PatchRequest = serde_json::from_value(v).unwrap();
    assert_eq!(req.operations[0].op, PatchOp::Remove);
    assert!(req.operations[0].value.is_none());
}

// ── Apply patch ─────────────────────────────────────────────────

#[test]
fn apply_patch_add_field() {
    let mut target = json!({"name": "John"});
    let op = PatchOperation {
        op: PatchOp::Add,
        path: Some("email".into()),
        value: Some(json!("john@example.com")),
    };
    apply_patch(&mut target, &op).unwrap();
    assert_eq!(target["email"], "john@example.com");
}

#[test]
fn apply_patch_replace_field() {
    let mut target = json!({"active": true});
    let op = PatchOperation {
        op: PatchOp::Replace,
        path: Some("active".into()),
        value: Some(json!(false)),
    };
    apply_patch(&mut target, &op).unwrap();
    assert_eq!(target["active"], false);
}

#[test]
fn apply_patch_remove_field() {
    let mut target = json!({"name": "John", "email": "john@example.com"});
    let op = PatchOperation {
        op: PatchOp::Remove,
        path: Some("email".into()),
        value: None,
    };
    apply_patch(&mut target, &op).unwrap();
    assert!(target.get("email").is_none());
}

// ── SCIM types ──────────────────────────────────────────────────

#[test]
fn scim_user_round_trip() {
    let user = ScimUser {
        schemas: vec![SCHEMA_USER.into()],
        id: "user-1".into(),
        user_name: "john@example.com".into(),
        name: Some(ScimName {
            formatted: Some("John Doe".into()),
            given_name: Some("John".into()),
            family_name: Some("Doe".into()),
        }),
        display_name: Some("John Doe".into()),
        emails: Some(vec![ScimEmail {
            value: "john@example.com".into(),
            email_type: Some("work".into()),
            primary: Some(true),
        }]),
        active: Some(true),
        groups: None,
        external_id: None,
        meta: Meta {
            resource_type: "User".into(),
            created: chrono::Utc::now(),
            last_modified: chrono::Utc::now(),
            location: None,
            version: None,
        },
    };
    let json = serde_json::to_value(&user).unwrap();
    assert_eq!(json["userName"], "john@example.com");

    let parsed: ScimUser = serde_json::from_value(json).unwrap();
    assert_eq!(parsed.id, "user-1");
}

#[test]
fn list_response_creation() {
    let resp = ListResponse::new(
        vec![json!({"id": "1"}), json!({"id": "2"})],
        42,
        1,
        10,
    );
    assert_eq!(resp.total_results, 42);
    assert_eq!(resp.resources.len(), 2);
    assert_eq!(resp.start_index, 1);
    assert_eq!(resp.items_per_page, 10);
}

#[test]
fn scim_error_response_creation() {
    let resp = ScimErrorResponse::new(404, Some("resourceNotFound"), "Resource not found");
    assert_eq!(resp.status, "404");
    assert_eq!(resp.scim_type, Some("resourceNotFound".into()));
}

// ── Config ──────────────────────────────────────────────────────

#[test]
fn scim_options_default() {
    let opts = ScimOptions::default();
    assert_eq!(opts.scim_base_path, "/scim/v2");
    assert_eq!(opts.max_results, 200);
    assert!(opts.auto_provision);
    assert!(opts.auto_deprovision);
}

#[test]
fn service_provider_config_default() {
    let spc = ServiceProviderConfig::default();
    assert!(spc.patch.supported);
    assert!(!spc.bulk.supported);
    assert!(spc.filter.supported);
    assert_eq!(spc.filter.max_results, 200);
}

// ── Error types ─────────────────────────────────────────────────

#[test]
fn scim_error_display() {
    let err = ScimError::Unauthorized;
    assert!(!format!("{}", err).is_empty());
}

#[test]
fn scim_error_resource_not_found() {
    let err = ScimError::ResourceNotFound;
    assert_eq!(err.status(), 404);
    assert_eq!(err.scim_type(), "resourceNotFound");
}

#[test]
fn scim_error_invalid_filter() {
    let err = ScimError::InvalidFilter;
    assert_eq!(err.status(), 400);
}

#[test]
fn scim_error_uniqueness() {
    let err = ScimError::Uniqueness;
    assert_eq!(err.status(), 409);
}
