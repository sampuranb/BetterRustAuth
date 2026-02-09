//! Passkey plugin integration tests.
//!
//! Covers: configuration, RP ID resolution, authenticator selection,
//! type serialization/deserialization, schema, and error types.

use better_auth_passkey::*;
use serde_json::json;

// ── PasskeyOptions ──────────────────────────────────────────────

#[test]
fn passkey_options_default_values() {
    let opts = PasskeyOptions::default();
    assert!(opts.rp_id.is_none());
    assert!(opts.rp_name.is_none());
    assert!(opts.origin.is_none());
    assert!(opts.authenticator_selection.is_none());
    assert_eq!(opts.challenge_cookie, "better-auth-passkey");
}

#[test]
fn passkey_options_custom_rp_id() {
    let opts = PasskeyOptions {
        rp_id: Some("auth.example.com".into()),
        rp_name: Some("My App".into()),
        ..Default::default()
    };
    assert_eq!(opts.rp_id.unwrap(), "auth.example.com");
    assert_eq!(opts.rp_name.unwrap(), "My App");
}

#[test]
fn passkey_options_custom_origins() {
    let opts = PasskeyOptions {
        origin: Some(vec![
            "https://example.com".into(),
            "https://app.example.com".into(),
        ]),
        ..Default::default()
    };
    assert_eq!(opts.origin.as_ref().unwrap().len(), 2);
}

// ── RP ID resolution ────────────────────────────────────────────

#[test]
fn rp_id_from_https_url() {
    let opts = PasskeyOptions::default();
    assert_eq!(get_rp_id(&opts, "https://example.com/api/auth"), "example.com");
}

#[test]
fn rp_id_from_localhost() {
    let opts = PasskeyOptions::default();
    assert_eq!(get_rp_id(&opts, "http://localhost:3000"), "localhost");
}

#[test]
fn rp_id_custom_override() {
    let opts = PasskeyOptions {
        rp_id: Some("custom-rp.example.com".into()),
        ..Default::default()
    };
    assert_eq!(get_rp_id(&opts, "https://other.com"), "custom-rp.example.com");
}

#[test]
fn rp_id_from_invalid_url() {
    let opts = PasskeyOptions::default();
    assert_eq!(get_rp_id(&opts, "not-a-url"), "localhost");
}

#[test]
fn rp_id_with_subdomain() {
    let opts = PasskeyOptions::default();
    assert_eq!(get_rp_id(&opts, "https://auth.app.example.com"), "auth.app.example.com");
}

// ── AuthenticatorSelection ──────────────────────────────────────

#[test]
fn authenticator_selection_defaults() {
    let sel = AuthenticatorSelection::default();
    assert_eq!(sel.resident_key, Some("preferred".to_string()));
    assert_eq!(sel.user_verification, Some("preferred".to_string()));
    assert!(sel.authenticator_attachment.is_none());
    assert!(sel.require_resident_key.is_none());
}

#[test]
fn authenticator_selection_serialize() {
    let sel = AuthenticatorSelection {
        authenticator_attachment: Some("platform".into()),
        require_resident_key: Some(true),
        resident_key: Some("required".into()),
        user_verification: Some("required".into()),
    };
    let v = serde_json::to_value(&sel).unwrap();
    assert_eq!(v["authenticator_attachment"], "platform");
    assert_eq!(v["require_resident_key"], true);
}

#[test]
fn authenticator_selection_skip_none() {
    let sel = AuthenticatorSelection::default();
    let json_str = serde_json::to_string(&sel).unwrap();
    assert!(!json_str.contains("authenticator_attachment"));
    assert!(!json_str.contains("require_resident_key"));
}

// ── Passkey types ───────────────────────────────────────────────

#[test]
fn passkey_type_serde() {
    let v = json!({
        "id": "pk-1",
        "name": "My Key",
        "public_key": "MFkwEwYH...",
        "user_id": "user-1",
        "credential_id": "cred-abc",
        "counter": 42,
        "device_type": "platform",
        "backed_up": true,
        "transports": "internal",
        "created_at": "2024-01-01T00:00:00Z"
    });
    let pk: types::Passkey = serde_json::from_value(v).unwrap();
    assert_eq!(pk.id, "pk-1");
    assert_eq!(pk.counter, 42);
    assert!(pk.backed_up);
}

#[test]
fn passkey_type_minimal() {
    let v = json!({
        "id": "pk-2",
        "public_key": "key",
        "user_id": "u1",
        "credential_id": "c1",
        "counter": 0,
        "device_type": "cross-platform",
        "backed_up": false,
        "created_at": "2024-01-01T00:00:00Z"
    });
    let pk: types::Passkey = serde_json::from_value(v).unwrap();
    assert!(pk.name.is_none());
    assert!(pk.transports.is_none());
    assert!(pk.aaguid.is_none());
}

#[test]
fn registration_options_serde() {
    let opts = types::RegistrationOptions {
        challenge: "random-challenge".into(),
        rp: types::RelyingParty {
            name: "Test App".into(),
            id: "example.com".into(),
        },
        user: types::PublicKeyUser {
            id: "user-1".into(),
            name: "test@example.com".into(),
            display_name: "Test User".into(),
        },
        timeout: Some(60000),
        attestation: Some("none".into()),
        exclude_credentials: None,
        authenticator_selection: None,
        pub_key_cred_params: Some(vec![
            types::PubKeyCredParam {
                cred_type: "public-key".into(),
                alg: -7,
            },
        ]),
    };
    let v = serde_json::to_value(&opts).unwrap();
    assert_eq!(v["challenge"], "random-challenge");
    assert_eq!(v["rp"]["id"], "example.com");
    assert_eq!(v["timeout"], 60000);
}

#[test]
fn authentication_options_serde() {
    let opts = types::AuthenticationOptions {
        challenge: "auth-challenge".into(),
        timeout: Some(30000),
        rp_id: "example.com".into(),
        allow_credentials: Some(vec![
            types::CredentialDescriptor {
                id: "cred-1".into(),
                cred_type: "public-key".into(),
                transports: Some(vec!["internal".into(), "usb".into()]),
            },
        ]),
        user_verification: Some("preferred".into()),
    };
    let v = serde_json::to_value(&opts).unwrap();
    assert_eq!(v["rp_id"], "example.com");
    assert_eq!(v["allow_credentials"].as_array().unwrap().len(), 1);
}

// ── Constants ───────────────────────────────────────────────────

#[test]
fn max_age_is_five_minutes() {
    assert_eq!(MAX_AGE_IN_SECONDS, 300);
}
