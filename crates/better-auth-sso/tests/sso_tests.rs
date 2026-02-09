//! SSO/SAML plugin integration tests.
//!
//! Covers: SAML request/response, config, types, attribute mapping,
//! SP metadata, redirect URL, error types.

use better_auth_sso::*;
use std::collections::HashMap;

// ── SsoOptions ──────────────────────────────────────────────────

#[test]
fn sso_options_default() {
    let opts = SsoOptions::default();
    assert!(opts.auto_create_user);
    assert!(opts.auto_link_by_email);
    assert!(!opts.allow_idp_initiated);
}

#[test]
fn sso_options_custom() {
    let opts = SsoOptions {
        sp_entity_id: Some("https://sp.example.com".into()),
        allow_idp_initiated: true,
        ..Default::default()
    };
    assert_eq!(opts.sp_entity_id, Some("https://sp.example.com".into()));
    assert!(opts.allow_idp_initiated);
}

// ── AttributeMapping ────────────────────────────────────────────

#[test]
fn attribute_mapping_default() {
    let mapping = types::AttributeMapping::default();
    assert!(mapping.email.contains("emailaddress"));
    assert!(mapping.name.is_some());
    assert!(mapping.first_name.is_some());
    assert!(mapping.last_name.is_some());
    assert!(mapping.image.is_none());
}

#[test]
fn attribute_mapping_custom() {
    let mapping = types::AttributeMapping {
        email: "urn:custom:email".into(),
        name: Some("urn:custom:name".into()),
        first_name: None,
        last_name: None,
        image: None,
    };
    assert_eq!(mapping.email, "urn:custom:email");
    assert!(mapping.first_name.is_none());
}

// ── SsoConnection ───────────────────────────────────────────────

#[test]
fn sso_connection_serde_round_trip() {
    let conn = types::SsoConnection {
        id: "conn-1".into(),
        organization_id: Some("org-1".into()),
        provider: types::SsoProvider::Saml,
        domain: "example.com".into(),
        enabled: true,
        idp_metadata_url: None,
        idp_entity_id: Some("https://idp.example.com".into()),
        idp_sso_url: Some("https://idp.example.com/sso".into()),
        idp_certificate: Some("MIIC...".into()),
        sp_entity_id: "https://sp.example.com".into(),
        sp_acs_url: "https://sp.example.com/sso/callback".into(),
        attribute_mapping: types::AttributeMapping::default(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let json = serde_json::to_value(&conn).unwrap();
    let parsed: types::SsoConnection = serde_json::from_value(json).unwrap();
    assert_eq!(parsed.id, "conn-1");
    assert_eq!(parsed.domain, "example.com");
    assert!(parsed.enabled);
}

#[test]
fn sso_provider_variants() {
    assert_eq!(types::SsoProvider::Saml, types::SsoProvider::Saml);
    assert_ne!(types::SsoProvider::Saml, types::SsoProvider::Oidc);
    let custom = types::SsoProvider::Custom("azure-ad".into());
    assert_eq!(custom, types::SsoProvider::Custom("azure-ad".into()));
}

// ── SAML functions ──────────────────────────────────────────────

#[test]
fn build_authn_request_creates_valid_xml() {
    let (xml, req) = saml::build_authn_request(
        "https://sp.example.com",
        "https://sp.example.com/sso/callback",
        "https://idp.example.com/sso",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    );
    assert!(xml.contains("samlp:AuthnRequest"));
    assert!(xml.contains("https://sp.example.com"));
    assert!(xml.contains("https://idp.example.com/sso"));
    assert!(req.id.starts_with('_'));
    assert_eq!(req.issuer, "https://sp.example.com");
}

#[test]
fn encode_authn_request_base64() {
    let encoded = saml::encode_authn_request("<xml>test</xml>");
    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &encoded,
    ).unwrap();
    assert_eq!(std::str::from_utf8(&decoded).unwrap(), "<xml>test</xml>");
}

#[test]
fn build_sso_redirect_url_without_relay_state() {
    let url = saml::build_sso_redirect_url(
        "https://idp.example.com/sso",
        "base64data",
        None,
    );
    assert!(url.starts_with("https://idp.example.com/sso?SAMLRequest="));
    assert!(!url.contains("RelayState"));
}

#[test]
fn build_sso_redirect_url_with_relay_state() {
    let url = saml::build_sso_redirect_url(
        "https://idp.example.com/sso",
        "base64data",
        Some("https://app.example.com/dashboard"),
    );
    assert!(url.contains("RelayState="));
}

#[test]
fn build_sso_redirect_url_with_existing_params() {
    let url = saml::build_sso_redirect_url(
        "https://idp.example.com/sso?tenant=abc",
        "base64data",
        None,
    );
    assert!(url.contains("&SAMLRequest="));
}

#[test]
fn build_sp_metadata_valid_xml() {
    let metadata = types::SpMetadata {
        entity_id: "https://sp.example.com".into(),
        acs_url: "https://sp.example.com/sso/callback".into(),
        sls_url: None,
        certificate: None,
        name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".into(),
    };
    let xml = saml::build_sp_metadata(&metadata);
    assert!(xml.contains("EntityDescriptor"));
    assert!(xml.contains("entityID=\"https://sp.example.com\""));
    assert!(xml.contains("AssertionConsumerService"));
}

// ── Attribute extraction ────────────────────────────────────────

#[test]
fn extract_user_full_attributes() {
    let mapping = types::AttributeMapping::default();
    let mut attrs = HashMap::new();
    attrs.insert(mapping.email.clone(), vec!["user@example.com".into()]);
    if let Some(ref name_key) = mapping.name {
        attrs.insert(name_key.clone(), vec!["John Doe".into()]);
    }

    let (email, name, image) = saml::extract_user_from_attributes(&attrs, &mapping).unwrap();
    assert_eq!(email, "user@example.com");
    assert_eq!(name, Some("John Doe".into()));
    assert!(image.is_none());
}

#[test]
fn extract_user_missing_email_fails() {
    let mapping = types::AttributeMapping::default();
    let attrs = HashMap::new();
    let result = saml::extract_user_from_attributes(&attrs, &mapping);
    assert!(result.is_err());
}

#[test]
fn extract_user_email_only() {
    let mapping = types::AttributeMapping {
        email: "email".into(),
        name: None,
        first_name: None,
        last_name: None,
        image: None,
    };
    let mut attrs = HashMap::new();
    attrs.insert("email".to_string(), vec!["minimal@example.com".into()]);
    let (email, name, image) = saml::extract_user_from_attributes(&attrs, &mapping).unwrap();
    assert_eq!(email, "minimal@example.com");
    assert!(name.is_none());
    assert!(image.is_none());
}

// ── Error types ─────────────────────────────────────────────────

#[test]
fn sso_error_display() {
    let err = SsoError::MissingAttribute;
    let msg = format!("{}", err);
    assert!(!msg.is_empty());
}

#[test]
fn sso_error_connection_not_found() {
    let err = SsoError::ConnectionNotFound;
    let msg = format!("{}", err);
    assert!(!msg.is_empty());
}

#[test]
fn sso_error_codes() {
    assert_eq!(SsoError::ConnectionNotFound.code(), "CONNECTION_NOT_FOUND");
    assert_eq!(SsoError::MissingAttribute.code(), "MISSING_ATTRIBUTE");
    assert_eq!(SsoError::InvalidConfiguration.code(), "INVALID_CONFIGURATION");
}

#[test]
fn sso_error_messages() {
    let err = SsoError::InvalidSamlResponse;
    assert!(!err.message().is_empty());
}
