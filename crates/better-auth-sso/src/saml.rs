//! SAML request/response processing.
//! Note: Full XML signing/verification would use a dedicated SAML library.
//! This module provides the core logic and data structures.

use crate::error::SsoError;
use crate::types::*;
use base64::Engine;
use chrono::Utc;
use std::collections::HashMap;

/// Build a SAML AuthnRequest XML string.
pub fn build_authn_request(
    sp_entity_id: &str,
    acs_url: &str,
    idp_sso_url: &str,
    name_id_format: &str,
) -> (String, AuthnRequest) {
    let request_id = format!("_{}",uuid::Uuid::new_v4());
    let issue_instant = Utc::now();
    let instant_str = issue_instant.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let xml = format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="{request_id}"
            Version="2.0"
            IssueInstant="{instant_str}"
            Destination="{idp_sso_url}"
            AssertionConsumerServiceURL="{acs_url}"
            ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
            <saml:Issuer>{sp_entity_id}</saml:Issuer>
            <samlp:NameIDPolicy Format="{name_id_format}" AllowCreate="true"/>
        </samlp:AuthnRequest>"#,
    );

    let request = AuthnRequest {
        id: request_id,
        issue_instant,
        issuer: sp_entity_id.to_string(),
        assertion_consumer_service_url: acs_url.to_string(),
        destination: idp_sso_url.to_string(),
        name_id_policy_format: Some(name_id_format.to_string()),
    };

    (xml, request)
}

/// Encode an AuthnRequest for HTTP-Redirect binding.
pub fn encode_authn_request(xml: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(xml.as_bytes())
}

/// Build the SSO redirect URL with the encoded AuthnRequest.
pub fn build_sso_redirect_url(
    idp_sso_url: &str,
    encoded_request: &str,
    relay_state: Option<&str>,
) -> String {
    let mut url = format!(
        "{}{}SAMLRequest={}",
        idp_sso_url,
        if idp_sso_url.contains('?') { "&" } else { "?" },
        urlencoding::encode(encoded_request),
    );
    if let Some(rs) = relay_state {
        url.push_str(&format!("&RelayState={}", urlencoding::encode(rs)));
    }
    url
}

/// Build SP metadata XML for publishing at the metadata endpoint.
pub fn build_sp_metadata(metadata: &SpMetadata) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="{entity_id}">
    <md:SPSSODescriptor
        AuthnRequestsSigned="false"
        WantAssertionsSigned="true"
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:NameIDFormat>{name_id_format}</md:NameIDFormat>
        <md:AssertionConsumerService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="{acs_url}"
            index="1"
            isDefault="true"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>"#,
        entity_id = metadata.entity_id,
        acs_url = metadata.acs_url,
        name_id_format = metadata.name_id_format,
    )
}

/// Parse attributes from a flat map (simulated SAML assertion attributes).
/// In production, this would parse XML assertion content.
pub fn extract_user_from_attributes(
    attributes: &HashMap<String, Vec<String>>,
    mapping: &AttributeMapping,
) -> Result<(String, Option<String>, Option<String>), SsoError> {
    let email = attributes
        .get(&mapping.email)
        .and_then(|v| v.first())
        .ok_or(SsoError::MissingAttribute)?
        .clone();

    let name = mapping.name.as_ref()
        .and_then(|key| attributes.get(key))
        .and_then(|v| v.first())
        .cloned();

    let image = mapping.image.as_ref()
        .and_then(|key| attributes.get(key))
        .and_then(|v| v.first())
        .cloned();

    Ok((email, name, image))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AttributeMapping;

    #[test]
    fn test_build_authn_request() {
        let (xml, req) = build_authn_request(
            "https://sp.example.com",
            "https://sp.example.com/sso/callback",
            "https://idp.example.com/sso",
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        );
        assert!(xml.contains("samlp:AuthnRequest"));
        assert!(xml.contains("https://sp.example.com"));
        assert!(xml.contains("https://idp.example.com/sso"));
        assert!(req.id.starts_with('_'));
    }

    #[test]
    fn test_encode_authn_request() {
        let encoded = encode_authn_request("<xml>test</xml>");
        let decoded = base64::engine::general_purpose::STANDARD.decode(&encoded).unwrap();
        assert_eq!(std::str::from_utf8(&decoded).unwrap(), "<xml>test</xml>");
    }

    #[test]
    fn test_build_sso_redirect_url() {
        let url = build_sso_redirect_url(
            "https://idp.example.com/sso",
            "base64encoded",
            Some("https://app.example.com/dashboard"),
        );
        assert!(url.starts_with("https://idp.example.com/sso?SAMLRequest="));
        assert!(url.contains("RelayState="));
    }

    #[test]
    fn test_build_sp_metadata() {
        let metadata = SpMetadata {
            entity_id: "https://sp.example.com".into(),
            acs_url: "https://sp.example.com/sso/callback".into(),
            sls_url: None,
            certificate: None,
            name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".into(),
        };
        let xml = build_sp_metadata(&metadata);
        assert!(xml.contains("EntityDescriptor"));
        assert!(xml.contains("https://sp.example.com"));
    }

    #[test]
    fn test_extract_user_from_attributes() {
        let mapping = AttributeMapping::default();
        let mut attrs = HashMap::new();
        attrs.insert(mapping.email.clone(), vec!["user@example.com".into()]);
        attrs.insert(mapping.name.clone().unwrap(), vec!["John Doe".into()]);

        let (email, name, image) = extract_user_from_attributes(&attrs, &mapping).unwrap();
        assert_eq!(email, "user@example.com");
        assert_eq!(name, Some("John Doe".into()));
        assert!(image.is_none());
    }

    #[test]
    fn test_extract_user_missing_email() {
        let mapping = AttributeMapping::default();
        let attrs = HashMap::new();
        let result = extract_user_from_attributes(&attrs, &mapping);
        assert!(result.is_err());
    }
}
