//! SSO route handlers.
//!
//! Maps to the TS SSO package endpoints:
//! - POST /sso/initiate — Start SSO flow
//! - POST /sso/callback — Handle SAML response
//! - GET /sso/metadata — SP metadata endpoint
//! - CRUD for SSO connections

use crate::config::SsoOptions;
use crate::saml;
use crate::types::*;

/// Initiate SSO flow — build AuthnRequest and return redirect URL.
pub fn initiate_sso(
    connection: &SsoConnection,
    options: &SsoOptions,
    base_url: &str,
    redirect_url: Option<&str>,
) -> Result<String, crate::error::SsoError> {
    let idp_sso_url = connection.idp_sso_url.as_ref()
        .ok_or(crate::error::SsoError::InvalidConfiguration)?;

    let sp_entity_id = options.sp_entity_id
        .clone()
        .unwrap_or_else(|| base_url.to_string());

    let (xml, _request) = saml::build_authn_request(
        &sp_entity_id,
        &connection.sp_acs_url,
        idp_sso_url,
        &options.name_id_format,
    );

    let encoded = saml::encode_authn_request(&xml);
    let url = saml::build_sso_redirect_url(idp_sso_url, &encoded, redirect_url);

    Ok(url)
}

/// Generate SP metadata XML.
pub fn get_sp_metadata(options: &SsoOptions, base_url: &str, acs_path: &str) -> String {
    let entity_id = options.sp_entity_id
        .clone()
        .unwrap_or_else(|| base_url.to_string());

    let metadata = SpMetadata {
        entity_id,
        acs_url: format!("{}{}", base_url, acs_path),
        sls_url: None,
        certificate: None,
        name_id_format: options.name_id_format.clone(),
    };

    saml::build_sp_metadata(&metadata)
}

/// Validate an SSO connection has required fields for SAML.
pub fn validate_connection(connection: &SsoConnection) -> Result<(), crate::error::SsoError> {
    if connection.idp_sso_url.is_none() && connection.idp_metadata_url.is_none() {
        return Err(crate::error::SsoError::InvalidConfiguration);
    }
    if connection.sp_entity_id.is_empty() || connection.sp_acs_url.is_empty() {
        return Err(crate::error::SsoError::InvalidConfiguration);
    }
    Ok(())
}

/// Create a new SSO connection record.
pub fn build_connection(
    domain: &str,
    provider: SsoProvider,
    sp_entity_id: &str,
    sp_acs_url: &str,
    idp_sso_url: Option<&str>,
    idp_entity_id: Option<&str>,
    idp_certificate: Option<&str>,
    idp_metadata_url: Option<&str>,
    organization_id: Option<&str>,
) -> SsoConnection {
    let now = chrono::Utc::now();
    SsoConnection {
        id: uuid::Uuid::new_v4().to_string(),
        organization_id: organization_id.map(String::from),
        provider,
        domain: domain.to_string(),
        enabled: true,
        idp_metadata_url: idp_metadata_url.map(String::from),
        idp_entity_id: idp_entity_id.map(String::from),
        idp_sso_url: idp_sso_url.map(String::from),
        idp_certificate: idp_certificate.map(String::from),
        sp_entity_id: sp_entity_id.to_string(),
        sp_acs_url: sp_acs_url.to_string(),
        attribute_mapping: AttributeMapping::default(),
        created_at: now,
        updated_at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_connection() -> SsoConnection {
        build_connection(
            "example.com",
            SsoProvider::Saml,
            "https://sp.example.com",
            "https://sp.example.com/sso/callback",
            Some("https://idp.example.com/sso"),
            Some("https://idp.example.com"),
            None,
            None,
            None,
        )
    }

    #[test]
    fn test_initiate_sso() {
        let conn = test_connection();
        let opts = SsoOptions::default();
        let url = initiate_sso(&conn, &opts, "https://sp.example.com", Some("/dashboard")).unwrap();
        assert!(url.contains("SAMLRequest="));
        assert!(url.contains("RelayState="));
    }

    #[test]
    fn test_get_sp_metadata() {
        let opts = SsoOptions::default();
        let xml = get_sp_metadata(&opts, "https://sp.example.com", "/sso/callback");
        assert!(xml.contains("EntityDescriptor"));
        assert!(xml.contains("https://sp.example.com/sso/callback"));
    }

    #[test]
    fn test_validate_connection() {
        let conn = test_connection();
        assert!(validate_connection(&conn).is_ok());

        let mut bad_conn = test_connection();
        bad_conn.idp_sso_url = None;
        bad_conn.idp_metadata_url = None;
        assert!(validate_connection(&bad_conn).is_err());
    }

    #[test]
    fn test_build_connection() {
        let conn = build_connection(
            "corp.com", SsoProvider::Saml, "https://sp.corp.com",
            "https://sp.corp.com/acs", Some("https://idp.corp.com/sso"),
            None, None, None, Some("org-123"),
        );
        assert_eq!(conn.domain, "corp.com");
        assert_eq!(conn.organization_id, Some("org-123".into()));
        assert!(conn.enabled);
    }
}
