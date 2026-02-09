//! SSO types — SAML assertions, SP/IdP config, connections.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// SSO connection representing an IdP configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoConnection {
    pub id: String,
    pub organization_id: Option<String>,
    pub provider: SsoProvider,
    pub domain: String,
    pub enabled: bool,
    pub idp_metadata_url: Option<String>,
    pub idp_entity_id: Option<String>,
    pub idp_sso_url: Option<String>,
    pub idp_certificate: Option<String>,
    pub sp_entity_id: String,
    pub sp_acs_url: String,
    pub attribute_mapping: AttributeMapping,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Supported SSO providers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SsoProvider {
    Saml,
    Oidc,
    Custom(String),
}

/// SAML attribute mapping — map SAML assertion attributes to user fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeMapping {
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

impl Default for AttributeMapping {
    fn default() -> Self {
        Self {
            email: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress".to_string(),
            name: Some("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name".to_string()),
            first_name: Some("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname".to_string()),
            last_name: Some("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname".to_string()),
            image: None,
        }
    }
}

/// Parsed SAML assertion data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAssertion {
    pub issuer: String,
    pub name_id: String,
    pub name_id_format: Option<String>,
    pub session_index: Option<String>,
    pub attributes: std::collections::HashMap<String, Vec<String>>,
    pub not_before: Option<DateTime<Utc>>,
    pub not_on_or_after: Option<DateTime<Utc>>,
    pub audience: Option<String>,
    pub in_response_to: Option<String>,
}

/// SAML AuthnRequest data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthnRequest {
    pub id: String,
    pub issue_instant: DateTime<Utc>,
    pub issuer: String,
    pub assertion_consumer_service_url: String,
    pub destination: String,
    pub name_id_policy_format: Option<String>,
}

/// SSO initiate request parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoInitiateRequest {
    pub connection_id: Option<String>,
    pub domain: Option<String>,
    pub organization_id: Option<String>,
    pub redirect_url: Option<String>,
}

/// SSO callback request parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoCallbackRequest {
    pub saml_response: Option<String>,
    pub relay_state: Option<String>,
}

/// SP metadata for publishing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpMetadata {
    pub entity_id: String,
    pub acs_url: String,
    pub sls_url: Option<String>,
    pub certificate: Option<String>,
    pub name_id_format: String,
}
