//! SSO configuration.

use crate::types::AttributeMapping;
use serde::{Deserialize, Serialize};

/// SSO plugin configuration options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoOptions {
    /// Default attribute mapping for new connections.
    #[serde(default)]
    pub default_attribute_mapping: AttributeMapping,
    /// SP entity ID (defaults to base_url).
    pub sp_entity_id: Option<String>,
    /// Auto-create users on first SSO login.
    #[serde(default = "default_true")]
    pub auto_create_user: bool,
    /// Auto-link users by email domain.
    #[serde(default = "default_true")]
    pub auto_link_by_email: bool,
    /// Allow IdP-initiated SSO (less secure).
    #[serde(default)]
    pub allow_idp_initiated: bool,
    /// NameID policy format.
    #[serde(default = "default_name_id_format")]
    pub name_id_format: String,
}

fn default_true() -> bool { true }
fn default_name_id_format() -> String {
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string()
}

impl Default for SsoOptions {
    fn default() -> Self {
        Self {
            default_attribute_mapping: AttributeMapping::default(),
            sp_entity_id: None,
            auto_create_user: true,
            auto_link_by_email: true,
            allow_idp_initiated: false,
            name_id_format: default_name_id_format(),
        }
    }
}
