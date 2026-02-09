//! SCIM 2.0 types — User, Group, ListResponse, Meta, etc.
//! Follows RFC 7643 (SCIM Core Schema) and RFC 7644 (SCIM Protocol).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// SCIM schemas URN constants.
pub const SCHEMA_USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const SCHEMA_GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const SCHEMA_LIST_RESPONSE: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const SCHEMA_PATCH_OP: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
pub const SCHEMA_ERROR: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
pub const SCHEMA_SERVICE_PROVIDER: &str = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
pub const SCHEMA_RESOURCE_TYPE: &str = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";

/// SCIM resource metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    #[serde(rename = "resourceType")]
    pub resource_type: String,
    pub created: DateTime<Utc>,
    #[serde(rename = "lastModified")]
    pub last_modified: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// SCIM User resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimUser {
    pub schemas: Vec<String>,
    pub id: String,
    #[serde(rename = "userName")]
    pub user_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<ScimName>,
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emails: Option<Vec<ScimEmail>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<ScimGroupRef>>,
    #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub meta: Meta,
}

/// SCIM user name component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimName {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(rename = "familyName", skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(rename = "givenName", skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
}

/// SCIM email value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimEmail {
    pub value: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub email_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
}

/// Reference to a group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimGroupRef {
    pub value: String,
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    pub ref_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

/// SCIM Group resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimGroup {
    pub schemas: Vec<String>,
    pub id: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<ScimMember>>,
    #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub meta: Meta,
}

/// SCIM group member reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimMember {
    pub value: String,
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    pub ref_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

/// SCIM list response (RFC 7644 §3.4.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResponse<T> {
    pub schemas: Vec<String>,
    #[serde(rename = "totalResults")]
    pub total_results: usize,
    #[serde(rename = "startIndex")]
    pub start_index: usize,
    #[serde(rename = "itemsPerPage")]
    pub items_per_page: usize,
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

impl<T> ListResponse<T> {
    pub fn new(resources: Vec<T>, total: usize, start: usize, count: usize) -> Self {
        Self {
            schemas: vec![SCHEMA_LIST_RESPONSE.to_string()],
            total_results: total,
            start_index: start,
            items_per_page: count,
            resources,
        }
    }
}

/// SCIM error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimErrorResponse {
    pub schemas: Vec<String>,
    pub status: String,
    #[serde(rename = "scimType", skip_serializing_if = "Option::is_none")]
    pub scim_type: Option<String>,
    pub detail: String,
}

impl ScimErrorResponse {
    pub fn new(status: u16, scim_type: Option<&str>, detail: &str) -> Self {
        Self {
            schemas: vec![SCHEMA_ERROR.to_string()],
            status: status.to_string(),
            scim_type: scim_type.map(String::from),
            detail: detail.to_string(),
        }
    }
}

/// Service provider configuration (RFC 7643 §5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceProviderConfig {
    pub schemas: Vec<String>,
    pub patch: SupportedFeature,
    pub bulk: BulkFeature,
    pub filter: FilterFeature,
    #[serde(rename = "changePassword")]
    pub change_password: SupportedFeature,
    pub sort: SupportedFeature,
    pub etag: SupportedFeature,
    #[serde(rename = "authenticationSchemes")]
    pub authentication_schemes: Vec<AuthScheme>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedFeature {
    pub supported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkFeature {
    pub supported: bool,
    #[serde(rename = "maxOperations")]
    pub max_operations: usize,
    #[serde(rename = "maxPayloadSize")]
    pub max_payload_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterFeature {
    pub supported: bool,
    #[serde(rename = "maxResults")]
    pub max_results: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthScheme {
    #[serde(rename = "type")]
    pub auth_type: String,
    pub name: String,
    pub description: String,
}

impl Default for ServiceProviderConfig {
    fn default() -> Self {
        Self {
            schemas: vec![SCHEMA_SERVICE_PROVIDER.to_string()],
            patch: SupportedFeature { supported: true },
            bulk: BulkFeature { supported: false, max_operations: 0, max_payload_size: 0 },
            filter: FilterFeature { supported: true, max_results: 200 },
            change_password: SupportedFeature { supported: false },
            sort: SupportedFeature { supported: false },
            etag: SupportedFeature { supported: false },
            authentication_schemes: vec![AuthScheme {
                auth_type: "oauthbearertoken".to_string(),
                name: "OAuth Bearer Token".to_string(),
                description: "Authentication using OAuth 2.0 Bearer Token".to_string(),
            }],
        }
    }
}
