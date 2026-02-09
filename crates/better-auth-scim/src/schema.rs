//! SCIM schema discovery endpoints.

use crate::types::*;
use serde_json::{json, Value};

/// Get the SCIM User schema definition.
pub fn user_schema() -> Value {
    json!({
        "id": SCHEMA_USER,
        "name": "User",
        "description": "User Account",
        "attributes": [
            {"name": "userName", "type": "string", "multiValued": false, "required": true, "mutability": "readWrite", "uniqueness": "server"},
            {"name": "name", "type": "complex", "multiValued": false, "required": false, "subAttributes": [
                {"name": "formatted", "type": "string"},
                {"name": "familyName", "type": "string"},
                {"name": "givenName", "type": "string"}
            ]},
            {"name": "displayName", "type": "string", "multiValued": false, "required": false},
            {"name": "emails", "type": "complex", "multiValued": true, "required": false, "subAttributes": [
                {"name": "value", "type": "string"},
                {"name": "type", "type": "string"},
                {"name": "primary", "type": "boolean"}
            ]},
            {"name": "active", "type": "boolean", "multiValued": false, "required": false},
            {"name": "externalId", "type": "string", "multiValued": false, "required": false, "mutability": "readWrite"}
        ],
        "meta": {"resourceType": "Schema", "location": "/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User"}
    })
}

/// Get the SCIM Group schema definition.
pub fn group_schema() -> Value {
    json!({
        "id": SCHEMA_GROUP,
        "name": "Group",
        "description": "Group",
        "attributes": [
            {"name": "displayName", "type": "string", "multiValued": false, "required": true, "mutability": "readWrite"},
            {"name": "members", "type": "complex", "multiValued": true, "required": false, "subAttributes": [
                {"name": "value", "type": "string"},
                {"name": "$ref", "type": "reference"},
                {"name": "display", "type": "string"}
            ]},
            {"name": "externalId", "type": "string", "multiValued": false, "required": false, "mutability": "readWrite"}
        ],
        "meta": {"resourceType": "Schema", "location": "/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group"}
    })
}

/// Get resource type definitions.
pub fn resource_types(base_url: &str) -> Vec<Value> {
    vec![
        json!({
            "schemas": [SCHEMA_RESOURCE_TYPE],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "schema": SCHEMA_USER,
            "meta": {"resourceType": "ResourceType", "location": format!("{}/scim/v2/ResourceTypes/User", base_url)}
        }),
        json!({
            "schemas": [SCHEMA_RESOURCE_TYPE],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "schema": SCHEMA_GROUP,
            "meta": {"resourceType": "ResourceType", "location": format!("{}/scim/v2/ResourceTypes/Group", base_url)}
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_schema() {
        let schema = user_schema();
        assert_eq!(schema["id"], SCHEMA_USER);
        assert!(schema["attributes"].as_array().unwrap().len() > 0);
    }

    #[test]
    fn test_group_schema() {
        let schema = group_schema();
        assert_eq!(schema["id"], SCHEMA_GROUP);
    }

    #[test]
    fn test_resource_types() {
        let types = resource_types("https://example.com");
        assert_eq!(types.len(), 2);
        assert_eq!(types[0]["id"], "User");
        assert_eq!(types[1]["id"], "Group");
    }
}
