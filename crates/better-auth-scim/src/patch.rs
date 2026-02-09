//! SCIM Patch operations (RFC 7644 §3.5.2).

use serde::{Deserialize, Serialize};
use crate::error::ScimError;

/// SCIM Patch request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchRequest {
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<PatchOperation>,
}

/// A single SCIM patch operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchOperation {
    pub op: PatchOp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

/// Patch operation types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PatchOp {
    Add,
    Remove,
    Replace,
}

/// Apply a patch operation to a JSON object.
pub fn apply_patch(
    target: &mut serde_json::Value,
    operation: &PatchOperation,
) -> Result<(), ScimError> {
    match operation.op {
        PatchOp::Add => apply_add(target, operation),
        PatchOp::Remove => apply_remove(target, operation),
        PatchOp::Replace => apply_replace(target, operation),
    }
}

fn apply_add(
    target: &mut serde_json::Value,
    operation: &PatchOperation,
) -> Result<(), ScimError> {
    let value = operation.value.as_ref().ok_or(ScimError::InvalidValue)?;

    match &operation.path {
        None => {
            // No path: merge value into target
            if let (Some(obj), Some(patch_obj)) = (target.as_object_mut(), value.as_object()) {
                for (k, v) in patch_obj {
                    obj.insert(k.clone(), v.clone());
                }
                Ok(())
            } else {
                Err(ScimError::InvalidValue)
            }
        }
        Some(path) => {
            set_value_at_path(target, path, value.clone())
        }
    }
}

fn apply_remove(
    target: &mut serde_json::Value,
    operation: &PatchOperation,
) -> Result<(), ScimError> {
    let path = operation.path.as_ref().ok_or(ScimError::NoTarget)?;

    if let Some(obj) = target.as_object_mut() {
        // Simple single-level path removal
        let parts: Vec<&str> = path.split('.').collect();
        if parts.len() == 1 {
            obj.remove(parts[0]);
            Ok(())
        } else {
            // Navigate to parent, then remove
            let parent_path = parts[..parts.len() - 1].join(".");
            let field = parts[parts.len() - 1];
            if let Some(parent) = get_value_at_path_mut(target, &parent_path) {
                if let Some(parent_obj) = parent.as_object_mut() {
                    parent_obj.remove(field);
                }
            }
            Ok(())
        }
    } else {
        Err(ScimError::InvalidPath)
    }
}

fn apply_replace(
    target: &mut serde_json::Value,
    operation: &PatchOperation,
) -> Result<(), ScimError> {
    let value = operation.value.as_ref().ok_or(ScimError::InvalidValue)?;

    match &operation.path {
        None => {
            // Replace entire object
            *target = value.clone();
            Ok(())
        }
        Some(path) => {
            set_value_at_path(target, path, value.clone())
        }
    }
}

fn set_value_at_path(
    target: &mut serde_json::Value,
    path: &str,
    value: serde_json::Value,
) -> Result<(), ScimError> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = target;

    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            if let Some(obj) = current.as_object_mut() {
                obj.insert(part.to_string(), value);
                return Ok(());
            }
            return Err(ScimError::InvalidPath);
        }
        current = current
            .as_object_mut()
            .and_then(|obj| obj.get_mut(*part))
            .ok_or(ScimError::InvalidPath)?;
    }
    Err(ScimError::InvalidPath)
}

fn get_value_at_path_mut<'a>(
    target: &'a mut serde_json::Value,
    path: &str,
) -> Option<&'a mut serde_json::Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = target;
    for part in &parts {
        current = current.as_object_mut()?.get_mut(*part)?;
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_patch_add_with_path() {
        let mut target = json!({"name": {"givenName": "John"}});
        let op = PatchOperation {
            op: PatchOp::Add,
            path: Some("name.familyName".to_string()),
            value: Some(json!("Doe")),
        };
        apply_patch(&mut target, &op).unwrap();
        assert_eq!(target["name"]["familyName"], "Doe");
    }

    #[test]
    fn test_patch_add_without_path() {
        let mut target = json!({"name": "John"});
        let op = PatchOperation {
            op: PatchOp::Add,
            path: None,
            value: Some(json!({"email": "john@example.com"})),
        };
        apply_patch(&mut target, &op).unwrap();
        assert_eq!(target["email"], "john@example.com");
        assert_eq!(target["name"], "John");
    }

    #[test]
    fn test_patch_remove() {
        let mut target = json!({"name": "John", "email": "john@example.com"});
        let op = PatchOperation {
            op: PatchOp::Remove,
            path: Some("email".to_string()),
            value: None,
        };
        apply_patch(&mut target, &op).unwrap();
        assert!(target.get("email").is_none());
    }

    #[test]
    fn test_patch_replace() {
        let mut target = json!({"name": "John", "active": true});
        let op = PatchOperation {
            op: PatchOp::Replace,
            path: Some("active".to_string()),
            value: Some(json!(false)),
        };
        apply_patch(&mut target, &op).unwrap();
        assert_eq!(target["active"], false);
    }

    #[test]
    fn test_patch_replace_no_path() {
        let mut target = json!({"old": "data"});
        let op = PatchOperation {
            op: PatchOp::Replace,
            path: None,
            value: Some(json!({"new": "data"})),
        };
        apply_patch(&mut target, &op).unwrap();
        assert_eq!(target["new"], "data");
    }
}
