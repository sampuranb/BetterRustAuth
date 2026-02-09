// Verification token system — maps to packages/better-auth/src/db/verification-token-storage.ts
// and the createVerificationValue / findVerificationValue internal adapter methods.
//
// Provides a high-level API for creating and verifying tokens stored in the database,
// with configurable identifier storage (plain/hashed).

use std::sync::Arc;

use crate::context::AuthContext;
use crate::internal_adapter::AdapterError;

pub mod token_storage;

pub use token_storage::{StoreIdentifierOption, process_identifier};

/// Create a verification token and store it in the database.
///
/// Generates a random token, optionally hashes the identifier, and stores
/// the value in the verification table with an expiration time.
///
/// Returns the identifier (for use in URLs/emails) and the stored verification record.
pub async fn create_verification_value(
    ctx: Arc<AuthContext>,
    identifier: &str,
    value: &str,
    expires_in_seconds: i64,
    storage_option: &StoreIdentifierOption,
) -> Result<VerificationResult, AdapterError> {
    let processed_identifier = process_identifier(identifier, storage_option);

    let expires_at = chrono::Utc::now() + chrono::TimeDelta::seconds(expires_in_seconds);

    let record = ctx
        .adapter
        .create_verification(&processed_identifier, value, expires_at)
        .await?;

    Ok(VerificationResult {
        identifier: processed_identifier,
        record,
    })
}

/// Find and validate a verification token.
///
/// Looks up the verification record by identifier, checks expiration,
/// and returns the stored value if valid.
pub async fn find_verification_value(
    ctx: Arc<AuthContext>,
    identifier: &str,
    storage_option: &StoreIdentifierOption,
) -> Result<Option<VerificationRecord>, AdapterError> {
    let processed_identifier = process_identifier(identifier, storage_option);

    let record = ctx
        .adapter
        .find_verification(&processed_identifier)
        .await?;

    match record {
        Some(value) => {
            // Check expiration
            if let Some(expires_at) = value["expiresAt"].as_str() {
                if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(expires_at) {
                    if exp < chrono::Utc::now() {
                        // Expired — clean up and return None
                        if let Some(id) = value["id"].as_str() {
                            let _ = ctx.adapter.delete_verification(id).await;
                        }
                        return Ok(None);
                    }
                }
            }

            Ok(Some(VerificationRecord {
                id: value["id"].as_str().unwrap_or_default().to_string(),
                identifier: value["identifier"].as_str().unwrap_or_default().to_string(),
                value: value["value"].as_str().unwrap_or_default().to_string(),
                expires_at: value["expiresAt"].as_str().unwrap_or_default().to_string(),
                raw: value,
            }))
        }
        None => Ok(None),
    }
}

/// Consume a verification token — find it, validate it, then delete it.
///
/// This is the standard pattern for one-time-use tokens like email verification,
/// password reset, etc.
pub async fn consume_verification_value(
    ctx: Arc<AuthContext>,
    identifier: &str,
    storage_option: &StoreIdentifierOption,
) -> Result<Option<VerificationRecord>, AdapterError> {
    let record = find_verification_value(ctx.clone(), identifier, storage_option).await?;

    if let Some(ref rec) = record {
        // Delete after consumption
        ctx.adapter.delete_verification(&rec.id).await?;
    }

    Ok(record)
}

/// Delete a verification token by identifier.
pub async fn delete_verification_by_identifier(
    ctx: Arc<AuthContext>,
    identifier: &str,
    storage_option: &StoreIdentifierOption,
) -> Result<(), AdapterError> {
    let processed_identifier = process_identifier(identifier, storage_option);
    ctx.adapter
        .delete_verification_by_identifier(&processed_identifier)
        .await
}

/// Result of creating a verification value.
#[derive(Debug)]
pub struct VerificationResult {
    pub identifier: String,
    pub record: serde_json::Value,
}

/// A verification record from the database.
#[derive(Debug, Clone)]
pub struct VerificationRecord {
    pub id: String,
    pub identifier: String,
    pub value: String,
    pub expires_at: String,
    pub raw: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_record_debug() {
        let record = VerificationRecord {
            id: "v-1".into(),
            identifier: "test-id".into(),
            value: "test-value".into(),
            expires_at: "2025-01-01T00:00:00Z".into(),
            raw: serde_json::json!({}),
        };
        let debug = format!("{:?}", record);
        assert!(debug.contains("test-id"));
    }
}
