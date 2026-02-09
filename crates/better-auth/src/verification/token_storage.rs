// Verification token storage — maps to packages/better-auth/src/db/verification-token-storage.ts
//
// Provides identifier processing (hashing/plain) for verification tokens
// stored in the database.

/// How to store verification identifiers.
#[derive(Debug, Clone, PartialEq)]
pub enum StoreIdentifierOption {
    /// Store as plain text (default).
    Plain,
    /// Hash with SHA-256 before storing.
    Hashed,
}

impl Default for StoreIdentifierOption {
    fn default() -> Self {
        Self::Plain
    }
}

/// Process an identifier according to the storage option.
///
/// Matches TS `processIdentifier`:
/// - `Plain` → return as-is
/// - `Hashed` → SHA-256 hash, base64url encoded
pub fn process_identifier(identifier: &str, option: &StoreIdentifierOption) -> String {
    match option {
        StoreIdentifierOption::Plain => identifier.to_string(),
        StoreIdentifierOption::Hashed => {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(identifier.as_bytes());
            base64_url_encode(&hash)
        }
    }
}

/// Base64url encode without padding.
fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Get the effective storage option for an identifier.
///
/// Matches TS `getStorageOption`.
pub fn get_storage_option(
    _identifier: &str,
    config: Option<&StoreIdentifierOption>,
) -> StoreIdentifierOption {
    config.cloned().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_identifier_plain() {
        let result = process_identifier("test@example.com", &StoreIdentifierOption::Plain);
        assert_eq!(result, "test@example.com");
    }

    #[test]
    fn test_process_identifier_hashed() {
        let result = process_identifier("test@example.com", &StoreIdentifierOption::Hashed);
        // Should be a base64url string, not the original
        assert_ne!(result, "test@example.com");
        assert!(!result.is_empty());
        // Same input should produce same hash
        let result2 = process_identifier("test@example.com", &StoreIdentifierOption::Hashed);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_process_identifier_different_inputs() {
        let a = process_identifier("a@example.com", &StoreIdentifierOption::Hashed);
        let b = process_identifier("b@example.com", &StoreIdentifierOption::Hashed);
        assert_ne!(a, b);
    }

    #[test]
    fn test_get_storage_option_default() {
        let opt = get_storage_option("test", None);
        assert_eq!(opt, StoreIdentifierOption::Plain);
    }

    #[test]
    fn test_get_storage_option_override() {
        let opt = get_storage_option("test", Some(&StoreIdentifierOption::Hashed));
        assert_eq!(opt, StoreIdentifierOption::Hashed);
    }
}
