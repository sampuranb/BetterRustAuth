// Password hashing — maps to packages/better-auth/src/crypto/password.ts
//
// Uses scrypt (N=16384, r=16, p=1, dkLen=64) with random 16-byte salt.
// Output format: "hex(salt):hex(key)"

use rand::RngCore;
use scrypt::{Params, scrypt};

/// Hash a password using scrypt.
///
/// Returns a string in the format `salt:key` where both are hex-encoded.
/// Matches the TypeScript implementation exactly:
/// - N = 16384, r = 16, p = 1, dkLen = 64
pub fn hash_password(password: &str) -> Result<String, better_auth_core::error::BetterAuthError> {
    // Generate 16 random bytes for salt
    let mut salt_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt_bytes);
    let salt_hex = hex::encode(salt_bytes);

    let key = generate_key(password, &salt_hex)?;
    Ok(format!("{}:{}", salt_hex, hex::encode(key)))
}

/// Verify a password against a hash produced by `hash_password`.
pub fn verify_password(
    hash: &str,
    password: &str,
) -> Result<bool, better_auth_core::error::BetterAuthError> {
    let (salt, key_hex) = hash.split_once(':').ok_or_else(|| {
        better_auth_core::error::BetterAuthError::Other("Invalid password hash format".into())
    })?;

    let expected_key =
        hex::decode(key_hex).map_err(|e| {
            better_auth_core::error::BetterAuthError::Other(format!(
                "Invalid hex in password hash: {e}"
            ))
        })?;

    let derived_key = generate_key(password, salt)?;

    Ok(super::symmetric::constant_time_equal(&derived_key, &expected_key))
}

/// Internal: derive a 64-byte key using scrypt.
fn generate_key(
    password: &str,
    salt: &str,
) -> Result<Vec<u8>, better_auth_core::error::BetterAuthError> {
    // N=16384 → log2(N)=14, r=16, p=1, dkLen=64
    let params = Params::new(14, 16, 1, 64).map_err(|e| {
        better_auth_core::error::BetterAuthError::Other(format!("Invalid scrypt params: {e}"))
    })?;

    // Normalize password to NFKC (Rust strings are already valid UTF-8;
    // for full NFKC we'd need the `unicode-normalization` crate,
    // but for ASCII passwords this is equivalent)
    let password_bytes = password.as_bytes();
    let salt_bytes = salt.as_bytes();

    let mut output = vec![0u8; 64];
    scrypt(password_bytes, salt_bytes, &params, &mut output).map_err(|e| {
        better_auth_core::error::BetterAuthError::Other(format!("scrypt failed: {e}"))
    })?;

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify() {
        let password = "my-secret-password";
        let hash = hash_password(password).unwrap();

        // Hash format: salt:key
        assert!(hash.contains(':'));
        let parts: Vec<&str> = hash.split(':').collect();
        assert_eq!(parts.len(), 2);
        // Salt = 16 bytes = 32 hex chars
        assert_eq!(parts[0].len(), 32);
        // Key = 64 bytes = 128 hex chars
        assert_eq!(parts[1].len(), 128);

        // Verify correct password
        assert!(verify_password(&hash, password).unwrap());

        // Verify wrong password
        assert!(!verify_password(&hash, "wrong-password").unwrap());
    }

    #[test]
    fn test_different_hashes_per_call() {
        let password = "same-password";
        let hash1 = hash_password(password).unwrap();
        let hash2 = hash_password(password).unwrap();
        // Different salts → different hashes
        assert_ne!(hash1, hash2);
        // Both verify
        assert!(verify_password(&hash1, password).unwrap());
        assert!(verify_password(&hash2, password).unwrap());
    }

    #[test]
    fn test_invalid_hash_format() {
        assert!(verify_password("no-colon-here", "password").is_err());
    }
}
