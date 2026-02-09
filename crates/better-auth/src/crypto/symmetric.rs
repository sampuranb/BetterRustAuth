// Symmetric encryption — maps to packages/better-auth/src/crypto/index.ts
//
// XChaCha20-Poly1305 symmetric encryption with SHA-256 key derivation.
// HMAC-SHA256 signature generation.
// Constant-time buffer comparison.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use hmac::{Hmac, Mac, digest::KeyInit as HmacKeyInit};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Encrypt data using XChaCha20-Poly1305.
///
/// The key is first hashed with SHA-256 to produce a 32-byte key.
/// A random 24-byte nonce is prepended to the ciphertext.
/// Output is hex-encoded.
///
/// Maps to TypeScript `symmetricEncrypt({ key, data })`.
pub fn symmetric_encrypt(
    key: &str,
    data: &str,
) -> Result<String, better_auth_core::error::BetterAuthError> {
    // Derive 32-byte key via SHA-256
    use sha2::Digest;
    let key_bytes: [u8; 32] = Sha256::digest(key.as_bytes()).into();

    let cipher = XChaCha20Poly1305::new_from_slice(&key_bytes).map_err(|e| {
        better_auth_core::error::BetterAuthError::Other(format!("Cipher init failed: {e}"))
    })?;

    // Generate random 24-byte nonce
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let ciphertext = cipher.encrypt(&nonce, data.as_bytes()).map_err(|e| {
        better_auth_core::error::BetterAuthError::Other(format!("Encryption failed: {e}"))
    })?;

    // Prepend nonce to ciphertext, then hex-encode
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(hex::encode(result))
}

/// Decrypt data encrypted by `symmetric_encrypt`.
///
/// Input is hex-encoded (nonce || ciphertext).
///
/// Maps to TypeScript `symmetricDecrypt({ key, data })`.
pub fn symmetric_decrypt(
    key: &str,
    data: &str,
) -> Result<String, better_auth_core::error::BetterAuthError> {
    use sha2::Digest;
    let key_bytes: [u8; 32] = Sha256::digest(key.as_bytes()).into();

    let raw = hex::decode(data).map_err(|e| {
        better_auth_core::error::BetterAuthError::Other(format!("Invalid hex data: {e}"))
    })?;

    if raw.len() < 24 {
        return Err(better_auth_core::error::BetterAuthError::Other(
            "Ciphertext too short (missing nonce)".into(),
        ));
    }

    let (nonce_bytes, ciphertext) = raw.split_at(24);
    let nonce = XNonce::from_slice(nonce_bytes);

    let cipher = XChaCha20Poly1305::new_from_slice(&key_bytes).map_err(|e| {
        better_auth_core::error::BetterAuthError::Other(format!("Cipher init failed: {e}"))
    })?;

    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| {
        better_auth_core::error::BetterAuthError::Other(format!("Decryption failed: {e}"))
    })?;

    String::from_utf8(plaintext).map_err(|e| {
        better_auth_core::error::BetterAuthError::Other(format!("Invalid UTF-8 plaintext: {e}"))
    })
}

/// Create an HMAC-SHA256 signature, returned as base64.
///
/// Maps to TypeScript `makeSignature(value, secret)`.
pub fn make_signature(
    value: &str,
    secret: &str,
) -> Result<String, better_auth_core::error::BetterAuthError> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(secret.as_bytes()).map_err(|e| {
        better_auth_core::error::BetterAuthError::Other(format!("HMAC init failed: {e}"))
    })?;

    mac.update(value.as_bytes());
    let result = mac.finalize().into_bytes();
    Ok(STANDARD.encode(result))
}

/// Verify an HMAC-SHA256 signature.
pub fn verify_signature(
    value: &str,
    secret: &str,
    signature: &str,
) -> Result<bool, better_auth_core::error::BetterAuthError> {
    let expected = make_signature(value, secret)?;
    Ok(constant_time_equal(expected.as_bytes(), signature.as_bytes()))
}

/// Compare two byte slices in constant time.
///
/// Maps to TypeScript `constantTimeEqual(a, b)`.
pub fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_encrypt_decrypt() {
        let key = "my-secret-key";
        let data = "Hello, World!";

        let encrypted = symmetric_encrypt(key, data).unwrap();
        assert_ne!(encrypted, data);

        let decrypted = symmetric_decrypt(key, &encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_symmetric_wrong_key() {
        let encrypted = symmetric_encrypt("correct-key", "secret data").unwrap();
        let result = symmetric_decrypt("wrong-key", &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_symmetric_different_ciphertexts() {
        let key = "my-key";
        let data = "same data";
        let enc1 = symmetric_encrypt(key, data).unwrap();
        let enc2 = symmetric_encrypt(key, data).unwrap();
        // Different nonces → different ciphertexts
        assert_ne!(enc1, enc2);
        // Both decrypt to same plaintext
        assert_eq!(symmetric_decrypt(key, &enc1).unwrap(), data);
        assert_eq!(symmetric_decrypt(key, &enc2).unwrap(), data);
    }

    #[test]
    fn test_make_signature() {
        let sig = make_signature("hello", "secret").unwrap();
        assert!(!sig.is_empty());
        // Base64-encoded HMAC-SHA256 is always 44 chars
        assert_eq!(sig.len(), 44);
    }

    #[test]
    fn test_verify_signature() {
        let sig = make_signature("hello", "secret").unwrap();
        assert!(verify_signature("hello", "secret", &sig).unwrap());
        assert!(!verify_signature("hello", "wrong-secret", &sig).unwrap());
        assert!(!verify_signature("wrong-data", "secret", &sig).unwrap());
    }

    #[test]
    fn test_constant_time_equal() {
        assert!(constant_time_equal(b"hello", b"hello"));
        assert!(!constant_time_equal(b"hello", b"world"));
        assert!(!constant_time_equal(b"hello", b"hell"));
    }
}
