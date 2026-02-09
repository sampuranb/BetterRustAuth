// PKCE (Proof Key for Code Exchange) — S256 code challenge generation.
//
// Maps to: packages/core/src/oauth2/utils.ts → generateCodeChallenge()
// Uses SHA-256 hash of the code verifier, then base64url-encodes it (no padding).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

/// Generate a PKCE S256 code challenge from a code verifier.
///
/// Algorithm: base64url(SHA-256(codeVerifier)), no padding.
/// This is the exact same computation as the TypeScript version.
pub fn generate_code_challenge(code_verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let hash = hasher.finalize();
    URL_SAFE_NO_PAD.encode(hash)
}

/// Generate a random code verifier string.
/// Uses the same character set as the TypeScript `generateRandomString`.
pub fn generate_code_verifier() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    let mut rng = rand::thread_rng();
    (0..43)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_challenge_deterministic() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        // This is the known S256 challenge for this verifier (RFC 7636 test vector).
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn test_code_verifier_length() {
        let verifier = generate_code_verifier();
        assert_eq!(verifier.len(), 43);
    }

    #[test]
    fn test_code_verifiers_are_unique() {
        let v1 = generate_code_verifier();
        let v2 = generate_code_verifier();
        assert_ne!(v1, v2);
    }
}
