//! PKCE (RFC 7636) — Proof Key for Code Exchange.

use base64::Engine;
use sha2::{Sha256, Digest};
use crate::error::OAuthProviderError;

/// PKCE code challenge methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeChallengeMethod {
    Plain,
    S256,
}

impl CodeChallengeMethod {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "plain" => Some(Self::Plain),
            "S256" => Some(Self::S256),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::S256 => "S256",
        }
    }
}

/// Generate a code challenge from a code verifier.
pub fn generate_code_challenge(verifier: &str, method: &CodeChallengeMethod) -> String {
    match method {
        CodeChallengeMethod::Plain => verifier.to_string(),
        CodeChallengeMethod::S256 => {
            let mut hasher = Sha256::new();
            hasher.update(verifier.as_bytes());
            let hash = hasher.finalize();
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
        }
    }
}

/// Verify a code verifier against a stored code challenge.
pub fn verify_code_verifier(
    verifier: &str,
    challenge: &str,
    method: &str,
) -> Result<(), OAuthProviderError> {
    let method = CodeChallengeMethod::from_str(method)
        .ok_or(OAuthProviderError::InvalidCodeChallenge)?;

    let computed = generate_code_challenge(verifier, &method);

    if subtle::ConstantTimeEq::ct_eq(computed.as_bytes(), challenge.as_bytes()).into() {
        Ok(())
    } else {
        Err(OAuthProviderError::InvalidCodeChallenge)
    }
}

/// Generate a cryptographically random code verifier (43-128 chars, URL-safe).
pub fn generate_code_verifier() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let length = rng.gen_range(43..=128);
    let bytes: Vec<u8> = (0..length).map(|_| rng.r#gen()).collect();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)[..length].to_string()
}

use subtle;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s256_challenge() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier, &CodeChallengeMethod::S256);
        assert!(!challenge.is_empty());
        // Verify the challenge matches
        assert!(verify_code_verifier(verifier, &challenge, "S256").is_ok());
    }

    #[test]
    fn test_plain_challenge() {
        let verifier = "my_plain_verifier";
        let challenge = generate_code_challenge(verifier, &CodeChallengeMethod::Plain);
        assert_eq!(challenge, verifier);
        assert!(verify_code_verifier(verifier, &challenge, "plain").is_ok());
    }

    #[test]
    fn test_verify_wrong_verifier() {
        let verifier = "correct_verifier";
        let challenge = generate_code_challenge(verifier, &CodeChallengeMethod::S256);
        assert!(verify_code_verifier("wrong_verifier", &challenge, "S256").is_err());
    }

    #[test]
    fn test_generate_code_verifier() {
        let v = generate_code_verifier();
        assert!(v.len() >= 43);
    }

    #[test]
    fn test_code_challenge_method_from_str() {
        assert_eq!(CodeChallengeMethod::from_str("S256"), Some(CodeChallengeMethod::S256));
        assert_eq!(CodeChallengeMethod::from_str("plain"), Some(CodeChallengeMethod::Plain));
        assert_eq!(CodeChallengeMethod::from_str("invalid"), None);
    }
}
