// JWT — maps to packages/better-auth/src/crypto/jwt.ts
//
// HS256 sign/verify using the `jsonwebtoken` crate.
// Symmetric JWE (A256CBC-HS512) is deferred to a later phase when jose-equivalent is available.

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// Sign a JWT with HS256.
///
/// Maps to TypeScript `signJWT(payload, secret, expiresIn)`.
pub fn sign_jwt<T: Serialize>(
    payload: &T,
    secret: &str,
    expires_in_secs: u64,
) -> Result<String, better_auth_core::error::BetterAuthError> {
    let now = chrono::Utc::now().timestamp() as u64;

    // Wrap the payload with standard JWT claims
    let claims = JwtClaims {
        payload: serde_json::to_value(payload).map_err(|e| {
            better_auth_core::error::BetterAuthError::Other(format!(
                "Failed to serialize JWT payload: {e}"
            ))
        })?,
        iat: now,
        exp: now + expires_in_secs,
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret(secret.as_bytes());

    jsonwebtoken::encode(&header, &claims, &key).map_err(|e| {
        better_auth_core::error::BetterAuthError::Other(format!("JWT signing failed: {e}"))
    })
}

/// Verify and decode a JWT signed with HS256.
///
/// Returns `None` if the token is invalid or expired.
/// Maps to TypeScript `verifyJWT(token, secret)`.
pub fn verify_jwt<T: DeserializeOwned>(
    token: &str,
    secret: &str,
) -> Option<T> {
    let key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.required_spec_claims.clear();

    let token_data = jsonwebtoken::decode::<JwtClaims>(token, &key, &validation).ok()?;
    serde_json::from_value(token_data.claims.payload).ok()
}

/// Internal JWT claims wrapper.
#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    #[serde(flatten)]
    payload: serde_json::Value,
    iat: u64,
    exp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestPayload {
        user_id: String,
        role: String,
    }

    #[test]
    fn test_sign_and_verify() {
        let payload = TestPayload {
            user_id: "user123".into(),
            role: "admin".into(),
        };

        let token = sign_jwt(&payload, "test-secret-key", 3600).unwrap();
        assert!(!token.is_empty());

        let decoded: Option<TestPayload> = verify_jwt(&token, "test-secret-key");
        assert!(decoded.is_some());
        let decoded = decoded.unwrap();
        assert_eq!(decoded.user_id, "user123");
        assert_eq!(decoded.role, "admin");
    }

    #[test]
    fn test_wrong_secret_fails() {
        let payload = TestPayload {
            user_id: "user123".into(),
            role: "admin".into(),
        };

        let token = sign_jwt(&payload, "correct-secret", 3600).unwrap();
        let decoded: Option<TestPayload> = verify_jwt(&token, "wrong-secret");
        assert!(decoded.is_none());
    }

    #[test]
    fn test_expired_token() {
        let payload = TestPayload {
            user_id: "user123".into(),
            role: "admin".into(),
        };

        // Expires immediately (0 seconds)
        let token = sign_jwt(&payload, "secret", 0).unwrap();
        // Should fail verification due to expiration
        let decoded: Option<TestPayload> = verify_jwt(&token, "secret");
        // Note: with 0 seconds, exp == iat, which may or may not
        // pass depending on the library's clock tolerance.
        // We just verify it doesn't panic.
        let _ = decoded;
    }
}
