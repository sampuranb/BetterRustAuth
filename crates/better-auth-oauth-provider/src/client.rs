//! OAuth client management.

use crate::types::*;
use crate::error::OAuthProviderError;
use chrono::Utc;
use sha2::{Sha256, Digest};

/// Hash a client secret for storage.
pub fn hash_client_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hex::encode(hasher.finalize())
}

/// Verify a client secret against a stored hash.
pub fn verify_client_secret(secret: &str, hash: &str) -> bool {
    let computed = hash_client_secret(secret);
    subtle::ConstantTimeEq::ct_eq(computed.as_bytes(), hash.as_bytes()).into()
}

/// Validate redirect URI format.
pub fn validate_redirect_uri(uri: &str) -> Result<(), OAuthProviderError> {
    let parsed = url::Url::parse(uri).map_err(|_| OAuthProviderError::InvalidRedirectUri)?;

    // Must use https (except localhost)
    if parsed.scheme() != "https" {
        if parsed.host_str() != Some("localhost") && parsed.host_str() != Some("127.0.0.1") {
            return Err(OAuthProviderError::InvalidRedirectUri);
        }
    }

    // Must not have fragment
    if parsed.fragment().is_some() {
        return Err(OAuthProviderError::InvalidRedirectUri);
    }

    Ok(())
}

/// Build a new OAuth client.
pub fn build_client(
    name: &str,
    redirect_uris: Vec<String>,
    client_type: ClientType,
    scopes: Vec<String>,
) -> (OAuthClient, String) {
    let client_id = uuid::Uuid::new_v4().to_string();
    let client_secret: String = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(rand::random::<[u8; 32]>());

    let now = Utc::now();
    let client = OAuthClient {
        id: uuid::Uuid::new_v4().to_string(),
        client_id: client_id.clone(),
        client_secret_hash: match client_type {
            ClientType::Confidential => Some(hash_client_secret(&client_secret)),
            ClientType::Public => None,
        },
        name: name.to_string(),
        redirect_uris,
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        response_types: vec!["code".to_string()],
        scopes,
        client_type,
        logo_uri: None,
        policy_uri: None,
        tos_uri: None,
        created_at: now,
        updated_at: now,
    };

    (client, client_secret)
}

/// Authenticate a client using client_id and client_secret.
pub fn authenticate_client(
    client: &OAuthClient,
    client_secret: Option<&str>,
) -> Result<(), OAuthProviderError> {
    match client.client_type {
        ClientType::Public => Ok(()),
        ClientType::Confidential => {
            let secret = client_secret.ok_or(OAuthProviderError::InvalidClient)?;
            let hash = client.client_secret_hash.as_ref()
                .ok_or(OAuthProviderError::InvalidClient)?;
            if verify_client_secret(secret, hash) {
                Ok(())
            } else {
                Err(OAuthProviderError::InvalidClient)
            }
        }
    }
}

use base64::Engine;
use subtle;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify_secret() {
        let secret = "my_client_secret";
        let hash = hash_client_secret(secret);
        assert!(verify_client_secret(secret, &hash));
        assert!(!verify_client_secret("wrong_secret", &hash));
    }

    #[test]
    fn test_validate_redirect_uri() {
        assert!(validate_redirect_uri("https://app.example.com/callback").is_ok());
        assert!(validate_redirect_uri("http://localhost:3000/callback").is_ok());
        assert!(validate_redirect_uri("http://localhost/callback").is_ok());
        assert!(validate_redirect_uri("http://evil.com/callback").is_err());
        assert!(validate_redirect_uri("https://app.example.com/callback#frag").is_err());
    }

    #[test]
    fn test_build_client() {
        let (client, secret) = build_client(
            "Test App",
            vec!["https://app.example.com/callback".into()],
            ClientType::Confidential,
            vec!["openid".into()],
        );
        assert!(!client.client_id.is_empty());
        assert!(client.client_secret_hash.is_some());
        assert!(!secret.is_empty());
        // Verify the secret matches the stored hash
        assert!(verify_client_secret(&secret, client.client_secret_hash.as_ref().unwrap()));
    }

    #[test]
    fn test_build_public_client() {
        let (client, _) = build_client(
            "Public App",
            vec!["https://app.example.com/callback".into()],
            ClientType::Public,
            vec!["openid".into()],
        );
        assert!(client.client_secret_hash.is_none());
    }

    #[test]
    fn test_authenticate_client() {
        let (client, secret) = build_client(
            "App", vec!["https://a.com/cb".into()],
            ClientType::Confidential, vec![],
        );
        assert!(authenticate_client(&client, Some(&secret)).is_ok());
        assert!(authenticate_client(&client, Some("wrong")).is_err());
        assert!(authenticate_client(&client, None).is_err());
    }
}
