//! OAuth 2.0 grant type processing.

use crate::config::OAuthProviderOptions;
use crate::error::OAuthProviderError;
use crate::types::*;

/// Validate an authorization request.
pub fn validate_authorization_request(
    request: &AuthorizationRequest,
    client: &OAuthClient,
    options: &OAuthProviderOptions,
) -> Result<(), OAuthProviderError> {
    // Check response_type
    if request.response_type != "code" {
        return Err(OAuthProviderError::UnsupportedResponseType);
    }

    // Validate redirect_uri
    if let Some(ref uri) = request.redirect_uri {
        if !client.redirect_uris.iter().any(|u| u == uri) {
            return Err(OAuthProviderError::InvalidRedirectUri);
        }
    } else if client.redirect_uris.len() != 1 {
        return Err(OAuthProviderError::InvalidRequest);
    }

    // PKCE required for public clients
    if client.client_type == ClientType::Public && options.require_pkce {
        if request.code_challenge.is_none() {
            return Err(OAuthProviderError::InvalidCodeChallenge);
        }
    }

    // Validate scopes
    if let Some(ref scope) = request.scope {
        for s in scope.split_whitespace() {
            if !options.scopes.contains(&s.to_string()) {
                return Err(OAuthProviderError::InvalidScope);
            }
        }
    }

    Ok(())
}

/// Validate a token request for authorization_code grant.
pub fn validate_token_request(
    request: &TokenRequest,
    stored_code: &AuthorizationCode,
    client: &OAuthClient,
) -> Result<(), OAuthProviderError> {
    // Check grant type
    if request.grant_type != "authorization_code" {
        return Err(OAuthProviderError::UnsupportedGrantType);
    }

    // Verify code not used
    if stored_code.used {
        return Err(OAuthProviderError::InvalidGrant);
    }

    // Verify code not expired
    if stored_code.expires_at < chrono::Utc::now() {
        return Err(OAuthProviderError::InvalidGrant);
    }

    // Verify client_id matches
    if stored_code.client_id != client.client_id {
        return Err(OAuthProviderError::InvalidClient);
    }

    // Verify redirect_uri matches
    if let Some(ref uri) = request.redirect_uri {
        if *uri != stored_code.redirect_uri {
            return Err(OAuthProviderError::InvalidGrant);
        }
    }

    // Verify PKCE
    if let Some(ref challenge) = stored_code.code_challenge {
        let verifier = request.code_verifier.as_ref()
            .ok_or(OAuthProviderError::InvalidCodeChallenge)?;
        let method = stored_code.code_challenge_method.as_deref().unwrap_or("S256");
        crate::pkce::verify_code_verifier(verifier, challenge, method)?;
    }

    Ok(())
}

/// Validate requested scopes against client's allowed scopes.
pub fn validate_scopes(
    requested: &str,
    _client: &OAuthClient,
    options: &OAuthProviderOptions,
) -> Result<String, OAuthProviderError> {
    let scopes: Vec<&str> = requested.split_whitespace().collect();
    for scope in &scopes {
        if !options.scopes.contains(&scope.to_string()) {
            return Err(OAuthProviderError::InvalidScope);
        }
    }
    Ok(scopes.join(" "))
}

/// Get the effective redirect URI from the request or client defaults.
pub fn resolve_redirect_uri(
    request: &AuthorizationRequest,
    client: &OAuthClient,
) -> Result<String, OAuthProviderError> {
    if let Some(ref uri) = request.redirect_uri {
        if client.redirect_uris.contains(uri) {
            Ok(uri.clone())
        } else {
            Err(OAuthProviderError::InvalidRedirectUri)
        }
    } else if client.redirect_uris.len() == 1 {
        Ok(client.redirect_uris[0].clone())
    } else {
        Err(OAuthProviderError::InvalidRequest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn test_client() -> OAuthClient {
        OAuthClient {
            id: "id1".into(), client_id: "client1".into(),
            client_secret_hash: None, name: "Test App".into(),
            redirect_uris: vec!["https://app.example.com/callback".into()],
            grant_types: vec![GrantType::AuthorizationCode],
            response_types: vec!["code".into()],
            scopes: vec!["openid".into(), "profile".into()],
            client_type: ClientType::Public,
            logo_uri: None, policy_uri: None, tos_uri: None,
            created_at: Utc::now(), updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_validate_authorization_request() {
        let client = test_client();
        let opts = OAuthProviderOptions::default();
        let req = AuthorizationRequest {
            response_type: "code".into(), client_id: "client1".into(),
            redirect_uri: Some("https://app.example.com/callback".into()),
            scope: Some("openid".into()), state: Some("xyz".into()),
            code_challenge: Some("challenge".into()),
            code_challenge_method: Some("S256".into()),
        };
        assert!(validate_authorization_request(&req, &client, &opts).is_ok());
    }

    #[test]
    fn test_validate_bad_redirect_uri() {
        let client = test_client();
        let opts = OAuthProviderOptions::default();
        let req = AuthorizationRequest {
            response_type: "code".into(), client_id: "client1".into(),
            redirect_uri: Some("https://evil.com/callback".into()),
            scope: None, state: None, code_challenge: Some("c".into()),
            code_challenge_method: Some("S256".into()),
        };
        assert_eq!(
            validate_authorization_request(&req, &client, &opts).unwrap_err(),
            OAuthProviderError::InvalidRedirectUri,
        );
    }

    #[test]
    fn test_validate_pkce_required() {
        let client = test_client();
        let opts = OAuthProviderOptions::default();
        let req = AuthorizationRequest {
            response_type: "code".into(), client_id: "client1".into(),
            redirect_uri: Some("https://app.example.com/callback".into()),
            scope: None, state: None,
            code_challenge: None, code_challenge_method: None,
        };
        assert_eq!(
            validate_authorization_request(&req, &client, &opts).unwrap_err(),
            OAuthProviderError::InvalidCodeChallenge,
        );
    }

    #[test]
    fn test_resolve_redirect_uri() {
        let client = test_client();
        let req = AuthorizationRequest {
            response_type: "code".into(), client_id: "c".into(),
            redirect_uri: Some("https://app.example.com/callback".into()),
            scope: None, state: None, code_challenge: None, code_challenge_method: None,
        };
        assert_eq!(
            resolve_redirect_uri(&req, &client).unwrap(),
            "https://app.example.com/callback"
        );
    }
}
