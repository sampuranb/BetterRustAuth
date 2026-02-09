//! OAuth 2.0 Authorization Server Metadata (RFC 8414).

use crate::config::OAuthProviderOptions;
use serde::{Deserialize, Serialize};

/// Authorization Server Metadata response.
/// Maps to `.well-known/oauth-authorization-server`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_documentation: Option<String>,
}

/// Build the discovery metadata document.
pub fn build_metadata(options: &OAuthProviderOptions, base_url: &str) -> AuthorizationServerMetadata {
    AuthorizationServerMetadata {
        issuer: options.issuer.clone(),
        authorization_endpoint: format!("{}/oauth/authorize", base_url),
        token_endpoint: format!("{}/oauth/token", base_url),
        introspection_endpoint: Some(format!("{}/oauth/introspect", base_url)),
        revocation_endpoint: Some(format!("{}/oauth/revoke", base_url)),
        registration_endpoint: Some(format!("{}/oauth/register", base_url)),
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "client_credentials".to_string(),
            "refresh_token".to_string(),
        ],
        token_endpoint_auth_methods_supported: vec![
            "client_secret_basic".to_string(),
            "client_secret_post".to_string(),
            "none".to_string(),
        ],
        scopes_supported: options.scopes.clone(),
        code_challenge_methods_supported: vec!["S256".to_string(), "plain".to_string()],
        service_documentation: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_metadata() {
        let opts = OAuthProviderOptions::default();
        let meta = build_metadata(&opts, "https://auth.example.com");
        assert_eq!(meta.authorization_endpoint, "https://auth.example.com/oauth/authorize");
        assert_eq!(meta.token_endpoint, "https://auth.example.com/oauth/token");
        assert!(meta.scopes_supported.contains(&"openid".to_string()));
        assert!(meta.code_challenge_methods_supported.contains(&"S256".to_string()));
    }
}
