// Authorization URL builder — maps to packages/core/src/oauth2/create-authorization-url.ts
//
// Builds the OAuth2 authorization URL with PKCE, scopes, state, and provider-specific params.

use std::collections::HashMap;

use crate::pkce::generate_code_challenge;

/// Parameters for building an authorization URL.
#[derive(Debug, Clone)]
pub struct AuthorizationUrlParams {
    /// Provider ID (e.g., "google").
    pub id: String,
    /// Authorization endpoint URL.
    pub authorization_endpoint: String,
    /// Redirect URI for the callback.
    pub redirect_uri: String,
    /// OAuth client ID.
    pub client_id: String,
    /// CSRF state parameter.
    pub state: String,
    /// PKCE code verifier (if provided, S256 challenge will be computed).
    pub code_verifier: Option<String>,
    /// Requested scopes.
    pub scopes: Option<Vec<String>>,
    /// OpenID claims to request.
    pub claims: Option<Vec<String>>,
    /// Token duration (e.g., "permanent" for Reddit).
    pub duration: Option<String>,
    /// OAuth prompt parameter.
    pub prompt: Option<String>,
    /// Google-specific: access type (e.g., "offline").
    pub access_type: Option<String>,
    /// Response type (default: "code").
    pub response_type: Option<String>,
    /// Display hint (e.g., "popup", "page").
    pub display: Option<String>,
    /// Login hint (pre-fill email).
    pub login_hint: Option<String>,
    /// Google-specific: hosted domain.
    pub hd: Option<String>,
    /// Response mode (e.g., "query", "form_post").
    pub response_mode: Option<String>,
    /// Additional query parameters.
    pub additional_params: HashMap<String, String>,
    /// Join character for scopes (default: " ").
    pub scope_joiner: Option<String>,
    /// Custom redirect URI from provider options (overrides redirect_uri).
    pub override_redirect_uri: Option<String>,
    /// Custom authorization endpoint from provider options.
    pub override_authorization_endpoint: Option<String>,
}

/// Build an OAuth2 authorization URL.
///
/// Exact port of the TypeScript `createAuthorizationURL()`.
pub fn create_authorization_url(params: AuthorizationUrlParams) -> Result<url::Url, url::ParseError> {
    let endpoint = params
        .override_authorization_endpoint
        .unwrap_or(params.authorization_endpoint);

    let mut url = url::Url::parse(&endpoint)?;

    // response_type (default: "code")
    url.query_pairs_mut()
        .append_pair("response_type", params.response_type.as_deref().unwrap_or("code"));

    // client_id
    url.query_pairs_mut().append_pair("client_id", &params.client_id);

    // state
    url.query_pairs_mut().append_pair("state", &params.state);

    // scopes
    if let Some(scopes) = &params.scopes {
        let joiner = params.scope_joiner.as_deref().unwrap_or(" ");
        url.query_pairs_mut()
            .append_pair("scope", &scopes.join(joiner));
    }

    // redirect_uri (options override takes priority)
    let redirect = params.override_redirect_uri.unwrap_or(params.redirect_uri);
    url.query_pairs_mut().append_pair("redirect_uri", &redirect);

    // Optional parameters
    if let Some(d) = &params.duration {
        url.query_pairs_mut().append_pair("duration", d);
    }
    if let Some(d) = &params.display {
        url.query_pairs_mut().append_pair("display", d);
    }
    if let Some(h) = &params.login_hint {
        url.query_pairs_mut().append_pair("login_hint", h);
    }
    if let Some(p) = &params.prompt {
        url.query_pairs_mut().append_pair("prompt", p);
    }
    if let Some(h) = &params.hd {
        url.query_pairs_mut().append_pair("hd", h);
    }
    if let Some(a) = &params.access_type {
        url.query_pairs_mut().append_pair("access_type", a);
    }
    if let Some(r) = &params.response_mode {
        url.query_pairs_mut().append_pair("response_mode", r);
    }

    // PKCE S256 code challenge
    if let Some(verifier) = &params.code_verifier {
        let challenge = generate_code_challenge(verifier);
        url.query_pairs_mut()
            .append_pair("code_challenge_method", "S256")
            .append_pair("code_challenge", &challenge);
    }

    // Claims (OpenID Connect)
    if let Some(claims) = &params.claims {
        let mut claims_obj = serde_json::Map::new();
        claims_obj.insert("email".to_string(), serde_json::Value::Null);
        claims_obj.insert("email_verified".to_string(), serde_json::Value::Null);
        for claim in claims {
            claims_obj.insert(claim.clone(), serde_json::Value::Null);
        }
        let id_token = serde_json::json!({ "id_token": claims_obj });
        url.query_pairs_mut()
            .append_pair("claims", &id_token.to_string());
    }

    // Additional parameters
    for (key, value) in &params.additional_params {
        url.query_pairs_mut().append_pair(key, value);
    }

    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_authorization_url() {
        let params = AuthorizationUrlParams {
            id: "google".to_string(),
            authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            redirect_uri: "http://localhost:3000/api/auth/callback/google".to_string(),
            client_id: "abc123".to_string(),
            state: "random-state".to_string(),
            code_verifier: Some("test-verifier".to_string()),
            scopes: Some(vec!["openid".to_string(), "email".to_string()]),
            claims: None,
            duration: None,
            prompt: None,
            access_type: Some("offline".to_string()),
            response_type: None,
            display: None,
            login_hint: None,
            hd: None,
            response_mode: None,
            additional_params: HashMap::new(),
            scope_joiner: None,
            override_redirect_uri: None,
            override_authorization_endpoint: None,
        };

        let url = create_authorization_url(params).unwrap();
        let url_str = url.to_string();

        assert!(url_str.contains("response_type=code"));
        assert!(url_str.contains("client_id=abc123"));
        assert!(url_str.contains("state=random-state"));
        assert!(url_str.contains("scope=openid+email"));
        assert!(url_str.contains("code_challenge_method=S256"));
        assert!(url_str.contains("access_type=offline"));
    }
}
