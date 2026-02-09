// Authorization code exchange — maps to packages/core/src/oauth2/validate-authorization-code.ts
//
// Exchanges an authorization code for tokens at the provider's token endpoint.
// Supports both Basic and POST authentication methods.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::provider::AuthenticationMethod;
use crate::tokens::OAuth2Tokens;

/// Parameters for exchanging an authorization code.
#[derive(Debug, Clone)]
pub struct CodeExchangeParams {
    /// The authorization code from the callback.
    pub code: String,
    /// The redirect URI (must match the one used in the auth request).
    pub redirect_uri: String,
    /// Token endpoint URL.
    pub token_endpoint: String,
    /// OAuth client ID.
    pub client_id: String,
    /// OAuth client secret.
    pub client_secret: Option<String>,
    /// PKCE code verifier.
    pub code_verifier: Option<String>,
    /// Device ID (used by some providers like TikTok).
    pub device_id: Option<String>,
    /// Client key (used by TikTok instead of client_id).
    pub client_key: Option<String>,
    /// Authentication method (Basic or POST).
    pub authentication: AuthenticationMethod,
    /// Additional request headers.
    pub headers: std::collections::HashMap<String, String>,
    /// Additional body parameters.
    pub additional_params: std::collections::HashMap<String, String>,
}

/// Exchange an authorization code for OAuth2 tokens.
///
/// Exact port of `validateAuthorizationCode()` in TypeScript.
pub async fn validate_authorization_code(
    params: CodeExchangeParams,
) -> Result<OAuth2Tokens, better_auth_core::error::BetterAuthError> {
    let client = reqwest::Client::new();

    // Build form body
    let mut form = vec![
        ("grant_type".to_string(), "authorization_code".to_string()),
        ("code".to_string(), params.code),
        ("redirect_uri".to_string(), params.redirect_uri),
    ];

    if let Some(verifier) = &params.code_verifier {
        form.push(("code_verifier".to_string(), verifier.clone()));
    }
    if let Some(key) = &params.client_key {
        form.push(("client_key".to_string(), key.clone()));
    }
    if let Some(device_id) = &params.device_id {
        form.push(("device_id".to_string(), device_id.clone()));
    }

    // Build headers
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        "application/x-www-form-urlencoded".parse().unwrap(),
    );
    headers.insert(
        reqwest::header::ACCEPT,
        "application/json".parse().unwrap(),
    );

    // Add custom headers
    for (key, value) in &params.headers {
        if let (Ok(name), Ok(val)) = (
            reqwest::header::HeaderName::from_bytes(key.as_bytes()),
            reqwest::header::HeaderValue::from_str(value),
        ) {
            headers.insert(name, val);
        }
    }

    // Authentication
    match params.authentication {
        AuthenticationMethod::Basic => {
            // RFC 7617: Base64 encode client_id:client_secret
            let credentials = format!(
                "{}:{}",
                params.client_id,
                params.client_secret.as_deref().unwrap_or("")
            );
            let encoded = STANDARD.encode(credentials.as_bytes());
            headers.insert(
                reqwest::header::AUTHORIZATION,
                format!("Basic {encoded}").parse().unwrap(),
            );
        }
        AuthenticationMethod::Post => {
            form.push(("client_id".to_string(), params.client_id));
            if let Some(secret) = &params.client_secret {
                form.push(("client_secret".to_string(), secret.clone()));
            }
        }
    }

    // Additional parameters (only add if not already present)
    let existing_keys: std::collections::HashSet<_> =
        form.iter().map(|(k, _)| k.clone()).collect();
    for (key, value) in &params.additional_params {
        if !existing_keys.contains(key) {
            form.push((key.clone(), value.clone()));
        }
    }

    let response = client
        .post(&params.token_endpoint)
        .headers(headers)
        .form(&form)
        .send()
        .await
        .map_err(|e| {
            better_auth_core::error::BetterAuthError::Other(format!(
                "Token endpoint request failed: {e}"
            ))
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(better_auth_core::error::BetterAuthError::Other(format!(
            "Token endpoint returned {status}: {body}"
        )));
    }

    let data: serde_json::Value = response.json().await.map_err(|e| {
        better_auth_core::error::BetterAuthError::Other(format!(
            "Failed to parse token response: {e}"
        ))
    })?;

    Ok(OAuth2Tokens::from_raw(&data))
}
