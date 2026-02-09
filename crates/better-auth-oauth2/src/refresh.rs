// Refresh access token — maps to packages/core/src/oauth2/refresh-access-token.ts
//
// Exchanges a refresh token for a new access token.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::provider::AuthenticationMethod;
use crate::tokens::OAuth2Tokens;

/// Parameters for refreshing an access token.
#[derive(Debug, Clone)]
pub struct RefreshTokenParams {
    /// The refresh token.
    pub refresh_token: String,
    /// Token endpoint URL.
    pub token_endpoint: String,
    /// OAuth client ID.
    pub client_id: String,
    /// OAuth client secret.
    pub client_secret: Option<String>,
    /// Authentication method (Basic or POST).
    pub authentication: AuthenticationMethod,
    /// Extra body parameters.
    pub extra_params: std::collections::HashMap<String, String>,
}

/// Refresh an OAuth2 access token.
///
/// Exact port of `refreshAccessToken()` in TypeScript.
pub async fn refresh_access_token(
    params: RefreshTokenParams,
) -> Result<OAuth2Tokens, better_auth_core::error::BetterAuthError> {
    let client = reqwest::Client::new();

    // Build form body
    let mut form = vec![
        ("grant_type".to_string(), "refresh_token".to_string()),
        ("refresh_token".to_string(), params.refresh_token),
    ];

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

    // Authentication
    match params.authentication {
        AuthenticationMethod::Basic => {
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

    // Extra parameters
    for (key, value) in &params.extra_params {
        form.push((key.clone(), value.clone()));
    }

    let response = client
        .post(&params.token_endpoint)
        .headers(headers)
        .form(&form)
        .send()
        .await
        .map_err(|e| {
            better_auth_core::error::BetterAuthError::Other(format!(
                "Refresh token request failed: {e}"
            ))
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(better_auth_core::error::BetterAuthError::Other(format!(
            "Refresh token endpoint returned {status}: {body}"
        )));
    }

    let data: serde_json::Value = response.json().await.map_err(|e| {
        better_auth_core::error::BetterAuthError::Other(format!(
            "Failed to parse refresh token response: {e}"
        ))
    })?;

    Ok(OAuth2Tokens::from_raw(&data))
}
