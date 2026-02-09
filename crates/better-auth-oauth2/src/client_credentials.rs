// Client credentials token — maps to packages/core/src/oauth2/client-credentials-token.ts
//
// OAuth2 client credentials grant (machine-to-machine authentication).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::provider::AuthenticationMethod;
use crate::tokens::OAuth2Tokens;

/// Parameters for a client credentials token request.
#[derive(Debug, Clone)]
pub struct ClientCredentialsParams {
    /// Token endpoint URL.
    pub token_endpoint: String,
    /// OAuth client ID.
    pub client_id: String,
    /// OAuth client secret (required for client credentials).
    pub client_secret: String,
    /// Requested scope.
    pub scope: Option<String>,
    /// Authentication method.
    pub authentication: AuthenticationMethod,
}

/// Request a token using the client credentials grant.
///
/// Exact port of `clientCredentialsToken()` in TypeScript.
pub async fn client_credentials_token(
    params: ClientCredentialsParams,
) -> Result<OAuth2Tokens, better_auth_core::error::BetterAuthError> {
    let client = reqwest::Client::new();

    let mut form = vec![("grant_type".to_string(), "client_credentials".to_string())];

    if let Some(scope) = &params.scope {
        form.push(("scope".to_string(), scope.clone()));
    }

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        "application/x-www-form-urlencoded".parse().unwrap(),
    );
    headers.insert(
        reqwest::header::ACCEPT,
        "application/json".parse().unwrap(),
    );

    match params.authentication {
        AuthenticationMethod::Basic => {
            let credentials = format!("{}:{}", params.client_id, params.client_secret);
            let encoded = URL_SAFE_NO_PAD.encode(credentials.as_bytes());
            headers.insert(
                reqwest::header::AUTHORIZATION,
                format!("Basic {encoded}").parse().unwrap(),
            );
        }
        AuthenticationMethod::Post => {
            form.push(("client_id".to_string(), params.client_id));
            form.push(("client_secret".to_string(), params.client_secret));
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
                "Client credentials request failed: {e}"
            ))
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(better_auth_core::error::BetterAuthError::Other(format!(
            "Client credentials endpoint returned {status}: {body}"
        )));
    }

    let data: serde_json::Value = response.json().await.map_err(|e| {
        better_auth_core::error::BetterAuthError::Other(format!(
            "Failed to parse client credentials response: {e}"
        ))
    })?;

    Ok(OAuth2Tokens::from_raw(&data))
}
