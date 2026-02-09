// Routes — mirrors packages/expo/src/routes.ts
//
// Implements the Expo authorization proxy endpoint:
// `/expo-authorization-proxy`

/// Query parameters for the `/expo-authorization-proxy` endpoint.
///
/// Maps to TS `expoAuthorizationProxy` Zod schema.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpoAuthorizationProxyQuery {
    /// The authorization URL to redirect to.
    pub authorization_url: String,
    /// Optional OAuth state parameter.
    pub oauth_state: Option<String>,
}

/// Result of processing the authorization proxy request.
///
/// Contains the cookie name/value to set and the URL to redirect to.
#[derive(Debug)]
pub struct AuthorizationProxyResult {
    /// Cookie to set (name, value, max_age_seconds).
    pub cookie: Option<(String, String, u64)>,
    /// The signed cookie to set (name, value, max_age_seconds).
    pub signed_cookie: Option<(String, String, u64)>,
    /// URL to redirect to.
    pub redirect_url: String,
}

/// Process the Expo authorization proxy request.
///
/// Maps to TS `expoAuthorizationProxy` endpoint handler:
/// 1. If `oauthState` is provided, set the OAuth state cookie and redirect
/// 2. Otherwise, extract `state` from the authorization URL, set a signed state
///    cookie, and redirect
///
/// Returns the cookies to set and the redirect URL.
pub fn process_authorization_proxy(
    query: &ExpoAuthorizationProxyQuery,
    cookie_prefix: &str,
) -> Result<AuthorizationProxyResult, &'static str> {
    if let Some(ref oauth_state) = query.oauth_state {
        // Case 1: oauthState provided — set oauth_state cookie
        let cookie_name = format!("{}.oauth_state", cookie_prefix);
        return Ok(AuthorizationProxyResult {
            cookie: Some((cookie_name, oauth_state.clone(), 600)), // 10 minutes
            signed_cookie: None,
            redirect_url: query.authorization_url.clone(),
        });
    }

    // Case 2: Extract state from authorization URL
    let url = url::Url::parse(&query.authorization_url)
        .map_err(|_| "Invalid authorization URL")?;

    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())
        .ok_or("Unexpected error")?;

    let cookie_name = format!("{}.state", cookie_prefix);

    Ok(AuthorizationProxyResult {
        cookie: None,
        signed_cookie: Some((cookie_name, state, 300)), // 5 minutes
        redirect_url: query.authorization_url.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_with_oauth_state() {
        let query = ExpoAuthorizationProxyQuery {
            authorization_url: "https://provider.com/authorize?scope=openid".to_string(),
            oauth_state: Some("my-state-123".to_string()),
        };

        let result =
            process_authorization_proxy(&query, "better-auth").unwrap();

        assert_eq!(
            result.cookie,
            Some(("better-auth.oauth_state".to_string(), "my-state-123".to_string(), 600))
        );
        assert!(result.signed_cookie.is_none());
        assert_eq!(result.redirect_url, "https://provider.com/authorize?scope=openid");
    }

    #[test]
    fn test_process_without_oauth_state() {
        let query = ExpoAuthorizationProxyQuery {
            authorization_url:
                "https://provider.com/authorize?state=abc123&scope=openid".to_string(),
            oauth_state: None,
        };

        let result =
            process_authorization_proxy(&query, "better-auth").unwrap();

        assert!(result.cookie.is_none());
        assert_eq!(
            result.signed_cookie,
            Some(("better-auth.state".to_string(), "abc123".to_string(), 300))
        );
    }

    #[test]
    fn test_process_missing_state() {
        let query = ExpoAuthorizationProxyQuery {
            authorization_url: "https://provider.com/authorize?scope=openid".to_string(),
            oauth_state: None,
        };

        let result = process_authorization_proxy(&query, "better-auth");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Unexpected error");
    }

    #[test]
    fn test_process_invalid_url() {
        let query = ExpoAuthorizationProxyQuery {
            authorization_url: "not-a-valid-url".to_string(),
            oauth_state: None,
        };

        let result = process_authorization_proxy(&query, "better-auth");
        assert!(result.is_err());
    }
}
