//! Token generation and management.

use base64::Engine;
use chrono::{Duration, Utc};
use crate::config::OAuthProviderOptions;
use crate::types::*;

/// Generate an opaque access token.
pub fn generate_access_token() -> String {
    let bytes: [u8; 32] = rand::random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate an opaque refresh token.
pub fn generate_refresh_token() -> String {
    let bytes: [u8; 32] = rand::random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate an authorization code.
pub fn generate_authorization_code() -> String {
    let bytes: [u8; 32] = rand::random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Build a token response.
pub fn build_token_response(
    options: &OAuthProviderOptions,
    user_id: Option<&str>,
    client_id: &str,
    scope: &str,
    include_refresh: bool,
) -> (TokenResponse, AccessToken, Option<RefreshToken>) {
    let now = Utc::now();
    let access_token_str = generate_access_token();
    let access_token = AccessToken {
        token: access_token_str.clone(),
        client_id: client_id.to_string(),
        user_id: user_id.map(String::from),
        scope: scope.to_string(),
        token_type: "Bearer".to_string(),
        expires_at: now + Duration::seconds(options.access_token_ttl),
        created_at: now,
    };

    let (refresh_token, refresh_token_str) = if include_refresh {
        let rt_str = generate_refresh_token();
        let rt = RefreshToken {
            token: rt_str.clone(),
            access_token: access_token_str.clone(),
            client_id: client_id.to_string(),
            user_id: user_id.unwrap_or_default().to_string(),
            scope: scope.to_string(),
            expires_at: now + Duration::seconds(options.refresh_token_ttl),
            revoked: false,
            created_at: now,
        };
        (Some(rt), Some(rt_str))
    } else {
        (None, None)
    };

    let response = TokenResponse {
        access_token: access_token_str,
        token_type: "Bearer".to_string(),
        expires_in: options.access_token_ttl,
        refresh_token: refresh_token_str,
        scope: Some(scope.to_string()),
    };

    (response, access_token, refresh_token)
}

/// Build an introspection response for an active token.
pub fn introspect_active_token(
    token: &AccessToken,
    username: Option<&str>,
    issuer: &str,
) -> IntrospectionResponse {
    IntrospectionResponse {
        active: true,
        scope: Some(token.scope.clone()),
        client_id: Some(token.client_id.clone()),
        username: username.map(String::from),
        token_type: Some(token.token_type.clone()),
        exp: Some(token.expires_at.timestamp()),
        iat: Some(token.created_at.timestamp()),
        sub: token.user_id.clone(),
        aud: Some(token.client_id.clone()),
        iss: Some(issuer.to_string()),
    }
}

/// Build an introspection response for an inactive token.
pub fn introspect_inactive_token() -> IntrospectionResponse {
    IntrospectionResponse {
        active: false,
        scope: None, client_id: None, username: None, token_type: None,
        exp: None, iat: None, sub: None, aud: None, iss: None,
    }
}

/// Check if an access token is expired.
pub fn is_token_expired(token: &AccessToken) -> bool {
    token.expires_at < Utc::now()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_tokens() {
        let at = generate_access_token();
        let rt = generate_refresh_token();
        let code = generate_authorization_code();
        assert!(!at.is_empty());
        assert!(!rt.is_empty());
        assert!(!code.is_empty());
        // All should be different
        assert_ne!(at, rt);
        assert_ne!(rt, code);
    }

    #[test]
    fn test_build_token_response() {
        let opts = OAuthProviderOptions::default();
        let (response, access, refresh) = build_token_response(
            &opts, Some("user1"), "client1", "openid profile", true,
        );
        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, 3600);
        assert!(response.refresh_token.is_some());
        assert_eq!(access.client_id, "client1");
        assert!(refresh.is_some());
    }

    #[test]
    fn test_build_token_response_no_refresh() {
        let opts = OAuthProviderOptions::default();
        let (response, _, refresh) = build_token_response(
            &opts, Some("user1"), "client1", "openid", false,
        );
        assert!(response.refresh_token.is_none());
        assert!(refresh.is_none());
    }

    #[test]
    fn test_introspect_active() {
        let now = Utc::now();
        let token = AccessToken {
            token: "tok".into(), client_id: "c1".into(), user_id: Some("u1".into()),
            scope: "openid".into(), token_type: "Bearer".into(),
            expires_at: now + Duration::seconds(3600), created_at: now,
        };
        let resp = introspect_active_token(&token, Some("user@example.com"), "https://auth.example.com");
        assert!(resp.active);
        assert_eq!(resp.username, Some("user@example.com".into()));
    }

    #[test]
    fn test_introspect_inactive() {
        let resp = introspect_inactive_token();
        assert!(!resp.active);
    }

    #[test]
    fn test_is_token_expired() {
        let now = Utc::now();
        let active = AccessToken {
            token: "t".into(), client_id: "c".into(), user_id: None,
            scope: "".into(), token_type: "Bearer".into(),
            expires_at: now + Duration::seconds(3600), created_at: now,
        };
        assert!(!is_token_expired(&active));

        let expired = AccessToken {
            expires_at: now - Duration::seconds(1),
            ..active
        };
        assert!(is_token_expired(&expired));
    }
}
