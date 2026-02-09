//! OIDC Provider plugin integration tests.
//!
//! Covers: metadata discovery, OAuth2 client types, authorization queries,
//! token requests/responses, consent, userinfo, client registration,
//! PKCE verification, and error types.

#[cfg(all(test, feature = "plugin-oidc-provider"))]
mod oidc_metadata_tests {
    use better_auth::plugins::oidc_provider::*;

    #[test]
    fn build_metadata_issuer() {
        let meta = build_oidc_metadata("https://auth.example.com");
        assert_eq!(meta.issuer, "https://auth.example.com");
    }

    #[test]
    fn build_metadata_endpoints() {
        let meta = build_oidc_metadata("https://auth.example.com");
        assert!(meta.authorization_endpoint.contains("/authorize"));
        assert!(meta.token_endpoint.contains("/token"));
        assert!(meta.userinfo_endpoint.contains("/userinfo"));
        assert!(meta.jwks_uri.contains("/jwks"));
    }

    #[test]
    fn build_metadata_response_types() {
        let meta = build_oidc_metadata("https://auth.example.com");
        assert!(meta.response_types_supported.contains(&"code".to_string()));
    }

    #[test]
    fn build_metadata_grant_types() {
        let meta = build_oidc_metadata("https://auth.example.com");
        assert!(meta.grant_types_supported.contains(&"authorization_code".to_string()));
    }

    #[test]
    fn build_metadata_scopes() {
        let meta = build_oidc_metadata("https://auth.example.com");
        assert!(meta.scopes_supported.contains(&"openid".to_string()));
        assert!(meta.scopes_supported.contains(&"email".to_string()));
        assert!(meta.scopes_supported.contains(&"profile".to_string()));
    }

    #[test]
    fn metadata_serde_round_trip() {
        let meta = build_oidc_metadata("https://auth.example.com");
        let json_str = serde_json::to_string(&meta).unwrap();
        let parsed: OidcMetadata = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.issuer, "https://auth.example.com");
    }
}

#[cfg(all(test, feature = "plugin-oidc-provider"))]
mod oidc_type_tests {
    use better_auth::plugins::oidc_provider::*;
    use serde_json::json;

    // ── OAuth Client ────────────────────────────────────────────

    #[test]
    fn oauth_client_serde() {
        let v = json!({
            "id": "client-1",
            "clientId": "my-app",
            "clientSecret": "secret-hash",
            "name": "My Application",
            "redirectUris": ["http://localhost:3000/callback"],
            "scopes": "openid email profile",
            "disabled": false,
            "icon": null,
            "metadata": null,
            "createdAt": "2024-01-01T00:00:00Z"
        });
        let client: OAuthClient = serde_json::from_value(v).unwrap();
        assert_eq!(client.client_id, "my-app");
        assert_eq!(client.redirect_uris.len(), 1);
        assert!(!client.disabled);
    }

    #[test]
    fn oauth_client_multiple_redirects() {
        let v = json!({
            "id": "client-2",
            "clientId": "multi-redirect",
            "clientSecret": "secret",
            "name": "Multi App",
            "redirectUris": [
                "http://localhost:3000/cb",
                "https://app.example.com/cb"
            ],
            "scopes": "openid",
            "disabled": false,
            "createdAt": "2024-01-01T00:00:00Z"
        });
        let client: OAuthClient = serde_json::from_value(v).unwrap();
        assert_eq!(client.redirect_uris.len(), 2);
    }

    // ── Access Token ────────────────────────────────────────────

    #[test]
    fn access_token_serde() {
        let v = json!({
            "id": "at-1",
            "token": "access-token-xyz",
            "userId": "user-1",
            "clientId": "client-1",
            "scopes": "openid email",
            "expiresAt": "2024-12-31T23:59:59Z",
            "createdAt": "2024-01-01T00:00:00Z"
        });
        let token: OAuthAccessToken = serde_json::from_value(v).unwrap();
        assert_eq!(token.token, "access-token-xyz");
        assert_eq!(token.scopes, "openid email");
    }

    // ── Consent ─────────────────────────────────────────────────

    #[test]
    fn consent_serde() {
        let v = json!({
            "id": "consent-1",
            "userId": "user-1",
            "clientId": "client-1",
            "scopes": "openid email",
            "createdAt": "2024-01-01T00:00:00Z"
        });
        let consent: OAuthConsent = serde_json::from_value(v).unwrap();
        assert_eq!(consent.user_id, "user-1");
    }

    // ── AuthorizeQuery ──────────────────────────────────────────

    #[test]
    fn authorize_query_deser() {
        let v = json!({
            "client_id": "my-app",
            "redirect_uri": "http://localhost:3000/cb",
            "response_type": "code",
            "scope": "openid email",
            "state": "random-state"
        });
        let q: AuthorizeQuery = serde_json::from_value(v).unwrap();
        assert_eq!(q.client_id, "my-app");
        assert_eq!(q.response_type, "code");
    }

    #[test]
    fn authorize_query_with_pkce() {
        let v = json!({
            "client_id": "my-app",
            "redirect_uri": "http://localhost:3000/cb",
            "response_type": "code",
            "scope": "openid",
            "code_challenge": "abc123",
            "code_challenge_method": "S256"
        });
        let q: AuthorizeQuery = serde_json::from_value(v).unwrap();
        assert_eq!(q.code_challenge, Some("abc123".into()));
        assert_eq!(q.code_challenge_method, Some("S256".into()));
    }

    // ── TokenRequest ────────────────────────────────────────────

    #[test]
    fn token_request_auth_code() {
        let v = json!({
            "grant_type": "authorization_code",
            "code": "auth-code-xyz",
            "redirect_uri": "http://localhost:3000/cb",
            "client_id": "my-app",
            "client_secret": "my-secret"
        });
        let req: TokenRequestBody = serde_json::from_value(v).unwrap();
        assert_eq!(req.grant_type, "authorization_code");
        assert_eq!(req.code, Some("auth-code-xyz".into()));
    }

    #[test]
    fn token_request_refresh() {
        let v = json!({
            "grant_type": "refresh_token",
            "refresh_token": "refresh-xyz",
            "client_id": "my-app"
        });
        let req: TokenRequestBody = serde_json::from_value(v).unwrap();
        assert_eq!(req.grant_type, "refresh_token");
        assert_eq!(req.refresh_token, Some("refresh-xyz".into()));
    }

    // ── TokenResponse ───────────────────────────────────────────

    #[test]
    fn token_response_serde() {
        let resp = TokenResponse {
            access_token: "at_xyz".into(),
            token_type: "Bearer".into(),
            expires_in: 3600,
            refresh_token: Some("rt_xyz".into()),
            scope: Some("openid email".into()),
            id_token: Some("eyJ...".into()),
        };
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["token_type"], "Bearer");
        assert_eq!(v["expires_in"], 3600);
    }

    // ── RegisterClient ──────────────────────────────────────────

    #[test]
    fn register_client_request_deser() {
        let v = json!({
            "client_name": "New App",
            "redirect_uris": ["http://localhost:3000/cb"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"]
        });
        let req: RegisterClientBody = serde_json::from_value(v).unwrap();
        assert_eq!(req.client_name, "New App");
        assert_eq!(req.redirect_uris.len(), 1);
    }

    // ── Userinfo ────────────────────────────────────────────────

    #[test]
    fn userinfo_response_serde() {
        let resp = UserinfoResponse {
            sub: "user-1".into(),
            name: Some("John Doe".into()),
            email: Some("john@example.com".into()),
            email_verified: Some(true),
            picture: None,
            given_name: Some("John".into()),
            family_name: Some("Doe".into()),
            preferred_username: None,
            updated_at: None,
        };
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["sub"], "user-1");
        assert_eq!(v["email"], "john@example.com");
        assert_eq!(v["email_verified"], true);
    }

    // ── OidcError ───────────────────────────────────────────────

    #[test]
    fn oidc_error_serde_invalid_request() {
        let err = OidcError::invalid_request("Missing redirect_uri");
        let v = serde_json::to_value(&err).unwrap();
        assert_eq!(v["error"], "invalid_request");
    }

    #[test]
    fn oidc_error_serde_unauthorized_client() {
        let err = OidcError::unauthorized_client("Client not found");
        let v = serde_json::to_value(&err).unwrap();
        assert_eq!(v["error"], "unauthorized_client");
    }

    #[test]
    fn oidc_error_serde_invalid_grant() {
        let err = OidcError::invalid_grant("Code expired");
        let v = serde_json::to_value(&err).unwrap();
        assert_eq!(v["error"], "invalid_grant");
    }
}

#[cfg(all(test, feature = "plugin-oidc-provider"))]
mod oidc_options_tests {
    use better_auth::plugins::oidc_provider::*;

    #[test]
    fn oidc_options_default() {
        let opts = OidcOptions::default();
        assert!(opts.access_token_expires_in > 0);
        assert!(opts.refresh_token_expires_in > 0);
        assert!(opts.code_expires_in > 0);
    }

    #[test]
    fn oidc_options_custom_expiry() {
        let mut opts = OidcOptions::default();
        opts.access_token_expires_in = 7200;
        opts.refresh_token_expires_in = 86400 * 30;
        assert_eq!(opts.access_token_expires_in, 7200);
        assert_eq!(opts.refresh_token_expires_in, 86400 * 30);
    }

    #[test]
    fn trusted_client_config() {
        let client = TrustedClient {
            client_id: "trusted-1".into(),
            client_secret: "secret".into(),
            name: "Trusted App".into(),
            redirect_uris: vec!["http://localhost:3000/cb".into()],
            scopes: "openid".into(),
            icon: None,
        };
        assert_eq!(client.client_id, "trusted-1");
        assert_eq!(client.redirect_uris.len(), 1);
    }
}
