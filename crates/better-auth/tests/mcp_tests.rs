//! MCP plugin integration tests.
//!
//! Covers: MCP server metadata, protected resource metadata, PKCE verification,
//! type serialization, registration request/response, authorization queries,
//! token types, and error types.

#[cfg(all(test, feature = "plugin-mcp"))]
mod mcp_metadata_tests {
    use better_auth::plugins::mcp::*;

    #[test]
    fn build_server_metadata_issuer() {
        let meta = build_mcp_metadata("https://auth.example.com");
        assert_eq!(meta.issuer, "https://auth.example.com");
    }

    #[test]
    fn build_server_metadata_endpoints() {
        let meta = build_mcp_metadata("https://auth.example.com");
        assert!(meta.authorization_endpoint.contains("/mcp/authorize"));
        assert!(meta.token_endpoint.contains("/mcp/token"));
        assert!(meta.registration_endpoint.contains("/mcp/register"));
    }

    #[test]
    fn build_server_metadata_pkce() {
        let meta = build_mcp_metadata("https://auth.example.com");
        assert!(meta.code_challenge_methods_supported.contains(&"S256".to_string()));
    }

    #[test]
    fn build_server_metadata_serde_round_trip() {
        let meta = build_mcp_metadata("https://auth.example.com");
        let json_str = serde_json::to_string(&meta).unwrap();
        let parsed: McpServerMetadata = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.issuer, meta.issuer);
    }

    #[test]
    fn build_protected_resource_metadata() {
        let meta = build_mcp_protected_resource_metadata(
            "https://api.example.com",
            None,
        );
        assert!(!meta.resource.is_empty());
        assert!(meta.authorization_servers.len() > 0);
    }

    #[test]
    fn build_protected_resource_metadata_custom_resource() {
        let meta = build_mcp_protected_resource_metadata(
            "https://api.example.com",
            Some("https://custom.resource.example.com"),
        );
        assert_eq!(meta.resource, "https://custom.resource.example.com");
    }
}

#[cfg(all(test, feature = "plugin-mcp"))]
mod mcp_pkce_tests {
    use better_auth::plugins::mcp::*;

    #[test]
    fn pkce_s256_valid() {
        use base64::Engine;
        use sha2::{Sha256, Digest};

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let digest = hasher.finalize();
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);

        assert!(verify_pkce_s256(verifier, &challenge));
    }

    #[test]
    fn pkce_s256_invalid() {
        assert!(!verify_pkce_s256("verifier", "wrong_challenge"));
    }

    #[test]
    fn pkce_s256_empty_verifier() {
        assert!(!verify_pkce_s256("", "non_empty_challenge"));
    }
}

#[cfg(all(test, feature = "plugin-mcp"))]
mod mcp_type_tests {
    use better_auth::plugins::mcp::*;
    use serde_json::json;

    #[test]
    fn mcp_client_serde() {
        let v = json!({
            "id": "mc-1",
            "clientId": "mcp-client-1",
            "clientSecret": "hashed-secret",
            "name": "MCP App",
            "redirectUrls": ["http://localhost:8080/callback"],
            "type": "web",
            "authenticationScheme": "header",
            "metadata": null,
            "disabled": false,
            "createdAt": "2024-01-01T00:00:00Z",
            "updatedAt": "2024-01-01T00:00:00Z"
        });
        let client: McpClient = serde_json::from_value(v).unwrap();
        assert_eq!(client.client_id, "mcp-client-1");
        assert!(!client.disabled);
    }

    #[test]
    fn mcp_register_body_deser() {
        let v = json!({
            "client_name": "New MCP Client",
            "redirect_uris": ["http://localhost:8080/cb"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post"
        });
        let body: McpRegisterBody = serde_json::from_value(v).unwrap();
        assert_eq!(body.client_name, Some("New MCP Client".into()));
        assert_eq!(body.redirect_uris.len(), 1);
    }

    #[test]
    fn mcp_register_response_ser() {
        let resp = McpRegisterResponse {
            client_id: "new-client-id".into(),
            client_secret: Some("generated-secret".into()),
            client_name: Some("New Client".into()),
            client_uri: None,
            logo_uri: None,
            redirect_uris: vec!["http://localhost/cb".into()],
            grant_types: vec!["authorization_code".into()],
            response_types: vec!["code".into()],
            token_endpoint_auth_method: "client_secret_post".into(),
            client_id_issued_at: 1714000000,
            client_secret_expires_at: 0,
        };
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["client_id"], "new-client-id");
        assert_eq!(v["client_secret_expires_at"], 0);
    }

    #[test]
    fn mcp_authorize_query_deser() {
        let v = json!({
            "client_id": "mc-1",
            "redirect_uri": "http://localhost:8080/cb",
            "response_type": "code",
            "scope": "openid",
            "state": "state123",
            "code_challenge": "challenge",
            "code_challenge_method": "S256"
        });
        let q: McpAuthorizeQuery = serde_json::from_value(v).unwrap();
        assert_eq!(q.client_id, "mc-1");
        assert_eq!(q.code_challenge, Some("challenge".into()));
    }

    #[test]
    fn mcp_token_body_deser() {
        let v = json!({
            "grant_type": "authorization_code",
            "code": "auth-code",
            "redirect_uri": "http://localhost/cb",
            "client_id": "mc-1",
            "client_secret": "secret",
            "code_verifier": "verifier123"
        });
        let body: McpTokenBody = serde_json::from_value(v).unwrap();
        assert_eq!(body.grant_type, "authorization_code");
        assert_eq!(body.code_verifier, Some("verifier123".into()));
    }

    #[test]
    fn mcp_token_response_ser() {
        let resp = McpTokenResponse {
            access_token: "at_xyz".into(),
            token_type: "Bearer".into(),
            expires_in: 3600,
            refresh_token: Some("rt_xyz".into()),
            scope: Some("openid".into()),
            id_token: None,
        };
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["token_type"], "Bearer");
        assert_eq!(v["expires_in"], 3600);
    }

    #[test]
    fn mcp_access_token_serde() {
        let v = json!({
            "id": "at-1",
            "accessToken": "access-token",
            "userId": "user-1",
            "clientId": "mc-1",
            "scopes": "openid",
            "accessTokenExpiresAt": "2024-12-31T23:59:59Z",
            "createdAt": "2024-01-01T00:00:00Z",
            "updatedAt": "2024-01-01T00:00:00Z"
        });
        let token: McpAccessToken = serde_json::from_value(v).unwrap();
        assert_eq!(token.access_token, "access-token");
    }

    #[test]
    fn mcp_refresh_token_serde() {
        let v = json!({
            "id": "rt-1",
            "token": "refresh-token",
            "accessTokenId": "at-1",
            "userId": "user-1",
            "clientId": "mc-1",
            "expiresAt": "2024-12-31T23:59:59Z",
            "createdAt": "2024-01-01T00:00:00Z",
            "updatedAt": "2024-01-01T00:00:00Z"
        });
        let token: McpRefreshToken = serde_json::from_value(v).unwrap();
        assert_eq!(token.token, "refresh-token");
    }
}

#[cfg(all(test, feature = "plugin-mcp"))]
mod mcp_error_tests {
    use better_auth::plugins::mcp::*;

    #[test]
    fn mcp_error_display() {
        let err = McpError::invalid_client("Client not found");
        let msg = format!("{}", err);
        assert!(!msg.is_empty());
    }

    #[test]
    fn mcp_error_invalid_request() {
        let err = McpError::invalid_request("Missing parameter");
        let msg = format!("{}", err);
        assert!(msg.contains("Missing") || !msg.is_empty());
    }

    #[test]
    fn mcp_error_invalid_grant() {
        let err = McpError::invalid_grant("Grant expired");
        let msg = format!("{}", err);
        assert!(!msg.is_empty());
    }
}
