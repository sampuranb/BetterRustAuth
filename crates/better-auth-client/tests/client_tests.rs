//! Client SDK integration tests.
//!
//! Covers: client creation, URL building, options, session management,
//! plugin registration, error types, typed endpoints, and serde.

use better_auth_client::*;
use serde_json::json;

// ── ClientOptions ───────────────────────────────────────────────

#[test]
fn client_options_default() {
    let opts = ClientOptions::default();
    assert_eq!(opts.base_path, "/api/auth");
    assert!(opts.base_url.is_empty());
    assert!(opts.auth_token.is_none());
    assert_eq!(opts.timeout_secs, 30);
}

#[test]
fn client_options_custom_base_path() {
    let opts = ClientOptions {
        base_url: "https://example.com".into(),
        base_path: "/auth/v2".into(),
        ..Default::default()
    };
    assert_eq!(opts.base_path, "/auth/v2");
}

#[test]
fn client_options_with_token() {
    let opts = ClientOptions {
        base_url: "https://example.com".into(),
        auth_token: Some("my-token".into()),
        ..Default::default()
    };
    assert_eq!(opts.auth_token, Some("my-token".into()));
}

// ── SessionOptions ──────────────────────────────────────────────

#[test]
fn session_options_default() {
    let opts = SessionOptions::default();
    assert_eq!(opts.refetch_interval_secs, 0);
    assert_eq!(opts.cache_max_age_secs, 60);
}

// ── BetterAuthClient ────────────────────────────────────────────

#[test]
fn client_creation() {
    let client = BetterAuthClient::new(ClientOptions {
        base_url: "https://example.com".into(),
        ..Default::default()
    });
    assert_eq!(client.base_url(), "https://example.com/api/auth");
}

#[test]
fn client_custom_base_path() {
    let client = BetterAuthClient::new(ClientOptions {
        base_url: "https://example.com".into(),
        base_path: "/auth".into(),
        ..Default::default()
    });
    assert_eq!(client.base_url(), "https://example.com/auth");
}

#[test]
fn client_trailing_slash_normalized() {
    let client = BetterAuthClient::new(ClientOptions {
        base_url: "https://example.com/".into(),
        ..Default::default()
    });
    let url = client.base_url();
    assert!(!url.contains("//api"));
}

#[test]
fn client_options_accessor() {
    let client = BetterAuthClient::new(ClientOptions {
        base_url: "https://example.com".into(),
        ..Default::default()
    });
    assert_eq!(client.options().base_url, "https://example.com");
}

#[test]
fn client_http_client_exists() {
    let client = BetterAuthClient::new(ClientOptions {
        base_url: "https://example.com".into(),
        ..Default::default()
    });
    let _ = client.http_client();
}

#[test]
fn client_broadcast_exists() {
    let client = BetterAuthClient::new(ClientOptions {
        base_url: "https://example.com".into(),
        ..Default::default()
    });
    let _ = client.broadcast();
}

#[test]
fn client_clone_works() {
    let client = BetterAuthClient::new(ClientOptions {
        base_url: "https://example.com".into(),
        ..Default::default()
    });
    let cloned = client.clone();
    assert_eq!(cloned.base_url(), client.base_url());
}

// ── ClientError ─────────────────────────────────────────────────

#[test]
fn client_error_display() {
    let err = ClientError::Unauthorized {
        code: "AUTH_REQUIRED".into(),
        message: "Login required".into(),
    };
    let msg = format!("{}", err);
    assert!(msg.contains("Unauthorized"));
    assert!(msg.contains("AUTH_REQUIRED"));
}

#[test]
fn client_error_is_unauthorized() {
    let err = ClientError::Unauthorized {
        code: "AUTH_REQUIRED".into(),
        message: "Required".into(),
    };
    assert!(err.is_unauthorized());
    assert_eq!(err.status(), Some(401));
}

#[test]
fn client_error_is_network() {
    let err = ClientError::Network("Connection refused".into());
    assert!(err.is_network());
    assert_eq!(err.status(), None);
}

#[test]
fn client_error_is_rate_limited() {
    let err = ClientError::TooManyRequests {
        message: "Rate limited".into(),
    };
    assert!(err.is_rate_limited());
    assert_eq!(err.status(), Some(429));
}

#[test]
fn client_error_bad_request() {
    let err = ClientError::BadRequest {
        code: "INVALID_INPUT".into(),
        message: "Bad email".into(),
    };
    assert_eq!(err.status(), Some(400));
    assert_eq!(err.code(), Some("INVALID_INPUT"));
}

#[test]
fn client_error_forbidden() {
    let err = ClientError::Forbidden {
        code: "FORBIDDEN".into(),
        message: "No access".into(),
    };
    assert_eq!(err.status(), Some(403));
}

#[test]
fn client_error_not_found() {
    let err = ClientError::NotFound {
        message: "Resource missing".into(),
    };
    assert_eq!(err.status(), Some(404));
    assert_eq!(err.code(), None);
}

#[test]
fn client_error_conflict() {
    let err = ClientError::Conflict {
        code: "DUPLICATE".into(),
        message: "Email exists".into(),
    };
    assert_eq!(err.status(), Some(409));
}

#[test]
fn client_error_server() {
    let err = ClientError::Server {
        status: 502,
        message: "Bad gateway".into(),
    };
    assert_eq!(err.status(), Some(502));
}

#[test]
fn client_error_deserialization() {
    let err = ClientError::Deserialization("invalid json".into());
    assert_eq!(err.message(), "invalid json");
}

// ── Auth types ──────────────────────────────────────────────────

#[test]
fn sign_up_request_ser() {
    let req = SignUpRequest {
        email: "new@example.com".into(),
        password: "s3cur3P@ss".into(),
        name: "New User".into(),
        image: None,
    };
    let v = serde_json::to_value(&req).unwrap();
    assert_eq!(v["email"], "new@example.com");
    assert_eq!(v["name"], "New User");
}

#[test]
fn sign_in_request_ser() {
    let req = SignInRequest {
        email: "user@example.com".into(),
        password: "secret123".into(),
        remember_me: Some(true),
    };
    let v = serde_json::to_value(&req).unwrap();
    assert_eq!(v["email"], "user@example.com");
    assert_eq!(v["rememberMe"], true);
}

#[test]
fn session_data_deser() {
    let v = json!({
        "session": {
            "id": "sess-1",
            "userId": "user-1",
            "expiresAt": "2024-12-31T23:59:59Z"
        },
        "user": {
            "id": "user-1",
            "email": "test@example.com",
            "name": "Test User"
        }
    });
    let data: SessionData = serde_json::from_value(v).unwrap();
    assert_eq!(data.user_id(), Some("user-1"));
    assert_eq!(data.user_email(), Some("test@example.com"));
    assert_eq!(data.user_name(), Some("Test User"));
    assert_eq!(data.session_id(), Some("sess-1"));
}

#[test]
fn session_data_equality() {
    let a = SessionData {
        user: json!({"id": "u1"}),
        session: json!({"id": "s1"}),
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn social_sign_in_request_ser() {
    let req = SocialSignInRequest {
        provider: "google".into(),
        callback_url: Some("http://localhost:3000/callback".into()),
    };
    let v = serde_json::to_value(&req).unwrap();
    assert_eq!(v["provider"], "google");
    assert_eq!(v["callbackURL"], "http://localhost:3000/callback");
}

#[test]
fn update_user_request_ser() {
    let req = UpdateUserRequest {
        name: Some("Updated Name".into()),
        image: None,
        extra: Default::default(),
    };
    let v = serde_json::to_value(&req).unwrap();
    assert_eq!(v["name"], "Updated Name");
}

#[test]
fn delete_user_request_ser() {
    let req = DeleteUserRequest {
        password: Some("mypassword".into()),
        callback_url: None,
    };
    let v = serde_json::to_value(&req).unwrap();
    assert_eq!(v["password"], "mypassword");
}

#[test]
fn ok_response_deser() {
    let v = json!({"ok": true});
    let resp: OkResponse = serde_json::from_value(v).unwrap();
    assert!(resp.ok);
}

// ── Plugin system ───────────────────────────────────────────────

#[test]
fn plugin_registry_new() {
    let registry = PluginRegistry::new();
    assert!(registry.plugin_ids.is_empty());
    assert!(registry.path_methods.is_empty());
    assert!(registry.session_signals.is_empty());
}

#[test]
fn plugin_registry_register() {
    let mut registry = PluginRegistry::new();
    let plugin = OrganizationClient;
    registry.register(&plugin);
    assert_eq!(registry.plugin_ids.len(), 1);
    assert_eq!(registry.plugin_ids[0], "organization");
}

#[test]
fn plugin_registry_session_invalidation() {
    let mut registry = PluginRegistry::new();
    registry.register(&OrganizationClient);
    assert!(registry.should_invalidate_session("/organization/set-active"));
    assert!(registry.should_invalidate_session("/organization/create"));
    assert!(!registry.should_invalidate_session("/other/path"));
}

// ── Client plugin IDs ───────────────────────────────────────────

#[test]
fn organization_client_plugin_id() {
    assert_eq!(OrganizationClient.id(), "organization");
}

#[test]
fn admin_client_plugin_id() {
    assert_eq!(AdminClient.id(), "admin-client");
}

#[test]
fn two_factor_client_plugin_id() {
    assert_eq!(TwoFactorClient.id(), "two-factor");
}

// ── Session cache ───────────────────────────────────────────────

#[test]
fn session_cache_lifecycle() {
    let mut cache = SessionCache::new(60);
    assert!(!cache.has_data());
    assert!(!cache.is_fresh());

    cache.set(SessionData {
        user: json!({"id": "u1"}),
        session: json!({"id": "s1"}),
    });
    assert!(cache.has_data());
    assert!(cache.is_fresh());

    cache.invalidate();
    assert!(cache.has_data());
    assert!(!cache.is_fresh());

    cache.clear();
    assert!(!cache.has_data());
}

#[test]
fn session_cache_rate_limiting() {
    let mut cache = SessionCache::new(60);
    assert!(!cache.is_rate_limited());
    cache.mark_request();
    assert!(cache.is_rate_limited());
}

// ── Session refresh config ──────────────────────────────────────

#[test]
fn session_refresh_config_default() {
    let config = SessionRefreshConfig::default();
    assert_eq!(config.refetch_interval_secs, 0);
    assert!(config.refetch_on_focus);
    assert!(!config.refetch_when_offline);
}

// ── HTTP method display ─────────────────────────────────────────

#[test]
fn http_method_display() {
    assert_eq!(format!("{}", HttpMethod::Get), "GET");
    assert_eq!(format!("{}", HttpMethod::Post), "POST");
    assert_eq!(format!("{}", HttpMethod::Put), "PUT");
    assert_eq!(format!("{}", HttpMethod::Patch), "PATCH");
    assert_eq!(format!("{}", HttpMethod::Delete), "DELETE");
}
