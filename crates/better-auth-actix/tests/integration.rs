// Integration tests for better-auth-actix
//
// HTTP-level tests using actix_web::test utilities to exercise the full
// Actix-web service configuration without starting a real HTTP server.

use std::sync::Arc;

use actix_web::{test, App};

use better_auth::internal_adapter::{
    AdapterError, CreateSessionOptions, InternalAdapter, OAuthUserResult, SessionWithUser,
};
use better_auth_actix::BetterAuth;
use better_auth_core::options::BetterAuthOptions;

// ─── Test Adapter ─────────────────────────────────────────────────

/// A stub adapter for integration tests.
///
/// Returns sensible defaults so route handlers can succeed without a
/// real database.
struct TestAdapter;

#[async_trait::async_trait]
impl InternalAdapter for TestAdapter {
    async fn create_user(&self, data: serde_json::Value) -> Result<serde_json::Value, AdapterError> {
        Ok(data)
    }
    async fn find_user_by_id(&self, _: &str) -> Result<Option<serde_json::Value>, AdapterError> {
        Ok(None)
    }
    async fn find_user_by_email(&self, _: &str) -> Result<Option<serde_json::Value>, AdapterError> {
        Ok(None)
    }
    async fn update_user(&self, _: &str, _: serde_json::Value) -> Result<serde_json::Value, AdapterError> {
        Ok(serde_json::json!({}))
    }
    async fn update_user_by_email(&self, _: &str, _: serde_json::Value) -> Result<serde_json::Value, AdapterError> {
        Ok(serde_json::json!({}))
    }
    async fn update_password(&self, _: &str, _: &str) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn list_users(
        &self,
        _: Option<usize>,
        _: Option<usize>,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<Vec<serde_json::Value>, AdapterError> {
        Ok(vec![])
    }
    async fn count_total_users(&self) -> Result<u64, AdapterError> {
        Ok(0)
    }
    async fn delete_user(&self, _: &str) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn create_session(
        &self,
        _user_id: &str,
        _options: Option<CreateSessionOptions>,
        _session_expiration: Option<i64>,
    ) -> Result<serde_json::Value, AdapterError> {
        Ok(serde_json::json!({
            "id": "sess-1",
            "token": "test-session-token-abc123",
            "userId": _user_id,
            "expiresAt": "2099-01-01T00:00:00Z",
            "createdAt": "2024-01-01T00:00:00Z",
            "updatedAt": "2024-01-01T00:00:00Z",
        }))
    }
    async fn find_session_by_token(&self, _: &str) -> Result<Option<serde_json::Value>, AdapterError> {
        Ok(None)
    }
    async fn find_session_and_user(&self, _: &str) -> Result<Option<SessionWithUser>, AdapterError> {
        Ok(None)
    }
    async fn update_session(&self, _: &str, _: serde_json::Value) -> Result<serde_json::Value, AdapterError> {
        Ok(serde_json::json!({}))
    }
    async fn delete_session(&self, _: &str) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn list_sessions_for_user(&self, _: &str) -> Result<Vec<serde_json::Value>, AdapterError> {
        Ok(vec![])
    }
    async fn find_sessions(&self, _: &[String]) -> Result<Vec<serde_json::Value>, AdapterError> {
        Ok(vec![])
    }
    async fn delete_sessions_for_user(&self, _: &str) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn create_account(&self, _: serde_json::Value) -> Result<serde_json::Value, AdapterError> {
        Ok(serde_json::json!({}))
    }
    async fn find_accounts_by_user_id(&self, _: &str) -> Result<Vec<serde_json::Value>, AdapterError> {
        Ok(vec![])
    }
    async fn find_account_by_provider(&self, _: &str, _: &str) -> Result<Option<serde_json::Value>, AdapterError> {
        Ok(None)
    }
    async fn update_account(&self, _: &str, _: &str, _: serde_json::Value) -> Result<serde_json::Value, AdapterError> {
        Ok(serde_json::json!({}))
    }
    async fn delete_account(&self, _: &str, _: &str) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn delete_accounts_by_user_id(&self, _: &str) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn find_account_by_id(&self, _: &str) -> Result<Option<serde_json::Value>, AdapterError> {
        Ok(None)
    }
    async fn update_account_by_id(&self, _: &str, _: serde_json::Value) -> Result<serde_json::Value, AdapterError> {
        Ok(serde_json::json!({}))
    }
    async fn create_oauth_user(&self, _: serde_json::Value, _: serde_json::Value) -> Result<serde_json::Value, AdapterError> {
        Ok(serde_json::json!({}))
    }
    async fn find_oauth_user(&self, _: &str, _: &str, _: &str) -> Result<Option<OAuthUserResult>, AdapterError> {
        Ok(None)
    }
    async fn link_account(&self, _: serde_json::Value) -> Result<serde_json::Value, AdapterError> {
        Ok(serde_json::json!({}))
    }
    async fn create_verification(
        &self,
        _: &str,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<serde_json::Value, AdapterError> {
        Ok(serde_json::json!({}))
    }
    async fn find_verification(&self, _: &str) -> Result<Option<serde_json::Value>, AdapterError> {
        Ok(None)
    }
    async fn delete_verification(&self, _: &str) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn delete_verification_by_identifier(&self, _: &str) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn update_verification(&self, _: &str, _: serde_json::Value) -> Result<serde_json::Value, AdapterError> {
        Ok(serde_json::json!({}))
    }
    async fn delete_user_cascade(&self, _: &str) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn create(&self, _: &str, data: serde_json::Value) -> Result<serde_json::Value, AdapterError> {
        Ok(data)
    }
    async fn find_by_id(&self, _: &str, _: &str) -> Result<serde_json::Value, AdapterError> {
        Ok(serde_json::json!({}))
    }
    async fn find_one(&self, _: &str, _: serde_json::Value) -> Result<serde_json::Value, AdapterError> {
        Ok(serde_json::json!({}))
    }
    async fn find_many(&self, _: &str, _: serde_json::Value) -> Result<Vec<serde_json::Value>, AdapterError> {
        Ok(vec![])
    }
    async fn update_by_id(&self, _: &str, _: &str, _: serde_json::Value) -> Result<serde_json::Value, AdapterError> {
        Ok(serde_json::json!({}))
    }
    async fn delete_by_id(&self, _: &str, _: &str) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn delete_many(&self, _: &str, _: serde_json::Value) -> Result<i64, AdapterError> {
        Ok(0)
    }
}

// ─── Helper ──────────────────────────────────────────────────────

/// Build a `BetterAuth` instance backed by the stub adapter.
fn build_auth() -> BetterAuth {
    let mut options = BetterAuthOptions::new("test-secret-that-is-long-enough-32");
    options.email_and_password.enabled = true;
    let adapter: Arc<dyn InternalAdapter> = Arc::new(TestAdapter);
    BetterAuth::new(options, adapter)
}

// ─── Tests ───────────────────────────────────────────────────────

#[actix_rt::test]
async fn health_check_returns_ok() {
    let auth = build_auth();
    let app = test::init_service(App::new().configure(auth.configure())).await;

    let req = test::TestRequest::get()
        .uri("/api/auth/ok")
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), actix_web::http::StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body, serde_json::json!({"ok": true}));
}

#[actix_rt::test]
async fn sign_up_creates_user() {
    let auth = build_auth();
    let app = test::init_service(App::new().configure(auth.configure())).await;

    let payload = serde_json::json!({
        "name": "Test",
        "email": "test@example.com",
        "password": "password123"
    });

    let req = test::TestRequest::post()
        .uri("/api/auth/sign-up/email")
        .set_json(&payload)
        .to_request();
    let resp = test::call_service(&app, req).await;

    // The Actix handler returns CREATED (201)
    assert_eq!(resp.status(), actix_web::http::StatusCode::CREATED);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body.get("user").is_some(), "response should contain 'user'");
    assert!(body.get("token").is_some(), "response should contain 'token'");
}

#[actix_rt::test]
async fn get_session_without_token_returns_null() {
    let auth = build_auth();
    let app = test::init_service(App::new().configure(auth.configure())).await;

    let req = test::TestRequest::get()
        .uri("/api/auth/session")
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), actix_web::http::StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body.is_null(), "session response without token should be null");
}

#[actix_rt::test]
async fn error_page_returns_html() {
    let auth = build_auth();
    let app = test::init_service(App::new().configure(auth.configure())).await;

    let req = test::TestRequest::get()
        .uri("/api/auth/error?error=test")
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), actix_web::http::StatusCode::OK);

    let content_type = resp
        .headers()
        .get("content-type")
        .expect("error page should have content-type")
        .to_str()
        .unwrap();
    assert!(
        content_type.contains("text/html"),
        "error page content-type should be text/html, got: {content_type}"
    );

    let body_bytes = test::read_body(resp).await;
    let body = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(body.contains("<!DOCTYPE html>"), "error page should contain HTML doctype");
    assert!(body.contains("test"), "error page should contain the error string");
}
