// Integration tests for better-auth-axum
//
// HTTP-level tests using tower::ServiceExt::oneshot to exercise the full
// Axum router without starting a real TCP server.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use better_auth::internal_adapter::{
    AdapterError, CreateSessionOptions, InternalAdapter, OAuthUserResult, SessionWithUser,
};
use better_auth_axum::BetterAuth;
use better_auth_core::options::BetterAuthOptions;

// ─── Test Adapter ─────────────────────────────────────────────────

/// A stub adapter for integration tests.
///
/// Returns sensible defaults so route handlers can succeed without a
/// real database. `create_user` echoes the input data back (with an
/// `id` if missing), `find_user_by_email` returns `None` (no
/// duplicate user), and `create_session` returns a session with a
/// token field.
struct TestAdapter;

#[async_trait::async_trait]
impl InternalAdapter for TestAdapter {
    async fn create_user(&self, data: serde_json::Value) -> Result<serde_json::Value, AdapterError> {
        // Echo the data back so the sign-up handler has a valid user
        Ok(data)
    }
    async fn find_user_by_id(&self, _: &str) -> Result<Option<serde_json::Value>, AdapterError> {
        Ok(None)
    }
    async fn find_user_by_email(&self, _: &str) -> Result<Option<serde_json::Value>, AdapterError> {
        // Return None so sign-up does not see a duplicate
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

/// Build a fresh `Router` backed by the stub adapter.
fn build_app() -> axum::Router {
    let mut options = BetterAuthOptions::new("test-secret-that-is-long-enough-32");
    options.email_and_password.enabled = true;
    let adapter: Arc<dyn InternalAdapter> = Arc::new(TestAdapter);
    let auth = BetterAuth::new(options, adapter);
    auth.router()
}

/// Collect the response body into a `String`.
async fn body_to_string(body: Body) -> String {
    let bytes = body.collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

// ─── Tests ───────────────────────────────────────────────────────

#[tokio::test]
async fn health_check_returns_ok() {
    let app = build_app();

    let request = Request::get("/api/auth/ok")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = body_to_string(response.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json, serde_json::json!({"ok": true}));
}

#[tokio::test]
async fn sign_up_creates_user() {
    let app = build_app();

    let payload = serde_json::json!({
        "name": "Test",
        "email": "test@example.com",
        "password": "password123"
    });

    let request = Request::post("/api/auth/sign-up/email")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // The Axum handler returns StatusCode::CREATED (201)
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = body_to_string(response.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();

    // Response should contain a user object and a token
    assert!(json.get("user").is_some(), "response should contain 'user'");
    assert!(json.get("token").is_some(), "response should contain 'token'");
}

#[tokio::test]
async fn get_session_without_token_returns_null() {
    let app = build_app();

    let request = Request::get("/api/auth/session")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = body_to_string(response.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(json.is_null(), "session response without token should be null");
}

#[tokio::test]
async fn callback_error_redirects() {
    let app = build_app();

    let request = Request::get("/api/auth/callback/google?error=access_denied")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // The callback handler returns 302 Found (matching TS behavior)
    assert_eq!(response.status(), StatusCode::FOUND);

    let location = response
        .headers()
        .get("location")
        .expect("redirect should have Location header")
        .to_str()
        .unwrap();

    assert!(
        location.contains("error=access_denied"),
        "redirect location should contain the error: {location}"
    );
}

#[tokio::test]
async fn error_page_returns_html() {
    let app = build_app();

    let request = Request::get("/api/auth/error?error=test")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get("content-type")
        .expect("error page should have content-type")
        .to_str()
        .unwrap();
    assert!(
        content_type.contains("text/html"),
        "error page content-type should be text/html, got: {content_type}"
    );

    let body = body_to_string(response.into_body()).await;
    assert!(body.contains("<!DOCTYPE html>"), "error page should contain HTML doctype");
    assert!(body.contains("test"), "error page should contain the error string");
}
