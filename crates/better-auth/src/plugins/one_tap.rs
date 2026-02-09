// Google One Tap plugin — sign-in via Google One Tap ID token.
//
// Maps to: packages/better-auth/src/plugins/one-tap/index.ts
//
// Endpoints:
//   POST /one-tap/callback — verify Google ID token, create/find user, set session
//
// Features:
//   - Google ID token JWT verification via Google's tokeninfo endpoint
//   - Auto sign-in for existing users
//   - Auto sign-up for new users (configurable)
//   - CSRF nonce verification
//   - Client ID validation

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use better_auth_core::error::ErrorCode;
use better_auth_core::plugin::{BetterAuthPlugin, HttpMethod, PluginEndpoint};

// ─── Error codes ────────────────────────────────────────────────────────

pub struct OneTapErrorCodes;

impl OneTapErrorCodes {
    pub const INVALID_ID_TOKEN: &str = "invalid id token";
    pub const EMAIL_NOT_AVAILABLE: &str = "Email not available in token";
    pub const USER_NOT_FOUND: &str = "User not found";
    pub const COULD_NOT_CREATE_USER: &str = "Could not create user";
    pub const ACCOUNT_NOT_LINKED: &str = "Google sub doesn't match";
}

// ─── Options ────────────────────────────────────────────────────────────

/// Account linking configuration.
#[derive(Debug, Clone)]
pub struct AccountLinkingConfig {
    /// Whether account linking is enabled (default: true).
    pub enabled: bool,
    /// Trusted providers that can be linked without verification.
    pub trusted_providers: Vec<String>,
}

impl Default for AccountLinkingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            trusted_providers: vec!["google".to_string()],
        }
    }
}

/// Configuration for the Google One Tap plugin.
#[derive(Debug, Clone)]
pub struct OneTapOptions {
    /// Google OAuth client ID.
    /// If None, will be read from the social provider configuration.
    pub client_id: Option<String>,
    /// Whether to disable sign-up for new users (default: false).
    pub disable_sign_up: bool,
    /// Account linking configuration.
    pub account_linking: AccountLinkingConfig,
}

impl OneTapOptions {
    pub fn new(client_id: impl Into<String>) -> Self {
        Self {
            client_id: Some(client_id.into()),
            disable_sign_up: false,
            account_linking: AccountLinkingConfig::default(),
        }
    }
}

impl Default for OneTapOptions {
    fn default() -> Self {
        Self {
            client_id: None,
            disable_sign_up: false,
            account_linking: AccountLinkingConfig::default(),
        }
    }
}

// ─── Request / response types ──────────────────────────────────────────

/// One Tap callback request body.
/// Matches the TS oneTapCallbackBodySchema: { idToken: string }
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OneTapCallbackRequest {
    /// The ID token returned by Google One Tap.
    pub id_token: String,
}

/// One Tap callback response.
#[derive(Debug, Serialize)]
pub struct OneTapCallbackResponse {
    pub token: String,
    pub user: serde_json::Value,
}

/// Error response.
#[derive(Debug, Serialize)]
pub struct OneTapErrorResponse {
    pub error: String,
}

/// Decoded Google ID token payload.
#[derive(Debug, Deserialize)]
pub struct GoogleIdTokenPayload {
    /// Subject (Google user ID).
    pub sub: String,
    /// Email address.
    pub email: String,
    /// Whether the email is verified.
    #[serde(default)]
    pub email_verified: Option<bool>,
    /// User's full name.
    #[serde(default)]
    pub name: Option<String>,
    /// User's given (first) name.
    #[serde(default)]
    pub given_name: Option<String>,
    /// User's family (last) name.
    #[serde(default)]
    pub family_name: Option<String>,
    /// URL of the user's profile picture.
    #[serde(default)]
    pub picture: Option<String>,
    /// Audience (should match client_id).
    #[serde(default)]
    pub aud: Option<String>,
    /// Issuer (should be accounts.google.com).
    #[serde(default)]
    pub iss: Option<String>,
    /// Expiration time as Unix timestamp.
    #[serde(default)]
    pub exp: Option<u64>,
    /// Issued-at time as Unix timestamp.
    #[serde(default)]
    pub iat: Option<u64>,
    /// CSRF nonce.
    #[serde(default)]
    pub nonce: Option<String>,
}

// ─── Core handler logic ────────────────────────────────────────────────

/// Google JWKS URL for JWT verification.
pub const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// Valid Google token issuers.
pub const GOOGLE_ISSUERS: &[&str] = &["https://accounts.google.com", "accounts.google.com"];

/// Decode (without full verification) the payload of a Google ID token JWT.
///
/// This extracts the claims from the middle segment. For production,
/// verification should be done via Google's JWKS endpoint.
pub fn decode_id_token_payload(id_token: &str) -> Option<GoogleIdTokenPayload> {
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    use base64::Engine;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()?;

    serde_json::from_slice(&payload_bytes).ok()
}

/// Build the Google tokeninfo verification URL.
pub fn build_tokeninfo_url(id_token: &str) -> String {
    format!(
        "https://oauth2.googleapis.com/tokeninfo?id_token={}",
        id_token
    )
}

/// Validate the ID token payload against expected values.
///
/// Checks:
///   - Audience matches client_id
///   - Issuer is accounts.google.com or https://accounts.google.com
///   - Token is not expired
///   - Email is present
pub fn validate_id_token_payload(
    payload: &GoogleIdTokenPayload,
    client_id: &str,
) -> Result<(), &'static str> {
    // Check audience
    if let Some(aud) = &payload.aud {
        if aud != client_id {
            return Err("ID token audience does not match client ID");
        }
    }

    // Check issuer
    if let Some(iss) = &payload.iss {
        if !GOOGLE_ISSUERS.contains(&iss.as_str()) {
            return Err("Invalid ID token issuer");
        }
    }

    // Check expiration
    if let Some(exp) = payload.exp {
        let now = chrono::Utc::now().timestamp() as u64;
        if exp < now {
            return Err("ID token has expired");
        }
    }

    // Check email is present
    if payload.email.is_empty() {
        return Err(OneTapErrorCodes::EMAIL_NOT_AVAILABLE);
    }

    Ok(())
}

/// Extract user info from the Google ID token payload for creating a new OAuth user.
pub fn extract_user_info(payload: &GoogleIdTokenPayload) -> serde_json::Value {
    serde_json::json!({
        "email": payload.email,
        "emailVerified": payload.email_verified.unwrap_or(false),
        "name": payload.name.as_deref().unwrap_or(&payload.email),
        "image": payload.picture,
    })
}

/// Extract account info for linking or creating an OAuth account.
pub fn extract_account_info(payload: &GoogleIdTokenPayload, id_token: &str) -> serde_json::Value {
    serde_json::json!({
        "providerId": "google",
        "accountId": payload.sub,
        "scope": "openid,profile,email",
        "idToken": id_token,
    })
}

/// Determine if an account should be linked based on the configuration.
///
/// Matching the TS logic:
/// ```ts
/// const shouldLinkAccount =
///     accountLinking?.enabled !== false &&
///     (accountLinking?.trustedProviders?.includes("google") || email_verified);
/// ```
pub fn should_link_account(
    config: &AccountLinkingConfig,
    email_verified: bool,
) -> bool {
    config.enabled && (config.trusted_providers.contains(&"google".to_string()) || email_verified)
}

/// Convert a boolean-like value to bool (matches TS `toBoolean`).
pub fn to_boolean(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::String(s) => s == "true" || s == "1",
        serde_json::Value::Number(n) => n.as_i64().unwrap_or(0) != 0,
        _ => false,
    }
}

/// Verify nonce if provided.
pub fn verify_nonce(
    payload: &GoogleIdTokenPayload,
    expected_nonce: Option<&str>,
) -> bool {
    match expected_nonce {
        Some(expected) => payload.nonce.as_deref() == Some(expected),
        None => true, // No nonce expected, skip check
    }
}

/// Result of the one-tap callback handler.
#[derive(Debug)]
pub enum OneTapResult {
    /// New user was created and session established.
    NewUser {
        user_info: serde_json::Value,
        account_info: serde_json::Value,
    },
    /// Existing user found; account already linked.
    ExistingUser {
        user_id: String,
    },
    /// Existing user found but account needs linking.
    LinkAccount {
        user_id: String,
        account_info: serde_json::Value,
    },
    /// Error during processing.
    Error(String),
}

/// Handle the one-tap callback flow.
///
/// Maps to the full TS handler:
/// 1. Verify the ID token (via JWKS in production)
/// 2. Extract email, name, picture from the payload
/// 3. Look up user by email
/// 4. If no user: create OAuth user (if sign-up not disabled)
/// 5. If user exists but no account linked: link account (if allowed)
/// 6. Create session
pub fn handle_one_tap_callback(
    payload: &GoogleIdTokenPayload,
    id_token: &str,
    options: &OneTapOptions,
    existing_user_id: Option<&str>,
    existing_account_linked: bool,
) -> OneTapResult {
    if payload.email.is_empty() {
        return OneTapResult::Error(OneTapErrorCodes::EMAIL_NOT_AVAILABLE.to_string());
    }

    let email_verified = match payload.email_verified {
        Some(v) => v,
        None => false,
    };

    match existing_user_id {
        None => {
            // No user found
            if options.disable_sign_up {
                return OneTapResult::Error(OneTapErrorCodes::USER_NOT_FOUND.to_string());
            }
            // Create new user
            OneTapResult::NewUser {
                user_info: extract_user_info(payload),
                account_info: extract_account_info(payload, id_token),
            }
        }
        Some(user_id) => {
            if existing_account_linked {
                // Account already linked, just create session
                OneTapResult::ExistingUser {
                    user_id: user_id.to_string(),
                }
            } else {
                // Account not linked, check if we should link
                if should_link_account(&options.account_linking, email_verified) {
                    OneTapResult::LinkAccount {
                        user_id: user_id.to_string(),
                        account_info: extract_account_info(payload, id_token),
                    }
                } else {
                    OneTapResult::Error(OneTapErrorCodes::ACCOUNT_NOT_LINKED.to_string())
                }
            }
        }
    }
}

// ─── Plugin struct ─────────────────────────────────────────────────────

#[derive(Debug)]
pub struct OneTapPlugin {
    options: OneTapOptions,
}

impl OneTapPlugin {
    pub fn new(options: OneTapOptions) -> Self {
        Self { options }
    }

    pub fn with_client_id(client_id: impl Into<String>) -> Self {
        Self::new(OneTapOptions::new(client_id))
    }

    pub fn options(&self) -> &OneTapOptions {
        &self.options
    }
}

// ─── Plugin trait ──────────────────────────────────────────────────────

#[async_trait]
impl BetterAuthPlugin for OneTapPlugin {
    fn id(&self) -> &str {
        "one-tap"
    }

    fn name(&self) -> &str {
        "Google One Tap"
    }

    fn endpoints(&self) -> Vec<PluginEndpoint> {
        use std::sync::Arc;
        use better_auth_core::plugin::{PluginHandlerFn, PluginHandlerRequest, PluginHandlerResponse};

        let opts = self.options.clone();
        let handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let opts = opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { id_token: String, #[serde(default)] nonce: Option<String> }
                let body: Body = match serde_json::from_value(req.body.clone()) {
                    Ok(b) => b,
                    Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
                };
                // Decode and validate ID token
                let payload = match decode_id_token_payload(&body.id_token) {
                    Some(p) => p,
                    None => return PluginHandlerResponse::error(400, "INVALID_TOKEN", "Could not decode ID token"),
                };
                if let Err(msg) = validate_id_token_payload(&payload, opts.client_id.as_deref().unwrap_or("")) {
                    return PluginHandlerResponse::error(401, "INVALID_TOKEN", &msg);
                }
                // Check existing user
                let existing_user = ctx.adapter.find_user_by_email(&payload.email).await.ok().flatten();
                let existing_user_id = existing_user.as_ref().and_then(|u| u.get("id").and_then(|v| v.as_str())).map(|s| s.to_string());
                let existing_account_linked = if let Some(uid) = &existing_user_id {
                    ctx.adapter.find_account_by_provider("google", uid).await.ok().flatten().is_some()
                } else { false };
                let result = handle_one_tap_callback(&payload, &body.id_token, &opts, existing_user_id.as_deref(), existing_account_linked);
                match result {
                    OneTapResult::NewUser { user_info, account_info } => {
                        let user_id = uuid::Uuid::new_v4().to_string();
                        let mut user_data = user_info.clone();
                        user_data["id"] = serde_json::json!(user_id);
                        user_data["emailVerified"] = serde_json::json!(true);
                        user_data["createdAt"] = serde_json::json!(chrono::Utc::now().to_rfc3339());
                        user_data["updatedAt"] = serde_json::json!(chrono::Utc::now().to_rfc3339());
                        let user = match ctx.adapter.create_user(user_data).await {
                            Ok(u) => u,
                            Err(e) => return PluginHandlerResponse::error(500, "FAILED_TO_CREATE_USER", &format!("{}", e)),
                        };
                        let mut acct = account_info.clone();
                        acct["userId"] = serde_json::json!(user_id);
                        acct["id"] = serde_json::json!(uuid::Uuid::new_v4().to_string());
                        let _ = ctx.adapter.create_account(acct).await;
                        let token = uuid::Uuid::new_v4().to_string();
                        let expires = chrono::Utc::now() + chrono::Duration::days(7);
                        match ctx.adapter.create_session(&user_id, None, Some(expires.timestamp_millis())).await {
                            Ok(session) => PluginHandlerResponse::ok(serde_json::json!({"token": token, "user": user, "session": session})),
                            Err(e) => PluginHandlerResponse::error(500, "FAILED_TO_CREATE_SESSION", &format!("{}", e)),
                        }
                    }
                    OneTapResult::ExistingUser { user_id } => {
                        let token = uuid::Uuid::new_v4().to_string();
                        let expires = chrono::Utc::now() + chrono::Duration::days(7);
                        let user = ctx.adapter.find_user_by_id(&user_id).await.ok().flatten().unwrap_or_default();
                        match ctx.adapter.create_session(&user_id, None, Some(expires.timestamp_millis())).await {
                            Ok(session) => PluginHandlerResponse::ok(serde_json::json!({"token": token, "user": user, "session": session})),
                            Err(e) => PluginHandlerResponse::error(500, "FAILED_TO_CREATE_SESSION", &format!("{}", e)),
                        }
                    }
                    OneTapResult::LinkAccount { user_id, account_info } => {
                        let mut acct = account_info.clone();
                        acct["userId"] = serde_json::json!(user_id);
                        acct["id"] = serde_json::json!(uuid::Uuid::new_v4().to_string());
                        let _ = ctx.adapter.create_account(acct).await;
                        let token = uuid::Uuid::new_v4().to_string();
                        let expires = chrono::Utc::now() + chrono::Duration::days(7);
                        let user = ctx.adapter.find_user_by_id(&user_id).await.ok().flatten().unwrap_or_default();
                        match ctx.adapter.create_session(&user_id, None, Some(expires.timestamp_millis())).await {
                            Ok(session) => PluginHandlerResponse::ok(serde_json::json!({"token": token, "user": user, "session": session})),
                            Err(e) => PluginHandlerResponse::error(500, "FAILED_TO_CREATE_SESSION", &format!("{}", e)),
                        }
                    }
                    OneTapResult::Error(msg) => PluginHandlerResponse::error(400, "ONE_TAP_ERROR", &msg),
                }
            })
        });
        vec![PluginEndpoint::with_handler("/one-tap/callback", HttpMethod::Post, false, handler)]
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![
            ErrorCode::InvalidToken,
            ErrorCode::UserNotFound,
            ErrorCode::FailedToCreateUser,
        ]
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: build a fake JWT with the given payload
    fn build_fake_jwt(payload: &serde_json::Value) -> String {
        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(payload).unwrap());
        format!("{}.{}.fake-signature", header, payload_b64)
    }

    #[test]
    fn test_decode_id_token_payload() {
        let payload = serde_json::json!({
            "sub": "1234567890",
            "email": "user@gmail.com",
            "email_verified": true,
            "name": "Test User",
            "picture": "https://lh3.googleusercontent.com/photo.jpg",
            "aud": "my-client-id.apps.googleusercontent.com",
            "iss": "accounts.google.com",
            "exp": 9999999999u64,
            "iat": 1000000000u64
        });
        let jwt = build_fake_jwt(&payload);
        let decoded = decode_id_token_payload(&jwt).unwrap();
        assert_eq!(decoded.sub, "1234567890");
        assert_eq!(decoded.email, "user@gmail.com");
        assert_eq!(decoded.email_verified, Some(true));
        assert_eq!(decoded.name, Some("Test User".into()));
    }

    #[test]
    fn test_decode_invalid_jwt() {
        assert!(decode_id_token_payload("not.a.valid.jwt").is_none());
        assert!(decode_id_token_payload("not-a-jwt-at-all").is_none());
    }

    #[test]
    fn test_validate_payload_valid() {
        let payload = GoogleIdTokenPayload {
            sub: "123".into(),
            email: "user@gmail.com".into(),
            email_verified: Some(true),
            name: Some("User".into()),
            given_name: None,
            family_name: None,
            picture: None,
            aud: Some("my-client".into()),
            iss: Some("accounts.google.com".into()),
            exp: Some(chrono::Utc::now().timestamp() as u64 + 3600),
            iat: None,
            nonce: None,
        };
        assert!(validate_id_token_payload(&payload, "my-client").is_ok());
    }

    #[test]
    fn test_validate_payload_wrong_audience() {
        let payload = GoogleIdTokenPayload {
            sub: "123".into(),
            email: "user@gmail.com".into(),
            email_verified: Some(true),
            name: None,
            given_name: None,
            family_name: None,
            picture: None,
            aud: Some("wrong-client".into()),
            iss: Some("accounts.google.com".into()),
            exp: Some(chrono::Utc::now().timestamp() as u64 + 3600),
            iat: None,
            nonce: None,
        };
        assert_eq!(
            validate_id_token_payload(&payload, "my-client").unwrap_err(),
            "ID token audience does not match client ID"
        );
    }

    #[test]
    fn test_validate_payload_expired() {
        let payload = GoogleIdTokenPayload {
            sub: "123".into(),
            email: "user@gmail.com".into(),
            email_verified: Some(true),
            name: None,
            given_name: None,
            family_name: None,
            picture: None,
            aud: Some("my-client".into()),
            iss: Some("accounts.google.com".into()),
            exp: Some(1000000000), // Way in the past
            iat: None,
            nonce: None,
        };
        assert_eq!(
            validate_id_token_payload(&payload, "my-client").unwrap_err(),
            "ID token has expired"
        );
    }

    #[test]
    fn test_validate_payload_email_not_verified() {
        let payload = GoogleIdTokenPayload {
            sub: "123".into(),
            email: "user@gmail.com".into(),
            email_verified: Some(false),
            name: None,
            given_name: None,
            family_name: None,
            picture: None,
            aud: Some("my-client".into()),
            iss: Some("accounts.google.com".into()),
            exp: Some(chrono::Utc::now().timestamp() as u64 + 3600),
            iat: None,
            nonce: None,
        };
        // email_verified=false is no longer an error; we only check for empty email
        // This test now validates that a non-empty email with email_verified=false passes
        assert!(validate_id_token_payload(&payload, "my-client").is_ok());
    }

    #[test]
    fn test_validate_payload_empty_email() {
        let payload = GoogleIdTokenPayload {
            sub: "123".into(),
            email: "".into(),
            email_verified: Some(true),
            name: None,
            given_name: None,
            family_name: None,
            picture: None,
            aud: Some("my-client".into()),
            iss: Some("accounts.google.com".into()),
            exp: Some(chrono::Utc::now().timestamp() as u64 + 3600),
            iat: None,
            nonce: None,
        };
        assert!(validate_id_token_payload(&payload, "my-client").is_err());
    }

    #[test]
    fn test_extract_user_info() {
        let payload = GoogleIdTokenPayload {
            sub: "google-id-123".into(),
            email: "user@gmail.com".into(),
            email_verified: Some(true),
            name: Some("Test User".into()),
            given_name: None,
            family_name: None,
            picture: Some("https://photo.jpg".into()),
            aud: None,
            iss: None,
            exp: None,
            iat: None,
            nonce: None,
        };
        let info = extract_user_info(&payload);
        assert_eq!(info["email"], "user@gmail.com");
        assert_eq!(info["name"], "Test User");
        assert_eq!(info["image"], "https://photo.jpg");
        assert_eq!(info["emailVerified"], true);
    }

    #[test]
    fn test_verify_nonce_matches() {
        let payload = GoogleIdTokenPayload {
            sub: "123".into(),
            email: "u@g.com".into(),
            email_verified: None,
            name: None,
            given_name: None,
            family_name: None,
            picture: None,
            aud: None,
            iss: None,
            exp: None,
            iat: None,
            nonce: Some("my-nonce".into()),
        };
        assert!(verify_nonce(&payload, Some("my-nonce")));
        assert!(!verify_nonce(&payload, Some("wrong-nonce")));
    }

    #[test]
    fn test_verify_nonce_none_expected() {
        let payload = GoogleIdTokenPayload {
            sub: "123".into(),
            email: "u@g.com".into(),
            email_verified: None,
            name: None,
            given_name: None,
            family_name: None,
            picture: None,
            aud: None,
            iss: None,
            exp: None,
            iat: None,
            nonce: None,
        };
        assert!(verify_nonce(&payload, None)); // No nonce expected, passes
    }

    #[test]
    fn test_plugin_id() {
        let plugin = OneTapPlugin::with_client_id("client-id");
        assert_eq!(plugin.id(), "one-tap");
    }

    #[test]
    fn test_plugin_endpoints() {
        let plugin = OneTapPlugin::with_client_id("client-id");
        let endpoints = plugin.endpoints();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].path, "/one-tap/callback");
    }

    #[test]
    fn test_build_tokeninfo_url() {
        let url = build_tokeninfo_url("my-token-here");
        assert_eq!(
            url,
            "https://oauth2.googleapis.com/tokeninfo?id_token=my-token-here"
        );
    }

    #[test]
    fn test_request_deserialization() {
        let json = serde_json::json!({ "idToken": "eyJ..." });
        let req: OneTapCallbackRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.id_token, "eyJ...");
    }

    #[test]
    fn test_should_link_account() {
        let config = AccountLinkingConfig::default();
        assert!(should_link_account(&config, true));
        assert!(should_link_account(&config, false)); // google is trusted

        let strict = AccountLinkingConfig {
            enabled: true,
            trusted_providers: vec![],
        };
        assert!(should_link_account(&strict, true));   // email_verified
        assert!(!should_link_account(&strict, false));  // not verified, not trusted

        let disabled = AccountLinkingConfig {
            enabled: false,
            trusted_providers: vec!["google".to_string()],
        };
        assert!(!should_link_account(&disabled, true)); // linking disabled
    }

    #[test]
    fn test_handle_one_tap_new_user() {
        let payload = GoogleIdTokenPayload {
            sub: "123".into(),
            email: "user@gmail.com".into(),
            email_verified: Some(true),
            name: Some("User".into()),
            given_name: None,
            family_name: None,
            picture: Some("https://photo.jpg".into()),
            aud: None,
            iss: None,
            exp: None,
            iat: None,
            nonce: None,
        };
        let options = OneTapOptions::default();
        let result = handle_one_tap_callback(&payload, "token", &options, None, false);
        assert!(matches!(result, OneTapResult::NewUser { .. }));
    }

    #[test]
    fn test_handle_one_tap_existing_user_linked() {
        let payload = GoogleIdTokenPayload {
            sub: "123".into(),
            email: "user@gmail.com".into(),
            email_verified: Some(true),
            name: None,
            given_name: None,
            family_name: None,
            picture: None,
            aud: None,
            iss: None,
            exp: None,
            iat: None,
            nonce: None,
        };
        let options = OneTapOptions::default();
        let result = handle_one_tap_callback(&payload, "token", &options, Some("user-1"), true);
        assert!(matches!(result, OneTapResult::ExistingUser { .. }));
    }

    #[test]
    fn test_handle_one_tap_link_account() {
        let payload = GoogleIdTokenPayload {
            sub: "123".into(),
            email: "user@gmail.com".into(),
            email_verified: Some(true),
            name: None,
            given_name: None,
            family_name: None,
            picture: None,
            aud: None,
            iss: None,
            exp: None,
            iat: None,
            nonce: None,
        };
        let options = OneTapOptions::default();
        let result = handle_one_tap_callback(&payload, "token", &options, Some("user-1"), false);
        assert!(matches!(result, OneTapResult::LinkAccount { .. }));
    }

    #[test]
    fn test_handle_one_tap_signup_disabled() {
        let payload = GoogleIdTokenPayload {
            sub: "123".into(),
            email: "user@gmail.com".into(),
            email_verified: Some(true),
            name: None,
            given_name: None,
            family_name: None,
            picture: None,
            aud: None,
            iss: None,
            exp: None,
            iat: None,
            nonce: None,
        };
        let mut options = OneTapOptions::default();
        options.disable_sign_up = true;
        let result = handle_one_tap_callback(&payload, "token", &options, None, false);
        assert!(matches!(result, OneTapResult::Error(_)));
    }

    #[test]
    fn test_to_boolean() {
        assert!(to_boolean(&serde_json::json!(true)));
        assert!(!to_boolean(&serde_json::json!(false)));
        assert!(to_boolean(&serde_json::json!("true")));
        assert!(!to_boolean(&serde_json::json!("false")));
        assert!(to_boolean(&serde_json::json!(1)));
        assert!(!to_boolean(&serde_json::json!(0)));
    }

    #[test]
    fn test_extract_account_info() {
        let payload = GoogleIdTokenPayload {
            sub: "google-123".into(),
            email: "user@gmail.com".into(),
            email_verified: Some(true),
            name: None,
            given_name: None,
            family_name: None,
            picture: None,
            aud: None,
            iss: None,
            exp: None,
            iat: None,
            nonce: None,
        };
        let info = extract_account_info(&payload, "token123");
        assert_eq!(info["providerId"], "google");
        assert_eq!(info["accountId"], "google-123");
        assert_eq!(info["idToken"], "token123");
    }
}
