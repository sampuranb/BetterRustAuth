// Anonymous plugin — sign in without credentials, optionally link to real account.
//
// Maps to: packages/better-auth/src/plugins/anonymous/index.ts
//
// Endpoints:
//   POST /sign-in/anonymous — create anonymous user + session
//   POST /delete-anonymous-user — delete the anonymous user (requires auth)
//
// Hooks (after):
//   sign-in/sign-up/callback paths — detect account linking from anonymous → real user,
//   invoke onLinkAccount callback, optionally delete the old anonymous user.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use better_auth_core::error::ErrorCode;
use better_auth_core::plugin::{BetterAuthPlugin, HttpMethod, PluginEndpoint, PluginHook};

// ─── Error codes ────────────────────────────────────────────────────────

pub struct AnonymousErrorCodes;

impl AnonymousErrorCodes {
    pub const ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN: &str =
        "Anonymous users cannot sign in anonymously again";
    pub const DELETE_ANONYMOUS_USER_DISABLED: &str =
        "Delete anonymous user functionality is disabled";
    pub const USER_IS_NOT_ANONYMOUS: &str = "User is not an anonymous user";
    pub const FAILED_TO_CREATE_USER: &str = "Failed to create anonymous user";
    pub const FAILED_TO_DELETE_ANONYMOUS_USER: &str = "Failed to delete anonymous user";
    pub const COULD_NOT_CREATE_SESSION: &str = "Could not create session for anonymous user";
    pub const INVALID_EMAIL_FORMAT: &str = "Custom email generator returned invalid email format";
}

// ─── Options ────────────────────────────────────────────────────────────

/// Configuration options for the anonymous plugin.
#[derive(Debug, Clone)]
pub struct AnonymousOptions {
    /// Domain name for generated anonymous emails (default: random-id.com).
    pub email_domain_name: Option<String>,
    /// Whether to disable the delete-anonymous-user endpoint (default: false).
    pub disable_delete_anonymous_user: bool,
}

impl Default for AnonymousOptions {
    fn default() -> Self {
        Self {
            email_domain_name: None,
            disable_delete_anonymous_user: false,
        }
    }
}

// ─── Request / Response types ──────────────────────────────────────────

/// Response for anonymous sign-in.
#[derive(Debug, Serialize)]
pub struct AnonymousSignInResponse {
    pub token: String,
    pub user: serde_json::Value,
}

/// Response for delete anonymous user.
#[derive(Debug, Serialize)]
pub struct DeleteAnonymousUserResponse {
    pub success: bool,
}

// ─── Core handler logic ────────────────────────────────────────────────

/// Generate a random email for an anonymous user.
///
/// Format: `temp@{random_id}.com` or `temp-{random_id}@{domain}` if domain is set.
pub fn generate_anonymous_email(domain: Option<&str>) -> String {
    let id = uuid::Uuid::new_v4().to_string().replace('-', "");
    let short_id = &id[..12]; // 12 chars is enough

    match domain {
        Some(d) => format!("temp-{short_id}@{d}"),
        None => format!("temp@{short_id}.com"),
    }
}

/// Check if a path triggers the anonymous account-linking after-hook.
///
/// These are all the paths that could result in a sign-in/sign-up transition
/// from anonymous → real account.
pub fn is_account_link_path(path: &str) -> bool {
    path.starts_with("/sign-in")
        || path.starts_with("/sign-up")
        || path.starts_with("/callback")
        || path.starts_with("/oauth2/callback")
        || path.starts_with("/magic-link/verify")
        || path.starts_with("/email-otp/verify-email")
        || path.starts_with("/one-tap/callback")
        || path.starts_with("/passkey/verify-authentication")
        || path.starts_with("/phone-number/verify")
}

/// Determine if the anonymous user should be deleted after account linking.
///
/// The old anonymous user is NOT deleted if:
///   - `disable_delete_anonymous_user` is true
///   - The new user is the same user (just re-signed in)
///   - The new session user is still anonymous
pub fn should_delete_old_anonymous_user(
    options: &AnonymousOptions,
    old_user_id: &str,
    new_user_id: &str,
    new_user_is_anonymous: bool,
) -> bool {
    if options.disable_delete_anonymous_user {
        return false;
    }
    if old_user_id == new_user_id {
        return false;
    }
    if new_user_is_anonymous {
        return false;
    }
    true
}

/// Schema fields added by the anonymous plugin.
pub fn anonymous_schema_fields() -> Vec<(&'static str, &'static str, bool)> {
    vec![("isAnonymous", "boolean", false)]
}

// ─── Plugin struct ─────────────────────────────────────────────────────

#[derive(Debug)]
pub struct AnonymousPlugin {
    options: AnonymousOptions,
}

impl AnonymousPlugin {
    pub fn new(options: AnonymousOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &AnonymousOptions {
        &self.options
    }
}

impl Default for AnonymousPlugin {
    fn default() -> Self {
        Self::new(AnonymousOptions::default())
    }
}

// ─── Plugin trait ──────────────────────────────────────────────────────

#[async_trait]
impl BetterAuthPlugin for AnonymousPlugin {
    fn id(&self) -> &str {
        "anonymous"
    }

    fn name(&self) -> &str {
        "Anonymous"
    }

    fn endpoints(&self) -> Vec<PluginEndpoint> {
        use std::sync::Arc;
        use better_auth_core::plugin::{PluginHandlerFn, PluginHandlerRequest, PluginHandlerResponse};

        let opts = self.options.clone();

        // POST /sign-in/anonymous
        let sign_in_opts = opts.clone();
        let sign_in_handler: PluginHandlerFn = Arc::new(move |ctx_any, _req| {
            let opts = sign_in_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                let email = generate_anonymous_email(opts.email_domain_name.as_deref());
                let user_id = uuid::Uuid::new_v4().to_string();
                let now = chrono::Utc::now().to_rfc3339();
                let user_data = serde_json::json!({
                    "id": user_id,
                    "email": email,
                    "name": "Anonymous",
                    "emailVerified": false,
                    "isAnonymous": true,
                    "createdAt": now,
                    "updatedAt": now,
                });
                let user = match ctx.adapter.create_user(user_data).await {
                    Ok(u) => u,
                    Err(e) => return PluginHandlerResponse::error(500, "FAILED_TO_CREATE_USER", &format!("{}", e)),
                };
                let session_token = uuid::Uuid::new_v4().to_string();
                let expires = chrono::Utc::now() + chrono::Duration::days(7);
                match ctx.adapter.create_session(
                    &user_id, None,
                    Some(expires.timestamp_millis()),
                ).await {
                    Ok(session) => PluginHandlerResponse::ok(serde_json::json!({
                        "token": session_token,
                        "user": user,
                        "session": session,
                    })),
                    Err(e) => PluginHandlerResponse::error(500, "COULD_NOT_CREATE_SESSION", &format!("{}", e)),
                }
            })
        });

        // POST /delete-anonymous-user
        let delete_opts = opts.clone();
        let delete_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let opts = delete_opts.clone();
            Box::pin(async move {
                if opts.disable_delete_anonymous_user {
                    return PluginHandlerResponse::error(403, "DELETE_ANONYMOUS_USER_DISABLED",
                        AnonymousErrorCodes::DELETE_ANONYMOUS_USER_DISABLED);
                }
                let user_id = match req.session.as_ref()
                    .and_then(|s| s.get("user"))
                    .and_then(|u| u.get("id"))
                    .and_then(|id| id.as_str()) {
                    Some(id) => id.to_string(),
                    None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
                };
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                // Check if user is anonymous
                match ctx.adapter.find_user_by_id(&user_id).await {
                    Ok(Some(user)) => {
                        let is_anon = user.get("isAnonymous")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        if !is_anon {
                            return PluginHandlerResponse::error(400, "USER_IS_NOT_ANONYMOUS",
                                AnonymousErrorCodes::USER_IS_NOT_ANONYMOUS);
                        }
                    }
                    Ok(None) => return PluginHandlerResponse::error(404, "NOT_FOUND", "User not found"),
                    Err(e) => return PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
                match ctx.adapter.delete_user(&user_id).await {
                    Ok(()) => PluginHandlerResponse::ok(serde_json::json!({"success": true})),
                    Err(e) => PluginHandlerResponse::error(500, "FAILED_TO_DELETE_ANONYMOUS_USER", &format!("{}", e)),
                }
            })
        });

        vec![
            PluginEndpoint::with_handler("/sign-in/anonymous", HttpMethod::Post, false, sign_in_handler),
            PluginEndpoint::with_handler("/delete-anonymous-user", HttpMethod::Post, true, delete_handler),
        ]
    }

    fn hooks(&self) -> Vec<PluginHook> {
        use better_auth_core::plugin::{HookOperation, HookTiming};
        vec![PluginHook {
            model: "user".to_string(),
            timing: HookTiming::After,
            operation: HookOperation::Create,
        }]
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![
            ErrorCode::FailedToCreateUser,
            ErrorCode::Unauthorized,
            ErrorCode::InternalServerError,
        ]
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_anonymous_email_default() {
        let email = generate_anonymous_email(None);
        assert!(email.starts_with("temp@"));
        assert!(email.ends_with(".com"));
        assert!(email.len() > 10);
    }

    #[test]
    fn test_generate_anonymous_email_custom_domain() {
        let email = generate_anonymous_email(Some("myapp.io"));
        assert!(email.starts_with("temp-"));
        assert!(email.ends_with("@myapp.io"));
    }

    #[test]
    fn test_generate_anonymous_email_uniqueness() {
        let e1 = generate_anonymous_email(None);
        let e2 = generate_anonymous_email(None);
        assert_ne!(e1, e2);
    }

    #[test]
    fn test_is_account_link_path() {
        assert!(is_account_link_path("/sign-in/email"));
        assert!(is_account_link_path("/sign-up/email"));
        assert!(is_account_link_path("/callback/google"));
        assert!(is_account_link_path("/oauth2/callback/github"));
        assert!(is_account_link_path("/magic-link/verify"));
        assert!(is_account_link_path("/email-otp/verify-email"));
        assert!(is_account_link_path("/one-tap/callback"));
        assert!(is_account_link_path("/passkey/verify-authentication"));
        assert!(is_account_link_path("/phone-number/verify"));
        assert!(!is_account_link_path("/get-session"));
        assert!(!is_account_link_path("/sign-out"));
    }

    #[test]
    fn test_should_delete_old_user_normal() {
        let options = AnonymousOptions::default();
        assert!(should_delete_old_anonymous_user(
            &options, "old-id", "new-id", false
        ));
    }

    #[test]
    fn test_should_delete_old_user_disabled() {
        let options = AnonymousOptions {
            disable_delete_anonymous_user: true,
            ..Default::default()
        };
        assert!(!should_delete_old_anonymous_user(
            &options, "old-id", "new-id", false
        ));
    }

    #[test]
    fn test_should_delete_old_user_same_user() {
        let options = AnonymousOptions::default();
        assert!(!should_delete_old_anonymous_user(
            &options, "same-id", "same-id", false
        ));
    }

    #[test]
    fn test_should_delete_old_user_still_anonymous() {
        let options = AnonymousOptions::default();
        assert!(!should_delete_old_anonymous_user(
            &options, "old-id", "new-id", true
        ));
    }

    #[test]
    fn test_plugin_id() {
        let plugin = AnonymousPlugin::default();
        assert_eq!(plugin.id(), "anonymous");
    }

    #[test]
    fn test_plugin_endpoints() {
        let plugin = AnonymousPlugin::default();
        let endpoints = plugin.endpoints();
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].path, "/sign-in/anonymous");
        assert!(endpoints[1].require_auth);
    }

    #[test]
    fn test_anonymous_schema_fields() {
        let fields = anonymous_schema_fields();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].0, "isAnonymous");
    }

    #[test]
    fn test_error_codes() {
        let plugin = AnonymousPlugin::default();
        let codes = plugin.error_codes();
        assert_eq!(codes.len(), 3);
    }
}
