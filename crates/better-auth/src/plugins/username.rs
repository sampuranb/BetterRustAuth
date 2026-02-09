// Username plugin — sign-in via username/password instead of email.
//
// Maps to: packages/better-auth/src/plugins/username/index.ts
//
// Endpoints:
//   POST /sign-in/username — authenticate by username + password
//   POST /is-username-available — check uniqueness
//
// Hooks (before):
//   /sign-up/email + /update-user — validate username, check uniqueness, normalize
//
// DB hooks:
//   user.create.before — normalize username + displayUsername
//   user.update.before — normalize username + displayUsername

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use better_auth_core::error::ErrorCode;
use better_auth_core::plugin::{BetterAuthPlugin, HttpMethod, PluginEndpoint, PluginHook};

// ─── Error codes ────────────────────────────────────────────────────────

/// Error codes specific to the username plugin.
pub struct UsernameErrorCodes;

impl UsernameErrorCodes {
    pub const INVALID_USERNAME_OR_PASSWORD: &str = "Invalid username or password";
    pub const USERNAME_TOO_SHORT: &str = "Username is too short";
    pub const USERNAME_TOO_LONG: &str = "Username is too long";
    pub const INVALID_USERNAME: &str = "Username contains invalid characters";
    pub const INVALID_DISPLAY_USERNAME: &str = "Display username is invalid";
    pub const USERNAME_IS_ALREADY_TAKEN: &str = "Username is already taken";
    pub const EMAIL_NOT_VERIFIED: &str = "Email is not verified";
}

// ─── Validation order ──────────────────────────────────────────────────

/// When validation runs relative to normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationOrder {
    PreNormalization,
    PostNormalization,
}

impl Default for ValidationOrder {
    fn default() -> Self {
        Self::PreNormalization
    }
}

// ─── Options ────────────────────────────────────────────────────────────

/// Configuration options for the username plugin.
#[derive(Debug, Clone)]
pub struct UsernameOptions {
    /// Minimum username length (default: 3).
    pub min_username_length: usize,
    /// Maximum username length (default: 30).
    pub max_username_length: usize,
    /// Whether to disable normalization (default: false, i.e. normalize to lowercase).
    pub disable_normalization: bool,
    /// When to validate the username relative to normalization.
    pub username_validation_order: ValidationOrder,
    /// When to validate the display username relative to normalization.
    pub display_username_validation_order: ValidationOrder,
}

impl Default for UsernameOptions {
    fn default() -> Self {
        Self {
            min_username_length: 3,
            max_username_length: 30,
            disable_normalization: false,
            username_validation_order: ValidationOrder::default(),
            display_username_validation_order: ValidationOrder::default(),
        }
    }
}

// ─── Request / response types ──────────────────────────────────────────

/// Sign-in by username request body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInUsernameRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub remember_me: Option<bool>,
    #[serde(default, alias = "callbackURL")]
    pub callback_url: Option<String>,
}

/// Is-username-available request body.
#[derive(Debug, Deserialize)]
pub struct IsUsernameAvailableRequest {
    pub username: String,
}

/// Is-username-available response.
#[derive(Debug, Serialize)]
pub struct IsUsernameAvailableResponse {
    pub available: bool,
}

/// Sign-in response (token + user).
#[derive(Debug, Serialize)]
pub struct SignInUsernameResponse {
    pub token: String,
    pub user: serde_json::Value,
}

// ─── Core handler logic ────────────────────────────────────────────────

/// Default username validator: alphanumeric + underscores + dots.
pub fn default_username_validator(username: &str) -> bool {
    regex::Regex::new(r"^[a-zA-Z0-9_.]+$")
        .map(|re| re.is_match(username))
        .unwrap_or(false)
}

/// Normalize a username (default: lowercase).
pub fn normalize_username(username: &str, disable_normalization: bool) -> String {
    if disable_normalization {
        username.to_string()
    } else {
        username.to_lowercase()
    }
}

/// Validate username length and character constraints.
///
/// Returns `Ok(normalized_username)` or `Err(error_message)`.
pub fn validate_username(
    username: &str,
    options: &UsernameOptions,
) -> Result<String, &'static str> {
    // Apply normalization first if validation order is post-normalization
    let to_validate = if options.username_validation_order == ValidationOrder::PostNormalization {
        normalize_username(username, options.disable_normalization)
    } else {
        username.to_string()
    };

    if to_validate.len() < options.min_username_length {
        return Err(UsernameErrorCodes::USERNAME_TOO_SHORT);
    }

    if to_validate.len() > options.max_username_length {
        return Err(UsernameErrorCodes::USERNAME_TOO_LONG);
    }

    if !default_username_validator(&to_validate) {
        return Err(UsernameErrorCodes::INVALID_USERNAME);
    }

    // Return the fully normalized value
    Ok(normalize_username(username, options.disable_normalization))
}

/// Validate a display username (optional validation).
pub fn validate_display_username(
    display_username: &str,
    options: &UsernameOptions,
) -> Result<String, &'static str> {
    // Display username has length constraints but by default no character validation
    if display_username.len() < options.min_username_length {
        return Err(UsernameErrorCodes::USERNAME_TOO_SHORT);
    }
    if display_username.len() > options.max_username_length {
        return Err(UsernameErrorCodes::USERNAME_TOO_LONG);
    }
    Ok(display_username.to_string())
}

/// Normalize user data for database hooks (before create/update).
///
/// Applies normalization to `username` and `displayUsername` fields.
pub fn normalize_user_data(
    data: &mut serde_json::Value,
    options: &UsernameOptions,
) {
    if let Some(obj) = data.as_object_mut() {
        // Normalize username
        if let Some(username) = obj.get("username").and_then(|v| v.as_str()) {
            let normalized = normalize_username(username, options.disable_normalization);
            obj.insert("username".to_string(), serde_json::Value::String(normalized));
        }

        // Set displayUsername = username if one is missing
        let has_username = obj.get("username").and_then(|v| v.as_str()).is_some();
        let has_display = obj.get("displayUsername").and_then(|v| v.as_str()).is_some();

        if has_username && !has_display {
            if let Some(u) = obj.get("username").cloned() {
                obj.insert("displayUsername".to_string(), u);
            }
        } else if has_display && !has_username {
            if let Some(d) = obj.get("displayUsername").cloned() {
                obj.insert("username".to_string(), d);
            }
        }
    }
}

/// Check if a path should trigger username validation hooks.
pub fn is_username_hook_path(path: &str) -> bool {
    path == "/sign-up/email" || path == "/update-user"
}

/// Schema fields added by the username plugin.
pub fn username_schema_fields() -> Vec<(&'static str, &'static str, bool)> {
    // (field_name, field_type, required)
    vec![
        ("username", "string", true),
        ("displayUsername", "string", false),
    ]
}

// ─── Plugin struct ─────────────────────────────────────────────────────

/// Username plugin.
#[derive(Debug)]
pub struct UsernamePlugin {
    options: UsernameOptions,
}

impl UsernamePlugin {
    pub fn new(options: UsernameOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &UsernameOptions {
        &self.options
    }
}

impl Default for UsernamePlugin {
    fn default() -> Self {
        Self::new(UsernameOptions::default())
    }
}

// ─── Plugin trait ──────────────────────────────────────────────────────

#[async_trait]
impl BetterAuthPlugin for UsernamePlugin {
    fn id(&self) -> &str {
        "username"
    }

    fn name(&self) -> &str {
        "Username"
    }

    fn endpoints(&self) -> Vec<PluginEndpoint> {
        use std::sync::Arc;
        use better_auth_core::plugin::{PluginHandlerFn, PluginHandlerRequest, PluginHandlerResponse};

        let opts = self.options.clone();

        // POST /sign-in/username
        let sign_in_opts = opts.clone();
        let sign_in_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let opts = sign_in_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { username: String, password: String }
                let body: Body = match serde_json::from_value(req.body.clone()) {
                    Ok(b) => b,
                    Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
                };
                let username = normalize_username(&body.username, opts.disable_normalization);
                // Find user by username field
                let users = ctx.adapter.list_users(Some(100), Some(0), None, None).await;
                let user = match users {
                    Ok(list) => list.into_iter().find(|u| {
                        u.get("username").and_then(|v| v.as_str()).map(|n|
                            normalize_username(n, opts.disable_normalization) == username
                        ).unwrap_or(false)
                    }),
                    Err(e) => return PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                };
                let user = match user {
                    Some(u) => u,
                    None => return PluginHandlerResponse::error(401, "INVALID_USERNAME_OR_PASSWORD", "Invalid username or password"),
                };
                let user_id = user.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                // Verify password via account
                let accounts = match ctx.adapter.find_accounts_by_user_id(&user_id).await {
                    Ok(a) => a,
                    Err(e) => return PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                };
                let credential_account = accounts.iter().find(|a| {
                    a.get("providerId").and_then(|v| v.as_str()) == Some("credential")
                });
                let stored_hash = credential_account
                    .and_then(|a| a.get("password").and_then(|v| v.as_str()));
                match stored_hash {
                    Some(hash) => {
                        let valid = crate::crypto::password::verify_password(&body.password, hash).unwrap_or(false);
                        if !valid {
                            return PluginHandlerResponse::error(401, "INVALID_USERNAME_OR_PASSWORD", "Invalid username or password");
                        }
                    }
                    None => return PluginHandlerResponse::error(401, "INVALID_USERNAME_OR_PASSWORD", "Invalid username or password"),
                }
                // Create session
                let session_token = uuid::Uuid::new_v4().to_string();
                let expires = chrono::Utc::now() + chrono::Duration::days(7);
                match ctx.adapter.create_session(&user_id, None, Some(expires.timestamp_millis())).await {
                    Ok(session) => PluginHandlerResponse::ok(serde_json::json!({
                        "token": session_token,
                        "user": user,
                        "session": session,
                    })),
                    Err(e) => PluginHandlerResponse::error(500, "FAILED_TO_CREATE_SESSION", &format!("{}", e)),
                }
            })
        });

        // POST /is-username-available
        let avail_opts = opts.clone();
        let is_available_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let opts = avail_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                struct Body { username: String }
                let body: Body = match serde_json::from_value(req.body.clone()) {
                    Ok(b) => b,
                    Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
                };
                let username = normalize_username(&body.username, opts.disable_normalization);
                // Validate
                if let Err(msg) = validate_username(&username, &opts) {
                    return PluginHandlerResponse::ok(serde_json::json!({"available": false, "error": msg}));
                }
                // Check if any user has this username
                let users = ctx.adapter.list_users(Some(100), Some(0), None, None).await;
                let taken = match users {
                    Ok(list) => list.iter().any(|u| {
                        u.get("username").and_then(|v| v.as_str()).map(|n|
                            normalize_username(n, opts.disable_normalization) == username
                        ).unwrap_or(false)
                    }),
                    Err(_) => false,
                };
                PluginHandlerResponse::ok(serde_json::json!({"available": !taken}))
            })
        });

        vec![
            PluginEndpoint::with_handler("/sign-in/username", HttpMethod::Post, false, sign_in_handler),
            PluginEndpoint::with_handler("/is-username-available", HttpMethod::Post, false, is_available_handler),
        ]
    }

    fn hooks(&self) -> Vec<PluginHook> {
        use better_auth_core::plugin::{HookOperation, HookTiming};
        vec![
            // Before hook: validate username on sign-up and update
            PluginHook {
                model: "user".to_string(),
                timing: HookTiming::Before,
                operation: HookOperation::Create,
            },
            PluginHook {
                model: "user".to_string(),
                timing: HookTiming::Before,
                operation: HookOperation::Update,
            },
        ]
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![
            ErrorCode::InvalidEmailOrPassword,
            ErrorCode::UserAlreadyExists,
        ]
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_username_validator_valid() {
        assert!(default_username_validator("john_doe"));
        assert!(default_username_validator("Alice123"));
        assert!(default_username_validator("user.name"));
        assert!(default_username_validator("a"));
    }

    #[test]
    fn test_default_username_validator_invalid() {
        assert!(!default_username_validator("user name"));
        assert!(!default_username_validator("user@name"));
        assert!(!default_username_validator("user-name"));
        assert!(!default_username_validator("user!name"));
        assert!(!default_username_validator(""));
    }

    #[test]
    fn test_normalize_username() {
        assert_eq!(normalize_username("JohnDoe", false), "johndoe");
        assert_eq!(normalize_username("JohnDoe", true), "JohnDoe");
    }

    #[test]
    fn test_validate_username_valid() {
        let options = UsernameOptions::default();
        let result = validate_username("john_doe", &options);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "john_doe");
    }

    #[test]
    fn test_validate_username_too_short() {
        let options = UsernameOptions::default();
        let result = validate_username("ab", &options);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), UsernameErrorCodes::USERNAME_TOO_SHORT);
    }

    #[test]
    fn test_validate_username_too_long() {
        let options = UsernameOptions {
            max_username_length: 5,
            ..Default::default()
        };
        let result = validate_username("toolong", &options);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), UsernameErrorCodes::USERNAME_TOO_LONG);
    }

    #[test]
    fn test_validate_username_invalid_chars() {
        let options = UsernameOptions::default();
        let result = validate_username("user name", &options);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), UsernameErrorCodes::INVALID_USERNAME);
    }

    #[test]
    fn test_validate_username_post_normalization() {
        let options = UsernameOptions {
            username_validation_order: ValidationOrder::PostNormalization,
            ..Default::default()
        };
        let result = validate_username("JohnDoe", &options);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "johndoe");
    }

    #[test]
    fn test_normalize_user_data() {
        let options = UsernameOptions::default();
        let mut data = serde_json::json!({
            "username": "JohnDoe",
            "email": "john@example.com"
        });
        normalize_user_data(&mut data, &options);
        assert_eq!(data["username"], "johndoe");
        // displayUsername auto-set from username
        assert_eq!(data["displayUsername"], "johndoe");
    }

    #[test]
    fn test_normalize_user_data_display_override() {
        let options = UsernameOptions::default();
        let mut data = serde_json::json!({
            "username": "JohnDoe",
            "displayUsername": "John Doe Display"
        });
        normalize_user_data(&mut data, &options);
        assert_eq!(data["username"], "johndoe");
        // displayUsername is kept as-is (no normalization by default)
        assert_eq!(data["displayUsername"], "John Doe Display");
    }

    #[test]
    fn test_is_username_hook_path() {
        assert!(is_username_hook_path("/sign-up/email"));
        assert!(is_username_hook_path("/update-user"));
        assert!(!is_username_hook_path("/sign-in/email"));
        assert!(!is_username_hook_path("/sign-in/username"));
    }

    #[test]
    fn test_username_schema_fields() {
        let fields = username_schema_fields();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].0, "username");
        assert_eq!(fields[1].0, "displayUsername");
    }

    #[test]
    fn test_plugin_id() {
        let plugin = UsernamePlugin::default();
        assert_eq!(plugin.id(), "username");
    }

    #[test]
    fn test_plugin_endpoints() {
        let plugin = UsernamePlugin::default();
        let endpoints = plugin.endpoints();
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].path, "/sign-in/username");
        assert_eq!(endpoints[1].path, "/is-username-available");
    }

    #[test]
    fn test_plugin_hooks() {
        let plugin = UsernamePlugin::default();
        let hooks = plugin.hooks();
        assert_eq!(hooks.len(), 2);
    }

    #[test]
    fn test_sign_in_request_deserialization() {
        let json = serde_json::json!({
            "username": "john",
            "password": "secret123",
            "rememberMe": true,
            "callbackURL": "/dashboard"
        });
        let req: SignInUsernameRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.username, "john");
        assert_eq!(req.password, "secret123");
        assert_eq!(req.remember_me, Some(true));
        assert_eq!(req.callback_url, Some("/dashboard".into()));
    }

    #[test]
    fn test_validate_display_username() {
        let options = UsernameOptions::default();
        assert!(validate_display_username("JohnDoe", &options).is_ok());
        assert!(validate_display_username("ab", &options).is_err());
    }

    #[test]
    fn test_custom_length_options() {
        let options = UsernameOptions {
            min_username_length: 5,
            max_username_length: 10,
            ..Default::default()
        };
        assert!(validate_username("abcd", &options).is_err()); // too short
        assert!(validate_username("abcde", &options).is_ok());
        assert!(validate_username("abcdefghij", &options).is_ok());
        assert!(validate_username("abcdefghijk", &options).is_err()); // too long
    }
}
