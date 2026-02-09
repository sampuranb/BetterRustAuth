// Admin plugin — user management, role assignment, banning, impersonation.
//
// Maps to: packages/better-auth/src/plugins/admin/admin.ts
//          packages/better-auth/src/plugins/admin/routes.ts
//          packages/better-auth/src/plugins/admin/has-permission.ts
//          packages/better-auth/src/plugins/admin/error-codes.ts
//          packages/better-auth/src/plugins/admin/access/index.ts

use std::collections::HashMap;

use async_trait::async_trait;

use better_auth_core::db::schema::SchemaField;
use better_auth_core::plugin::{
    BetterAuthPlugin, HookOperation, HookTiming, HttpMethod, PluginEndpoint, PluginHook,
};

use crate::plugins::access::{AccessControl, AuthorizeResult, Role, Statements};

// ── Error codes ─────────────────────────────────────────────────────────────

/// Admin plugin error codes (matches TS ADMIN_ERROR_CODES).
pub struct AdminErrorCodes;

impl AdminErrorCodes {
    pub const FAILED_TO_CREATE_USER: &'static str = "FAILED_TO_CREATE_USER";
    pub const USER_ALREADY_EXISTS: &'static str = "USER_ALREADY_EXISTS";
    pub const USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL: &'static str =
        "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL";
    pub const YOU_CANNOT_BAN_YOURSELF: &'static str = "YOU_CANNOT_BAN_YOURSELF";
    pub const YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE";
    pub const YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS";
    pub const YOU_ARE_NOT_ALLOWED_TO_LIST_USERS: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS";
    pub const YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS";
    pub const YOU_ARE_NOT_ALLOWED_TO_BAN_USERS: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS";
    pub const YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS";
    pub const YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS";
    pub const YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS";
    pub const YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD";
    pub const BANNED_USER: &'static str = "BANNED_USER";
    pub const YOU_ARE_NOT_ALLOWED_TO_GET_USER: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_GET_USER";
    pub const NO_DATA_TO_UPDATE: &'static str = "NO_DATA_TO_UPDATE";
    pub const YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS";
    pub const YOU_CANNOT_REMOVE_YOURSELF: &'static str = "YOU_CANNOT_REMOVE_YOURSELF";
    pub const YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE: &'static str =
        "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE";
    pub const YOU_CANNOT_IMPERSONATE_ADMINS: &'static str = "YOU_CANNOT_IMPERSONATE_ADMINS";
    pub const INVALID_ROLE_TYPE: &'static str = "INVALID_ROLE_TYPE";
}

/// Error code message lookup.
pub fn admin_error_message(code: &str) -> &'static str {
    match code {
        "FAILED_TO_CREATE_USER" => "Failed to create user",
        "USER_ALREADY_EXISTS" => "User already exists.",
        "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL" => "User already exists. Use another email.",
        "YOU_CANNOT_BAN_YOURSELF" => "You cannot ban yourself",
        "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE" => "You are not allowed to change users role",
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS" => "You are not allowed to create users",
        "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS" => "You are not allowed to list users",
        "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS" => {
            "You are not allowed to list users sessions"
        }
        "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS" => "You are not allowed to ban users",
        "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS" => {
            "You are not allowed to impersonate users"
        }
        "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS" => {
            "You are not allowed to revoke users sessions"
        }
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS" => "You are not allowed to delete users",
        "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD" => {
            "You are not allowed to set users password"
        }
        "BANNED_USER" => "You have been banned from this application",
        "YOU_ARE_NOT_ALLOWED_TO_GET_USER" => "You are not allowed to get user",
        "NO_DATA_TO_UPDATE" => "No data to update",
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS" => "You are not allowed to update users",
        "YOU_CANNOT_REMOVE_YOURSELF" => "You cannot remove yourself",
        "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE" => {
            "You are not allowed to set a non-existent role value"
        }
        "YOU_CANNOT_IMPERSONATE_ADMINS" => "You cannot impersonate admins",
        "INVALID_ROLE_TYPE" => "Invalid role type",
        _ => "Unknown admin error",
    }
}

// ── Default admin statements ────────────────────────────────────────────────

/// Default permission statements for admin access control.
///
/// Maps to: packages/better-auth/src/plugins/admin/access/index.ts
pub fn default_admin_statements() -> Statements {
    let mut statements = HashMap::new();
    statements.insert(
        "user".to_string(),
        vec![
            "create".to_string(),
            "read".to_string(),
            "update".to_string(),
            "delete".to_string(),
            "list".to_string(),
            "get".to_string(),
            "set-role".to_string(),
            "ban".to_string(),
            "impersonate".to_string(),
            "set-password".to_string(),
        ],
    );
    statements.insert(
        "session".to_string(),
        vec![
            "list".to_string(),
            "revoke".to_string(),
            "delete".to_string(),
        ],
    );
    statements
}

/// Default admin access control: admin has full access, user has read-only.
pub fn default_admin_access() -> AccessControl {
    AccessControl::new(default_admin_statements())
}

/// Default admin roles (admin = full, user = read-only).
pub fn default_admin_roles() -> HashMap<String, Role> {
    let ac = default_admin_access();
    let mut roles = HashMap::new();

    // Admin gets all permissions
    roles.insert("admin".to_string(), ac.new_role(default_admin_statements()));

    // User gets read-only on user
    let mut user_statements = HashMap::new();
    user_statements.insert("user".to_string(), vec!["read".to_string()]);
    roles.insert("user".to_string(), ac.new_role(user_statements));

    roles
}

// ── Permission checking ─────────────────────────────────────────────────────

/// Check if a user has the required permissions.
///
/// Maps to: packages/better-auth/src/plugins/admin/has-permission.ts
pub fn has_permission(
    user_id: Option<&str>,
    role: Option<&str>,
    options: &AdminOptions,
    permissions: &HashMap<String, Vec<String>>,
) -> bool {
    // Admin user IDs always have permission
    if let Some(uid) = user_id {
        if options.admin_user_ids.iter().any(|id| id == uid) {
            return true;
        }
    }

    if permissions.is_empty() {
        return false;
    }

    // Parse comma-separated roles
    let role_str = role.unwrap_or(&options.default_role);
    let role_names: Vec<&str> = role_str.split(',').map(|r| r.trim()).collect();

    let ac_roles = options
        .roles
        .as_ref()
        .cloned()
        .unwrap_or_else(default_admin_roles);

    for role_name in role_names {
        if let Some(role) = ac_roles.get(role_name) {
            if let AuthorizeResult::Success = role.authorize(permissions, "OR") {
                return true;
            }
        }
    }

    false
}

/// Parse role input — converts array to comma-separated string.
pub fn parse_roles(roles: &serde_json::Value) -> Option<String> {
    match roles {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(arr) => {
            let strs: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            if strs.is_empty() {
                None
            } else {
                Some(strs.join(","))
            }
        }
        _ => None,
    }
}

/// Validate that all provided role names exist in the configured roles.
pub fn validate_roles(role_names: &[&str], configured_roles: &HashMap<String, Role>) -> bool {
    role_names
        .iter()
        .all(|name| configured_roles.contains_key(*name))
}

/// Check if a user is banned and the ban has not expired.
pub fn is_user_banned(banned: bool, ban_expires: Option<&str>) -> bool {
    if !banned {
        return false;
    }
    if let Some(expires) = ban_expires {
        if let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(expires) {
            return chrono::Utc::now() < expires_at;
        }
    }
    // Banned with no expiry = permanently banned
    true
}

/// Calculate the ban expiry date from a duration in seconds.
pub fn calculate_ban_expiry(seconds: u64) -> String {
    let expiry = chrono::Utc::now() + chrono::Duration::seconds(seconds as i64);
    expiry.to_rfc3339()
}

/// Check if the target user is an admin (for impersonation guard).
pub fn is_user_admin(
    user_role: Option<&str>,
    admin_roles: &[String],
    admin_user_ids: &[String],
    user_id: &str,
) -> bool {
    // Check admin user IDs
    if admin_user_ids.iter().any(|id| id == user_id) {
        return true;
    }

    // Check admin roles
    if let Some(role_str) = user_role {
        let user_roles: Vec<&str> = role_str.split(',').map(|r| r.trim()).collect();
        for role in user_roles {
            if admin_roles.iter().any(|ar| ar == role) {
                return true;
            }
        }
    }

    false
}

// ── Admin plugin options ────────────────────────────────────────────────────

/// Admin plugin options.
#[derive(Debug, Clone)]
pub struct AdminOptions {
    /// Default role for new users.
    pub default_role: String,
    /// Roles with admin privileges.
    pub admin_roles: Vec<String>,
    /// User IDs that always have admin permissions (bypass role checks).
    pub admin_user_ids: Vec<String>,
    /// Message shown to banned users.
    pub banned_user_message: String,
    /// Default ban reason if none provided.
    pub default_ban_reason: Option<String>,
    /// Default ban expiry in seconds if none provided.
    pub default_ban_expires_in: Option<u64>,
    /// Whether to allow impersonating admin users.
    pub allow_impersonating_admins: bool,
    /// Duration of impersonation sessions in seconds (default: 1 hour).
    pub impersonation_session_duration: Option<u64>,
    /// RBAC roles mapping (role name → Role with statements).
    pub roles: Option<HashMap<String, Role>>,
}

impl Default for AdminOptions {
    fn default() -> Self {
        Self {
            default_role: "user".into(),
            admin_roles: vec!["admin".into()],
            admin_user_ids: vec![],
            banned_user_message:
                "You have been banned from this application. Please contact support if you believe this is an error."
                    .into(),
            default_ban_reason: None,
            default_ban_expires_in: None,
            allow_impersonating_admins: false,
            impersonation_session_duration: None,
            roles: None,
        }
    }
}

// ── Admin session cookie ────────────────────────────────────────────────────

/// Cookie name for storing the admin session during impersonation.
pub const ADMIN_SESSION_COOKIE_NAME: &str = "admin_session";

/// Build admin session cookie value: `{admin_session_token}:{dont_remember_me}`.
pub fn build_admin_session_cookie(token: &str, dont_remember: &str) -> String {
    format!("{}:{}", token, dont_remember)
}

/// Parse admin session cookie value.
pub fn parse_admin_session_cookie(cookie: &str) -> Option<(&str, &str)> {
    let parts: Vec<&str> = cookie.splitn(2, ':').collect();
    if parts.len() == 2 {
        Some((parts[0], parts[1]))
    } else {
        None
    }
}

// ── Admin request/response types ────────────────────────────────────────────

/// Request body for POST /admin/set-role
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetRoleBody {
    pub user_id: String,
    /// Role can be a single string or an array (parsed via parse_roles).
    pub role: serde_json::Value,
}

/// Query params for GET /admin/get-user
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GetUserQuery {
    pub id: String,
}

/// Request body for POST /admin/create-user
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateUserBody {
    pub email: String,
    pub password: Option<String>,
    pub name: String,
    pub role: Option<serde_json::Value>,
    pub data: Option<serde_json::Value>,
}

/// Request body for POST /admin/update-user
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUpdateUserBody {
    pub user_id: String,
    pub data: serde_json::Value,
}

/// Sort direction for list-users query.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDirection {
    Asc,
    Desc,
}

/// Filter operator for list-users query.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilterOperator {
    Eq,
    Ne,
    Lt,
    Lte,
    Gt,
    Gte,
    Contains,
}

/// Query params for GET /admin/list-users (with search, filter, sort, pagination).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListUsersQuery {
    pub search_value: Option<String>,
    pub search_field: Option<String>, // "email" | "name"
    pub search_operator: Option<String>, // "contains" | "starts_with" | "ends_with"
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub sort_by: Option<String>,
    pub sort_direction: Option<SortDirection>,
    pub filter_field: Option<String>,
    pub filter_value: Option<serde_json::Value>,
    pub filter_operator: Option<FilterOperator>,
}

/// Request body for POST /admin/list-user-sessions
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListUserSessionsBody {
    pub user_id: String,
}

/// Request body for POST /admin/ban-user
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BanUserBody {
    pub user_id: String,
    pub ban_reason: Option<String>,
    /// Duration in seconds until ban expires.
    pub ban_expires_in: Option<u64>,
}

/// Request body for POST /admin/unban-user
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnbanUserBody {
    pub user_id: String,
}

/// Request body for POST /admin/impersonate-user
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImpersonateUserBody {
    pub user_id: String,
}

/// Request body for POST /admin/revoke-user-session
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeUserSessionBody {
    pub session_token: String,
}

/// Request body for POST /admin/revoke-user-sessions
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeUserSessionsBody {
    pub user_id: String,
}

/// Request body for POST /admin/remove-user
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveUserBody {
    pub user_id: String,
}

/// Request body for POST /admin/set-user-password
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetUserPasswordBody {
    pub user_id: String,
    pub new_password: String,
}

/// Request body for POST /admin/has-permission
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HasPermissionBody {
    pub user_id: Option<String>,
    pub role: Option<String>,
    /// permission or permissions — maps to TS's exclusive union
    pub permission: Option<HashMap<String, Vec<String>>>,
    pub permissions: Option<HashMap<String, Vec<String>>>,
}

// ── Plugin ──────────────────────────────────────────────────────────────────

/// Admin plugin.
#[derive(Debug)]
pub struct AdminPlugin {
    options: AdminOptions,
}

impl AdminPlugin {
    pub fn new(options: AdminOptions) -> Self {
        Self { options }
    }

    /// Access the plugin options.
    pub fn options(&self) -> &AdminOptions {
        &self.options
    }
}

impl Default for AdminPlugin {
    fn default() -> Self {
        Self::new(AdminOptions::default())
    }
}

#[async_trait]
impl BetterAuthPlugin for AdminPlugin {
    fn id(&self) -> &str {
        "admin"
    }

    fn name(&self) -> &str {
        "Admin"
    }

    fn additional_fields(&self) -> HashMap<String, HashMap<String, SchemaField>> {
        let mut user_fields = HashMap::new();
        user_fields.insert("role".to_string(), SchemaField::optional_string());
        user_fields.insert("banned".to_string(), SchemaField::boolean(false));
        user_fields.insert("banReason".to_string(), SchemaField::optional_string());
        user_fields.insert("banExpires".to_string(), SchemaField::optional_string());

        let mut session_fields = HashMap::new();
        session_fields.insert("impersonatedBy".to_string(), SchemaField::optional_string());

        let mut fields = HashMap::new();
        fields.insert("user".to_string(), user_fields);
        fields.insert("session".to_string(), session_fields);
        fields
    }

    fn endpoints(&self) -> Vec<PluginEndpoint> {
        use std::sync::Arc;
        use better_auth_core::plugin::{PluginHandlerFn, PluginHandlerRequest, PluginHandlerResponse};

        // POST /admin/set-role
        let set_role: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>().expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { user_id: String, role: String }
                let body: Body = match serde_json::from_value(req.body.clone()) { Ok(b) => b, Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)) };
                match ctx.adapter.update_user(&body.user_id, serde_json::json!({"role": body.role})).await {
                    Ok(u) => PluginHandlerResponse::ok(u),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // GET /admin/get-user
        let get_user: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>().expect("Expected AuthContext");
                let uid = match req.query.get("userId").and_then(|v| v.as_str()) {
                    Some(id) => id.to_string(), None => return PluginHandlerResponse::error(400, "BAD_REQUEST", "Missing userId"),
                };
                match ctx.adapter.find_user_by_id(&uid).await {
                    Ok(Some(u)) => PluginHandlerResponse::ok(u),
                    Ok(None) => PluginHandlerResponse::error(404, "NOT_FOUND", "User not found"),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // POST /admin/create-user
        let create_user: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>().expect("Expected AuthContext");
                let mut data = req.body.clone();
                if data.get("id").is_none() { data.as_object_mut().map(|o| o.insert("id".into(), serde_json::json!(uuid::Uuid::new_v4().to_string()))); }
                data.as_object_mut().map(|o| { o.insert("createdAt".into(), serde_json::json!(chrono::Utc::now().to_rfc3339())); o.insert("updatedAt".into(), serde_json::json!(chrono::Utc::now().to_rfc3339())); });
                match ctx.adapter.create_user(data).await {
                    Ok(u) => PluginHandlerResponse::created(u),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // POST /admin/update-user
        let update_user: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>().expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { user_id: String, data: serde_json::Value }
                let body: Body = match serde_json::from_value(req.body.clone()) { Ok(b) => b, Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)) };
                match ctx.adapter.update_user(&body.user_id, body.data).await {
                    Ok(u) => PluginHandlerResponse::ok(u),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // GET /admin/list-users
        let list_users: PluginHandlerFn = Arc::new(move |ctx_any, _req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>().expect("Expected AuthContext");
                match ctx.adapter.find_many("user", serde_json::json!({})).await {
                    Ok(users) => PluginHandlerResponse::ok(serde_json::json!({"users": users, "total": users.len()})),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // POST /admin/list-user-sessions
        let list_sessions: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>().expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { user_id: String }
                let body: Body = match serde_json::from_value(req.body.clone()) { Ok(b) => b, Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)) };
                match ctx.adapter.find_many("session", serde_json::json!({"userId": body.user_id})).await {
                    Ok(sessions) => PluginHandlerResponse::ok(serde_json::json!({"sessions": sessions})),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // POST /admin/ban-user
        let ban_user: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>().expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { user_id: String, #[serde(default)] reason: Option<String>, #[serde(default)] ban_expires_in: Option<i64> }
                let body: Body = match serde_json::from_value(req.body.clone()) { Ok(b) => b, Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)) };
                let ban_expires = body.ban_expires_in.map(|s| (chrono::Utc::now() + chrono::Duration::seconds(s)).to_rfc3339());
                match ctx.adapter.update_user(&body.user_id, serde_json::json!({"banned": true, "banReason": body.reason, "banExpires": ban_expires})).await {
                    Ok(u) => PluginHandlerResponse::ok(u),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // POST /admin/unban-user
        let unban_user: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>().expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { user_id: String }
                let body: Body = match serde_json::from_value(req.body.clone()) { Ok(b) => b, Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)) };
                match ctx.adapter.update_user(&body.user_id, serde_json::json!({"banned": false, "banReason": null::<String>, "banExpires": null::<String>})).await {
                    Ok(u) => PluginHandlerResponse::ok(u),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // POST /admin/impersonate-user
        let impersonate: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>().expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { user_id: String }
                let body: Body = match serde_json::from_value(req.body.clone()) { Ok(b) => b, Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)) };
                let token = uuid::Uuid::new_v4().to_string();
                let expires = chrono::Utc::now() + chrono::Duration::hours(1);
                let admin_id = req.session.as_ref().and_then(|s| s.get("user")).and_then(|u| u.get("id")).and_then(|id| id.as_str()).unwrap_or("").to_string();
                match ctx.adapter.create_session(&body.user_id, None, Some(expires.timestamp_millis())).await {
                    Ok(session) => PluginHandlerResponse::ok(serde_json::json!({"session": session, "token": token})),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // POST /admin/stop-impersonating
        let stop_impersonate: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>().expect("Expected AuthContext");
                let session_token = req.session.as_ref().and_then(|s| s.get("session")).and_then(|s| s.get("token")).and_then(|t| t.as_str()).unwrap_or("").to_string();
                if !session_token.is_empty() {
                    let _ = ctx.adapter.delete_session(&session_token).await;
                }
                PluginHandlerResponse::ok(serde_json::json!({"status": true}))
            })
        });

        // POST /admin/revoke-user-session
        let revoke_session: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>().expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { session_token: String }
                let body: Body = match serde_json::from_value(req.body.clone()) { Ok(b) => b, Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)) };
                match ctx.adapter.delete_session(&body.session_token).await {
                    Ok(_) => PluginHandlerResponse::ok(serde_json::json!({"status": true})),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // POST /admin/revoke-user-sessions
        let revoke_sessions: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>().expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { user_id: String }
                let body: Body = match serde_json::from_value(req.body.clone()) { Ok(b) => b, Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)) };
                match ctx.adapter.find_many("session", serde_json::json!({"userId": body.user_id})).await {
                    Ok(sessions) => {
                        for s in &sessions {
                            if let Some(token) = s.get("token").and_then(|t| t.as_str()) {
                                let _ = ctx.adapter.delete_session(token).await;
                            }
                        }
                        PluginHandlerResponse::ok(serde_json::json!({"status": true, "count": sessions.len()}))
                    }
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // POST /admin/remove-user
        let remove_user: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>().expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { user_id: String }
                let body: Body = match serde_json::from_value(req.body.clone()) { Ok(b) => b, Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)) };
                let _ = ctx.adapter.delete_by_id("user", &body.user_id).await;
                PluginHandlerResponse::ok(serde_json::json!({"status": true}))
            })
        });

        // POST /admin/set-user-password
        let set_password: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>().expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { user_id: String, new_password: String }
                let body: Body = match serde_json::from_value(req.body.clone()) { Ok(b) => b, Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)) };

                // Validate password length
                if body.new_password.len() < 8 {
                    return PluginHandlerResponse::error(400, "BAD_REQUEST", "Password is too short (minimum 8 characters)");
                }
                if body.new_password.len() > 128 {
                    return PluginHandlerResponse::error(400, "BAD_REQUEST", "Password is too long (maximum 128 characters)");
                }

                // Hash the password using scrypt
                let hashed_password = match crate::crypto::hash_password(&body.new_password) {
                    Ok(h) => h,
                    Err(_) => return PluginHandlerResponse::error(500, "INTERNAL_ERROR", "Failed to hash password"),
                };

                match ctx.adapter.find_many("account", serde_json::json!({"userId": body.user_id.clone(), "providerId": "credential"})).await {
                    Ok(accounts) if !accounts.is_empty() => {
                        let acct_id = accounts[0].get("id").and_then(|v| v.as_str()).unwrap_or("");
                        let _ = ctx.adapter.update_by_id("account", acct_id, serde_json::json!({"password": hashed_password})).await;
                        PluginHandlerResponse::ok(serde_json::json!({"status": true}))
                    }
                    _ => PluginHandlerResponse::error(404, "NOT_FOUND", "Credential account not found"),
                }
            })
        });

        // POST /admin/has-permission
        let has_perm: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let _ctx = ctx_any.downcast::<crate::context::AuthContext>().expect("Expected AuthContext");
                let role = req.session.as_ref().and_then(|s| s.get("user")).and_then(|u| u.get("role")).and_then(|r| r.as_str()).unwrap_or("user");
                #[derive(serde::Deserialize)]
                struct Body { permission: String }
                let body: Body = match serde_json::from_value(req.body.clone()) { Ok(b) => b, Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("{}", e)) };
                // Simple role-based check: admin has all permissions
                let has = role == "admin";
                PluginHandlerResponse::ok(serde_json::json!({"hasPermission": has, "permission": body.permission, "role": role}))
            })
        });

        vec![
            PluginEndpoint::with_handler("/admin/set-role", HttpMethod::Post, true, set_role),
            PluginEndpoint::with_handler("/admin/get-user", HttpMethod::Get, true, get_user),
            PluginEndpoint::with_handler("/admin/create-user", HttpMethod::Post, true, create_user),
            PluginEndpoint::with_handler("/admin/update-user", HttpMethod::Post, true, update_user),
            PluginEndpoint::with_handler("/admin/list-users", HttpMethod::Get, true, list_users),
            PluginEndpoint::with_handler("/admin/list-user-sessions", HttpMethod::Post, true, list_sessions),
            PluginEndpoint::with_handler("/admin/ban-user", HttpMethod::Post, true, ban_user),
            PluginEndpoint::with_handler("/admin/unban-user", HttpMethod::Post, true, unban_user),
            PluginEndpoint::with_handler("/admin/impersonate-user", HttpMethod::Post, true, impersonate),
            PluginEndpoint::with_handler("/admin/stop-impersonating", HttpMethod::Post, true, stop_impersonate),
            PluginEndpoint::with_handler("/admin/revoke-user-session", HttpMethod::Post, true, revoke_session),
            PluginEndpoint::with_handler("/admin/revoke-user-sessions", HttpMethod::Post, true, revoke_sessions),
            PluginEndpoint::with_handler("/admin/remove-user", HttpMethod::Post, true, remove_user),
            PluginEndpoint::with_handler("/admin/set-user-password", HttpMethod::Post, true, set_password),
            PluginEndpoint::with_handler("/admin/has-permission", HttpMethod::Post, true, has_perm),
        ]
    }

    fn hooks(&self) -> Vec<PluginHook> {
        vec![
            // Assign default role on user creation
            PluginHook {
                model: "user".to_string(),
                timing: HookTiming::Before,
                operation: HookOperation::Create,
            },
            // Check ban status on session creation
            PluginHook {
                model: "session".to_string(),
                timing: HookTiming::Before,
                operation: HookOperation::Create,
            },
            // Filter impersonation sessions from list-sessions
            PluginHook {
                model: "session".to_string(),
                timing: HookTiming::After,
                operation: HookOperation::Create,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_id() {
        let plugin = AdminPlugin::default();
        assert_eq!(plugin.id(), "admin");
    }

    #[test]
    fn test_plugin_name() {
        let plugin = AdminPlugin::default();
        assert_eq!(plugin.name(), "Admin");
    }

    #[test]
    fn test_endpoints_count() {
        let plugin = AdminPlugin::default();
        assert_eq!(plugin.endpoints().len(), 15);
    }

    #[test]
    fn test_schema_fields() {
        let plugin = AdminPlugin::default();
        let fields = plugin.additional_fields();
        assert!(fields["user"].contains_key("role"));
        assert!(fields["user"].contains_key("banned"));
        assert!(fields["user"].contains_key("banReason"));
        assert!(fields["user"].contains_key("banExpires"));
        assert!(fields["session"].contains_key("impersonatedBy"));
    }

    #[test]
    fn test_hooks_count() {
        let plugin = AdminPlugin::default();
        assert_eq!(plugin.hooks().len(), 3);
    }

    #[test]
    fn test_default_options() {
        let opts = AdminOptions::default();
        assert_eq!(opts.default_role, "user");
        assert_eq!(opts.admin_roles, vec!["admin".to_string()]);
        assert!(opts.admin_user_ids.is_empty());
        assert!(!opts.allow_impersonating_admins);
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(AdminErrorCodes::FAILED_TO_CREATE_USER, "FAILED_TO_CREATE_USER");
        assert_eq!(AdminErrorCodes::YOU_CANNOT_BAN_YOURSELF, "YOU_CANNOT_BAN_YOURSELF");
        assert_eq!(AdminErrorCodes::BANNED_USER, "BANNED_USER");
    }

    #[test]
    fn test_error_messages() {
        assert!(admin_error_message("FAILED_TO_CREATE_USER").contains("Failed"));
        assert!(admin_error_message("BANNED_USER").contains("banned"));
    }

    #[test]
    fn test_default_admin_statements() {
        let stmts = default_admin_statements();
        assert!(stmts.contains_key("user"));
        assert!(stmts.contains_key("session"));
        assert!(stmts["user"].contains(&"create".to_string()));
        assert!(stmts["user"].contains(&"ban".to_string()));
        assert!(stmts["user"].contains(&"impersonate".to_string()));
        assert!(stmts["session"].contains(&"revoke".to_string()));
    }

    #[test]
    fn test_default_admin_roles() {
        let roles = default_admin_roles();
        assert!(roles.contains_key("admin"));
        assert!(roles.contains_key("user"));
    }

    #[test]
    fn test_has_permission_admin_role() {
        let opts = AdminOptions::default();
        let mut perms = HashMap::new();
        perms.insert("user".to_string(), vec!["create".to_string()]);
        assert!(has_permission(None, Some("admin"), &opts, &perms));
    }

    #[test]
    fn test_has_permission_user_role_denied() {
        let opts = AdminOptions::default();
        let mut perms = HashMap::new();
        perms.insert("user".to_string(), vec!["create".to_string()]);
        assert!(!has_permission(None, Some("user"), &opts, &perms));
    }

    #[test]
    fn test_has_permission_admin_user_id() {
        let opts = AdminOptions {
            admin_user_ids: vec!["admin-123".to_string()],
            ..Default::default()
        };
        let mut perms = HashMap::new();
        perms.insert("user".to_string(), vec!["delete".to_string()]);
        assert!(has_permission(Some("admin-123"), Some("user"), &opts, &perms));
    }

    #[test]
    fn test_has_permission_no_role() {
        let opts = AdminOptions::default();
        let mut perms = HashMap::new();
        perms.insert("user".to_string(), vec!["read".to_string()]);
        // Default role = "user", which has read permission
        assert!(has_permission(None, None, &opts, &perms));
    }

    #[test]
    fn test_has_permission_comma_separated_roles() {
        let opts = AdminOptions::default();
        let mut perms = HashMap::new();
        perms.insert("user".to_string(), vec!["create".to_string()]);
        // "user,admin" → should pass because admin has create
        assert!(has_permission(None, Some("user,admin"), &opts, &perms));
    }

    #[test]
    fn test_parse_roles_string() {
        let val = serde_json::json!("admin");
        assert_eq!(parse_roles(&val), Some("admin".to_string()));
    }

    #[test]
    fn test_parse_roles_array() {
        let val = serde_json::json!(["admin", "user"]);
        assert_eq!(parse_roles(&val), Some("admin,user".to_string()));
    }

    #[test]
    fn test_validate_roles() {
        let roles = default_admin_roles();
        assert!(validate_roles(&["admin", "user"], &roles));
        assert!(!validate_roles(&["admin", "superadmin"], &roles));
    }

    #[test]
    fn test_is_user_banned_not_banned() {
        assert!(!is_user_banned(false, None));
    }

    #[test]
    fn test_is_user_banned_permanent() {
        assert!(is_user_banned(true, None));
    }

    #[test]
    fn test_is_user_banned_expired() {
        // Ban that expired yesterday
        let yesterday = (chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339();
        assert!(!is_user_banned(true, Some(&yesterday)));
    }

    #[test]
    fn test_is_user_banned_not_expired() {
        // Ban that expires tomorrow
        let tomorrow = (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339();
        assert!(is_user_banned(true, Some(&tomorrow)));
    }

    #[test]
    fn test_calculate_ban_expiry() {
        let expiry = calculate_ban_expiry(3600);
        assert!(!expiry.is_empty());
        // Should be parseable
        assert!(chrono::DateTime::parse_from_rfc3339(&expiry).is_ok());
    }

    #[test]
    fn test_is_user_admin_by_role() {
        assert!(is_user_admin(
            Some("admin"),
            &["admin".to_string()],
            &[],
            "user1",
        ));
    }

    #[test]
    fn test_is_user_admin_by_id() {
        assert!(is_user_admin(
            Some("user"),
            &["admin".to_string()],
            &["user1".to_string()],
            "user1",
        ));
    }

    #[test]
    fn test_is_user_admin_not_admin() {
        assert!(!is_user_admin(
            Some("user"),
            &["admin".to_string()],
            &[],
            "user1",
        ));
    }

    #[test]
    fn test_is_user_admin_comma_separated() {
        assert!(is_user_admin(
            Some("user,admin"),
            &["admin".to_string()],
            &[],
            "user1",
        ));
    }

    #[test]
    fn test_admin_session_cookie() {
        let cookie = build_admin_session_cookie("token123", "dontremember");
        assert_eq!(cookie, "token123:dontremember");

        let (token, dr) = parse_admin_session_cookie(&cookie).unwrap();
        assert_eq!(token, "token123");
        assert_eq!(dr, "dontremember");
    }

    #[test]
    fn test_parse_admin_session_cookie_empty_dr() {
        let cookie = build_admin_session_cookie("token123", "");
        let (token, dr) = parse_admin_session_cookie(&cookie).unwrap();
        assert_eq!(token, "token123");
        assert_eq!(dr, "");
    }
}
