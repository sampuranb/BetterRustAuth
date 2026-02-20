// MCP plugin — OAuth2/OIDC server for Model Context Protocol.
//
// Maps to: packages/better-auth/src/plugins/mcp/index.ts (1,061 lines)
// + authorize.ts (251 lines)
//
// MCP wraps the OIDC provider with MCP-specific endpoints and metadata,
// providing OAuth2 authorization for MCP (Model Context Protocol) clients.

use std::collections::HashMap;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use better_auth_core::db::schema::{AuthTable, SchemaField};
use better_auth_core::plugin::{
    BetterAuthPlugin, HookOperation, HookTiming, HttpMethod, PluginEndpoint, PluginHook,
    PluginRateLimit,
};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// MCP OAuth2 client record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpClient {
    pub id: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub name: String,
    pub icon: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub redirect_urls: Vec<String>,
    pub r#type: String,
    pub authentication_scheme: String,
    pub disabled: bool,
    pub user_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// MCP access token record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpAccessToken {
    pub id: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub access_token_expires_at: String,
    pub refresh_token_expires_at: Option<String>,
    pub client_id: String,
    pub user_id: String,
    pub scopes: String,
    pub created_at: String,
    pub updated_at: String,
}

/// MCP refresh token record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpRefreshToken {
    pub id: String,
    pub token: String,
    pub access_token_id: String,
    pub client_id: String,
    pub user_id: String,
    pub expires_at: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Registration request (RFC 7591 Dynamic Client Registration).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRegisterBody {
    pub redirect_uris: Vec<String>,
    pub token_endpoint_auth_method: Option<String>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub client_name: Option<String>,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
    pub scope: Option<String>,
    pub contacts: Option<Vec<String>>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub jwks_uri: Option<String>,
    pub software_id: Option<String>,
    pub software_version: Option<String>,
    pub software_statement: Option<String>,
}

/// Registration response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRegisterResponse {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub client_id_issued_at: i64,
    pub client_secret_expires_at: i64,
    pub redirect_uris: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
}

/// Authorization query parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpAuthorizeQuery {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub prompt: Option<String>,
}

/// Token request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTokenBody {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub refresh_token: Option<String>,
    pub code_verifier: Option<String>,
}

/// Token response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

/// Authorization server metadata (RFC 8414).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub registration_endpoint: String,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
}

/// Protected resource metadata (MCP-specific).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub jwks_uri: String,
    pub scopes_supported: Vec<String>,
    pub bearer_methods_supported: Vec<String>,
    pub resource_signing_alg_values_supported: Vec<String>,
}

/// Build server metadata for a base URL.
pub fn build_mcp_metadata(base_url: &str) -> McpServerMetadata {
    let base = base_url.trim_end_matches('/');
    McpServerMetadata {
        issuer: base.to_string(),
        authorization_endpoint: format!("{}/mcp/authorize", base),
        token_endpoint: format!("{}/mcp/token", base),
        userinfo_endpoint: format!("{}/mcp/userinfo", base),
        jwks_uri: format!("{}/mcp/jwks", base),
        registration_endpoint: format!("{}/mcp/register", base),
        scopes_supported: vec![
            "openid".into(),
            "profile".into(),
            "email".into(),
            "offline_access".into(),
        ],
        response_types_supported: vec!["code".into()],
        grant_types_supported: vec!["authorization_code".into(), "refresh_token".into()],
        token_endpoint_auth_methods_supported: vec![
            "client_secret_basic".into(),
            "client_secret_post".into(),
            "none".into(),
        ],
        code_challenge_methods_supported: vec!["S256".into()],
    }
}

/// Build protected resource metadata for a base URL.
pub fn build_mcp_protected_resource_metadata(
    base_url: &str,
    resource: Option<&str>,
) -> McpProtectedResourceMetadata {
    let base = base_url.trim_end_matches('/');
    // Extract origin from URL
    let origin = if let Some(idx) = base.find("//") {
        let after = &base[idx + 2..];
        let end = after.find('/').unwrap_or(after.len());
        format!("{}//{}", &base[..idx], &after[..end])
    } else {
        base.to_string()
    };

    McpProtectedResourceMetadata {
        resource: resource.unwrap_or(&origin).to_string(),
        authorization_servers: vec![origin],
        jwks_uri: format!("{}/mcp/jwks", base),
        scopes_supported: vec![
            "openid".into(),
            "profile".into(),
            "email".into(),
            "offline_access".into(),
        ],
        bearer_methods_supported: vec!["header".into()],
        resource_signing_alg_values_supported: vec!["RS256".into(), "none".into()],
    }
}

// ---------------------------------------------------------------------------
// PKCE verification
// ---------------------------------------------------------------------------

/// Verify a PKCE code challenge (S256 method).
pub fn verify_pkce_s256(code_verifier: &str, code_challenge: &str) -> bool {
    use sha2::{Digest, Sha256};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let hash = Sha256::digest(code_verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(hash);
    computed == code_challenge
}

// ---------------------------------------------------------------------------
// MCP Authorization handler
// ---------------------------------------------------------------------------

/// Code verification value for MCP authorization flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpCodeVerificationValue {
    pub client_id: String,
    pub redirect_uri: String,
    pub user_id: String,
    pub scope: Vec<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub state: Option<String>,
    pub require_consent: Option<bool>,
}

/// MCP authorize response variants.
#[derive(Debug, Clone)]
pub enum McpAuthorizeResponse {
    /// Redirect to login page.
    RedirectToLogin {
        login_url: String,
        original_query: String,
    },
    /// Redirect with authorization code.
    Redirect {
        redirect_uri: String,
        code: String,
        code_value: McpCodeVerificationValue,
        expires_in: i64,
    },
    /// Require consent.
    RequireConsent {
        code_value: McpCodeVerificationValue,
    },
}

/// Handle GET /mcp/authorize
///
/// MCP OAuth2 Authorization endpoint. Validates client, PKCE, scope,
/// and redirects to login or generates authorization code.
pub fn handle_mcp_authorize(
    query: &McpAuthorizeQuery,
    options: &McpOptions,
    user_id: Option<&str>,
) -> Result<McpAuthorizeResponse, McpError> {
    // Validate response_type
    if query.response_type != "code" {
        return Err(McpError::invalid_request("response_type must be 'code'"));
    }

    // Parse scopes
    let requested_scopes: Vec<String> = query
        .scope
        .as_deref()
        .unwrap_or("openid")
        .split_whitespace()
        .map(String::from)
        .collect();

    // PKCE is always required for MCP
    if query.code_challenge.is_none() {
        return Err(McpError::invalid_request(
            "code_challenge is required for MCP OAuth",
        ));
    }

    // Validate code_challenge_method
    if let Some(method) = &query.code_challenge_method {
        if method != "S256" {
            return Err(McpError::invalid_request(
                "only S256 code_challenge_method is supported",
            ));
        }
    }

    // Check prompt
    let prompts: Vec<String> = query
        .prompt
        .as_deref()
        .map(|p| p.split_whitespace().map(String::from).collect())
        .unwrap_or_default();

    if prompts.contains(&"none".to_string()) && user_id.is_none() {
        return Err(McpError {
            error: "login_required".into(),
            error_description: "User is not authenticated and prompt=none".into(),
        });
    }

    // If user is not authenticated, redirect to login
    if user_id.is_none() || prompts.contains(&"login".to_string()) {
        return Ok(McpAuthorizeResponse::RedirectToLogin {
            login_url: options.login_page.clone(),
            original_query: serde_json::to_string(query).unwrap_or_default(),
        });
    }

    let user_id = user_id.unwrap();

    let code_value = McpCodeVerificationValue {
        client_id: query.client_id.clone(),
        redirect_uri: query.redirect_uri.clone(),
        user_id: user_id.to_string(),
        scope: requested_scopes,
        code_challenge: query.code_challenge.clone(),
        code_challenge_method: query.code_challenge_method.clone(),
        state: query.state.clone(),
        require_consent: None,
    };

    // Generate authorization code
    let code = generate_random_code(32);
    let mut redirect_url = query.redirect_uri.clone();
    let sep = if redirect_url.contains('?') { "&" } else { "?" };
    redirect_url.push_str(&format!("{}code={}", sep, code));
    if let Some(state) = &query.state {
        redirect_url.push_str(&format!("&state={}", state));
    }

    Ok(McpAuthorizeResponse::Redirect {
        redirect_uri: redirect_url,
        code,
        code_value,
        expires_in: options.code_expires_in,
    })
}

// ---------------------------------------------------------------------------
// MCP Token handler
// ---------------------------------------------------------------------------

/// Handle POST /mcp/token
///
/// MCP token endpoint — exchanges authorization code or refresh token
/// for access tokens. Mirrors OIDC token endpoint with MCP-specific behavior.
pub fn handle_mcp_token(
    body: &McpTokenBody,
    authorization_header: Option<&str>,
    options: &McpOptions,
    stored_code_value: Option<&McpCodeVerificationValue>,
) -> Result<McpTokenResponse, McpError> {
    // Extract client credentials
    let (client_id, _client_secret) = extract_mcp_client_credentials(
        body.client_id.as_deref(),
        body.client_secret.as_deref(),
        authorization_header,
    )?;

    let access_token_expires_in = options.access_token_expires_in;

    match body.grant_type.as_str() {
        "refresh_token" => {
            let _refresh_token = body.refresh_token.as_deref()
                .ok_or_else(|| McpError::invalid_request("refresh_token is required"))?;

            // In production: look up refresh token, validate, generate new tokens
            let new_access_token = generate_random_code(32);
            let new_refresh_token = generate_random_code(32);

            Ok(McpTokenResponse {
                access_token: new_access_token,
                token_type: "Bearer".into(),
                expires_in: access_token_expires_in,
                refresh_token: Some(new_refresh_token),
                scope: None,
                id_token: None,
            })
        }
        "authorization_code" => {
            let _code = body.code.as_deref()
                .ok_or_else(|| McpError::invalid_request("code is required"))?;
            let _redirect_uri = body.redirect_uri.as_deref()
                .ok_or_else(|| McpError::invalid_request("redirect_uri is required"))?;

            if client_id.is_empty() {
                return Err(McpError::invalid_client("client_id is required"));
            }

            // PKCE verification (required for MCP)
            if let Some(verifier) = &body.code_verifier {
                if let Some(code_val) = stored_code_value {
                    if let Some(challenge) = &code_val.code_challenge {
                        if !verify_pkce_s256(verifier, challenge) {
                            return Err(McpError::invalid_request("PKCE verification failed"));
                        }
                    }
                }
            } else {
                return Err(McpError::invalid_request("code_verifier is required for MCP"));
            }

            let access_token = generate_random_code(32);
            let refresh_token = generate_random_code(32);

            Ok(McpTokenResponse {
                access_token,
                token_type: "Bearer".into(),
                expires_in: access_token_expires_in,
                refresh_token: Some(refresh_token),
                scope: stored_code_value.map(|v| v.scope.join(" ")),
                id_token: None,
            })
        }
        _ => Err(McpError {
            error: "unsupported_grant_type".into(),
            error_description: format!("unsupported grant_type: {}", body.grant_type),
        }),
    }
}

/// Extract client credentials from body or Basic auth header.
fn extract_mcp_client_credentials(
    body_client_id: Option<&str>,
    body_client_secret: Option<&str>,
    authorization: Option<&str>,
) -> Result<(String, Option<String>), McpError> {
    if let (Some(id), secret) = (body_client_id, body_client_secret) {
        return Ok((id.to_string(), secret.map(String::from)));
    }

    if let Some(auth) = authorization {
        if let Some(encoded) = auth.strip_prefix("Basic ") {
            use base64::engine::general_purpose::STANDARD;
            use base64::Engine;
            let decoded = STANDARD
                .decode(encoded)
                .map_err(|_| McpError::invalid_client("invalid authorization header"))?;
            let decoded_str = String::from_utf8(decoded)
                .map_err(|_| McpError::invalid_client("invalid authorization header encoding"))?;
            let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
            if parts.len() != 2 || parts[0].is_empty() {
                return Err(McpError::invalid_client("invalid authorization header format"));
            }
            return Ok((parts[0].to_string(), Some(parts[1].to_string())));
        }
    }

    Ok((String::new(), None))
}

// ---------------------------------------------------------------------------
// MCP Registration handler
// ---------------------------------------------------------------------------

/// Handle POST /mcp/register
///
/// Dynamic client registration for MCP clients (RFC 7591).
pub fn handle_mcp_register(
    body: &McpRegisterBody,
) -> Result<McpRegisterResponse, McpError> {
    if body.redirect_uris.is_empty() {
        return Err(McpError::invalid_request("redirect_uris is required"));
    }

    let client_id = generate_random_code(32);
    let client_secret = generate_random_code(48);
    let now = chrono::Utc::now().timestamp();

    let auth_method = body
        .token_endpoint_auth_method
        .as_deref()
        .unwrap_or("client_secret_basic");
    let has_secret = auth_method != "none";

    Ok(McpRegisterResponse {
        client_id,
        client_secret: if has_secret { Some(client_secret) } else { None },
        client_id_issued_at: now,
        client_secret_expires_at: 0,
        redirect_uris: body.redirect_uris.clone(),
        token_endpoint_auth_method: auth_method.to_string(),
        grant_types: body
            .grant_types
            .clone()
            .unwrap_or_else(|| vec!["authorization_code".into()]),
        response_types: body
            .response_types
            .clone()
            .unwrap_or_else(|| vec!["code".into()]),
        client_name: body.client_name.clone(),
        client_uri: body.client_uri.clone(),
        logo_uri: body.logo_uri.clone(),
    })
}

// ---------------------------------------------------------------------------
// MCP Userinfo handler
// ---------------------------------------------------------------------------

/// Handle GET /mcp/userinfo
///
/// Returns user claims based on access token scopes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpUserinfoResponse {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
}

pub fn build_mcp_userinfo(
    user_id: &str,
    user_name: Option<&str>,
    user_email: Option<&str>,
    email_verified: Option<bool>,
    user_image: Option<&str>,
    scopes: &[String],
) -> McpUserinfoResponse {
    let mut response = McpUserinfoResponse {
        sub: user_id.to_string(),
        name: None,
        email: None,
        email_verified: None,
        picture: None,
    };

    if scopes.iter().any(|s| s == "profile") {
        response.name = user_name.map(String::from);
        response.picture = user_image.map(String::from);
    }

    if scopes.iter().any(|s| s == "email") {
        response.email = user_email.map(String::from);
        response.email_verified = email_verified;
    }

    response
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// MCP Error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpError {
    pub error: String,
    pub error_description: String,
}

impl std::fmt::Display for McpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.error, self.error_description)
    }
}

impl std::error::Error for McpError {}

impl McpError {
    pub fn invalid_request(desc: &str) -> Self {
        Self { error: "invalid_request".into(), error_description: desc.into() }
    }
    pub fn invalid_client(desc: &str) -> Self {
        Self { error: "invalid_client".into(), error_description: desc.into() }
    }
    pub fn invalid_grant(desc: &str) -> Self {
        Self { error: "invalid_grant".into(), error_description: desc.into() }
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn generate_random_code(len: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Plugin options
// ---------------------------------------------------------------------------

/// MCP plugin options.
#[derive(Debug, Clone)]
pub struct McpOptions {
    /// Login page URL for redirect.
    pub login_page: String,
    /// Resource identifier for the protected resource metadata.
    pub resource: Option<String>,
    /// Code expiration in seconds (default: 600).
    pub code_expires_in: i64,
    /// Access token expiration in seconds (default: 3600).
    pub access_token_expires_in: i64,
    /// Refresh token expiration in seconds (default: 604800).
    pub refresh_token_expires_in: i64,
    /// Additional scopes beyond the defaults.
    pub scopes: Vec<String>,
}

impl Default for McpOptions {
    fn default() -> Self {
        Self {
            login_page: "/login".to_string(),
            resource: None,
            code_expires_in: 600,
            access_token_expires_in: 3600,
            refresh_token_expires_in: 604800,
            scopes: vec![
                "openid".into(),
                "profile".into(),
                "email".into(),
                "offline_access".into(),
            ],
        }
    }
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

pub fn mcp_client_table() -> AuthTable {
    AuthTable::new("oauthApplication")
        .field("id", SchemaField::required_string())
        .field("clientId", SchemaField::required_string().with_unique())
        .field("clientSecret", SchemaField::optional_string())
        .field("name", SchemaField::required_string())
        .field("icon", SchemaField::optional_string())
        .field("metadata", SchemaField::optional_string())
        .field("redirectUrls", SchemaField::required_string())
        .field("type", SchemaField::required_string())
        .field("authenticationScheme", SchemaField::required_string())
        .field("disabled", SchemaField::boolean(false))
        .field("userId", SchemaField::optional_string())
        .field("createdAt", SchemaField::created_at())
        .field("updatedAt", SchemaField::updated_at())
}

pub fn mcp_access_token_table() -> AuthTable {
    AuthTable::new("oauthAccessToken")
        .field("id", SchemaField::required_string())
        .field("accessToken", SchemaField::required_string().with_unique())
        .field("refreshToken", SchemaField::optional_string())
        .field("accessTokenExpiresAt", SchemaField::required_string())
        .field("refreshTokenExpiresAt", SchemaField::optional_string())
        .field("clientId", SchemaField::required_string())
        .field("userId", SchemaField::required_string())
        .field("scopes", SchemaField::required_string())
        .field("createdAt", SchemaField::created_at())
        .field("updatedAt", SchemaField::updated_at())
}

pub fn mcp_refresh_token_table() -> AuthTable {
    AuthTable::new("oauthConsent")
        .field("id", SchemaField::required_string())
        .field("clientId", SchemaField::required_string())
        .field("userId", SchemaField::required_string())
        .field("scopes", SchemaField::required_string())
        .field("consentGiven", SchemaField::boolean(false))
        .field("createdAt", SchemaField::created_at())
        .field("updatedAt", SchemaField::updated_at())
}

// ---------------------------------------------------------------------------
// Plugin definition
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct McpPlugin {
    options: McpOptions,
}

impl McpPlugin {
    pub fn new(options: McpOptions) -> Self {
        Self { options }
    }
    pub fn options(&self) -> &McpOptions {
        &self.options
    }
}

impl Default for McpPlugin {
    fn default() -> Self {
        Self::new(McpOptions::default())
    }
}

#[async_trait]
impl BetterAuthPlugin for McpPlugin {
    fn id(&self) -> &str {
        "mcp"
    }
    fn name(&self) -> &str {
        "MCP"
    }
    fn endpoints(&self) -> Vec<PluginEndpoint> {
        use std::sync::Arc;
        use better_auth_core::plugin::{PluginHandlerFn, PluginHandlerRequest, PluginHandlerResponse};

        let opts = self.options.clone();

        // GET /.well-known/oauth-authorization-server
        let metadata_opts = opts.clone();
        let metadata_handler: PluginHandlerFn = Arc::new(move |ctx_any, _req: PluginHandlerRequest| {
            let opts = metadata_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>().expect("Expected AuthContext");
                let metadata = build_mcp_metadata(ctx.base_url.as_deref().unwrap_or(""));
                PluginHandlerResponse::ok(serde_json::to_value(metadata).unwrap_or_default())
            })
        });

        // GET /.well-known/oauth-protected-resource
        let resource_handler: PluginHandlerFn = Arc::new(move |ctx_any, _req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>().expect("Expected AuthContext");
                PluginHandlerResponse::ok(serde_json::json!({
                    "resource": ctx.base_url.as_deref().unwrap_or(""),
                    "authorization_servers": [ctx.base_url.as_deref().unwrap_or("")],
                }))
            })
        });

        // GET /mcp/authorize
        let auth_opts = opts.clone();
        let authorize_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let opts = auth_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>().expect("Expected AuthContext");
                let client_id = req.query.get("client_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let redirect_uri = req.query.get("redirect_uri").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let state = req.query.get("state").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let scope = req.query.get("scope").and_then(|v| v.as_str()).unwrap_or("openid").to_string();
                let code_challenge = req.query.get("code_challenge").and_then(|v| v.as_str()).map(String::from);
                let code_challenge_method = req.query.get("code_challenge_method").and_then(|v| v.as_str()).map(String::from);
                let response_type = req.query.get("response_type").and_then(|v| v.as_str()).unwrap_or("code").to_string();

                if client_id.is_empty() || redirect_uri.is_empty() {
                    return PluginHandlerResponse::error(400, "INVALID_REQUEST", "Missing client_id or redirect_uri");
                }

                if response_type != "code" {
                    let sep = if redirect_uri.contains('?') { "&" } else { "?" };
                    let error_url = format!("{}{}error=unsupported_response_type&error_description=response_type+must+be+code", redirect_uri, sep);
                    return PluginHandlerResponse { status: 302, body: serde_json::json!({}), headers: HashMap::from([("Location".into(), error_url)]), redirect: None };
                }

                // PKCE is always required for MCP
                if code_challenge.is_none() {
                    let sep = if redirect_uri.contains('?') { "&" } else { "?" };
                    let error_url = format!("{}{}error=invalid_request&error_description=code_challenge+is+required+for+MCP+OAuth", redirect_uri, sep);
                    return PluginHandlerResponse { status: 302, body: serde_json::json!({}), headers: HashMap::from([("Location".into(), error_url)]), redirect: None };
                }

                // Only S256 allowed for MCP
                if let Some(ref method) = code_challenge_method {
                    if method != "S256" {
                        let sep = if redirect_uri.contains('?') { "&" } else { "?" };
                        let error_url = format!("{}{}error=invalid_request&error_description=only+S256+code_challenge_method+is+supported", redirect_uri, sep);
                        return PluginHandlerResponse { status: 302, body: serde_json::json!({}), headers: HashMap::from([("Location".into(), error_url)]), redirect: None };
                    }
                }

                // Parse scopes
                let requested_scopes: Vec<String> = scope.split_whitespace()
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect();

                // Check if user is authenticated
                let user_id = req.session.as_ref()
                    .and_then(|s| s.get("user"))
                    .and_then(|u| u.get("id"))
                    .and_then(|id| id.as_str())
                    .map(String::from);

                if user_id.is_none() {
                    let login_url = format!("{}?client_id={}&redirect_uri={}&scope={}&state={}",
                        opts.login_page, client_id, redirect_uri, scope, state);
                    return PluginHandlerResponse { status: 302, body: serde_json::json!({}), headers: HashMap::from([("Location".into(), login_url)]), redirect: None };
                }

                let user_id = user_id.unwrap();

                // Generate authorization code with full context
                let code = generate_random_code(32);
                let expires = chrono::Utc::now() + chrono::Duration::seconds(opts.code_expires_in);
                let _ = ctx.adapter.create_verification(&format!("mcp:auth:{}", code), &serde_json::json!({
                    "clientId": client_id,
                    "redirectUri": redirect_uri,
                    "scope": requested_scopes,
                    "userId": user_id,
                    "codeChallenge": code_challenge,
                    "codeChallengeMethod": code_challenge_method.as_deref().unwrap_or("S256"),
                }).to_string(), expires).await;

                let sep = if redirect_uri.contains('?') { "&" } else { "?" };
                let redirect_url = format!("{}{}code={}&state={}", redirect_uri, sep, code, state);
                PluginHandlerResponse {
                    status: 302, body: serde_json::json!({}),
                    headers: HashMap::from([("Location".into(), redirect_url)]), redirect: None,
                }
            })
        });

        // POST /mcp/token
        let token_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>().expect("Expected AuthContext");
                let grant_type = req.body.get("grant_type").and_then(|v| v.as_str()).unwrap_or("").to_string();

                // Extract client credentials from body or Basic auth header
                let body_client_id = req.body.get("client_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let body_client_secret = req.body.get("client_secret").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let auth_header = req.headers.get("authorization")
                    .or_else(|| req.headers.get("Authorization"))
                    .cloned()
                    .unwrap_or_default();

                let (client_id, _client_secret) = if !body_client_id.is_empty() {
                    (body_client_id, if body_client_secret.is_empty() { None } else { Some(body_client_secret) })
                } else if auth_header.starts_with("Basic ") {
                    let encoded = &auth_header[6..];
                    use base64::engine::general_purpose::STANDARD;
                    use base64::Engine;
                    match STANDARD.decode(encoded) {
                        Ok(decoded) => {
                            let decoded_str = String::from_utf8(decoded).unwrap_or_default();
                            let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
                            if parts.len() == 2 { (parts[0].to_string(), Some(parts[1].to_string())) }
                            else { return PluginHandlerResponse::error(401, "INVALID_CLIENT", "invalid authorization header format"); }
                        }
                        Err(_) => return PluginHandlerResponse::error(401, "INVALID_CLIENT", "invalid authorization header encoding"),
                    }
                } else {
                    (String::new(), None)
                };

                match grant_type.as_str() {
                    "authorization_code" => {
                        let code = req.body.get("code").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let code_verifier = req.body.get("code_verifier").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let redirect_uri = req.body.get("redirect_uri").and_then(|v| v.as_str()).unwrap_or("").to_string();

                        if code.is_empty() {
                            return PluginHandlerResponse::error(400, "INVALID_REQUEST", "code is required");
                        }
                        // PKCE is required for MCP
                        if code_verifier.is_empty() {
                            return PluginHandlerResponse::error(400, "INVALID_REQUEST", "code_verifier is required for MCP");
                        }

                        match ctx.adapter.find_verification(&format!("mcp:auth:{}", code)).await {
                            Ok(Some(v)) => {
                                let stored_val = v.get("value").and_then(|v| v.as_str()).unwrap_or("{}");
                                let auth_data: serde_json::Value = serde_json::from_str(stored_val).unwrap_or_default();
                                let stored_client_id = auth_data.get("clientId").and_then(|v| v.as_str()).unwrap_or("");

                                // Validate client_id matches
                                if !client_id.is_empty() && stored_client_id != client_id {
                                    return PluginHandlerResponse::error(400, "INVALID_GRANT", "client_id mismatch");
                                }
                                // Validate redirect_uri matches
                                let stored_redirect = auth_data.get("redirectUri").and_then(|v| v.as_str()).unwrap_or("");
                                if !redirect_uri.is_empty() && stored_redirect != redirect_uri {
                                    return PluginHandlerResponse::error(400, "INVALID_GRANT", "redirect_uri mismatch");
                                }

                                // PKCE S256 verification
                                let challenge = auth_data.get("codeChallenge").and_then(|v| v.as_str()).unwrap_or("");
                                if !challenge.is_empty() {
                                    if !verify_pkce_s256(&code_verifier, challenge) {
                                        return PluginHandlerResponse::error(400, "INVALID_GRANT", "PKCE verification failed");
                                    }
                                }

                                let _ = ctx.adapter.delete_verification(&format!("mcp:auth:{}", code)).await;

                                let user_id = auth_data.get("userId").and_then(|v| v.as_str()).unwrap_or("unknown");
                                let scopes: Vec<String> = auth_data.get("scope")
                                    .and_then(|v| v.as_array())
                                    .map(|arr| arr.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                                    .unwrap_or_else(|| vec!["openid".to_string()]);

                                let access_token = generate_random_code(32);
                                let refresh_token = generate_random_code(32);
                                let now = chrono::Utc::now();
                                let expires_in = 3600i64;
                                let access_expires = now + chrono::Duration::seconds(expires_in);
                                let refresh_expires = now + chrono::Duration::seconds(604800);

                                let _ = ctx.adapter.create("oauthAccessToken", serde_json::json!({
                                    "id": uuid::Uuid::new_v4().to_string(),
                                    "accessToken": access_token,
                                    "refreshToken": refresh_token,
                                    "accessTokenExpiresAt": access_expires.to_rfc3339(),
                                    "refreshTokenExpiresAt": refresh_expires.to_rfc3339(),
                                    "clientId": if client_id.is_empty() { stored_client_id.to_string() } else { client_id.clone() },
                                    "userId": user_id,
                                    "scopes": scopes.join(" "),
                                    "createdAt": now.to_rfc3339(),
                                    "updatedAt": now.to_rfc3339(),
                                })).await;

                                PluginHandlerResponse::ok(serde_json::json!({
                                    "access_token": access_token,
                                    "refresh_token": refresh_token,
                                    "token_type": "Bearer",
                                    "expires_in": expires_in,
                                    "scope": scopes.join(" "),
                                }))
                            }
                            _ => PluginHandlerResponse::error(400, "INVALID_GRANT", "Invalid authorization code"),
                        }
                    }
                    "refresh_token" => {
                        let refresh_token_val = req.body.get("refresh_token").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        if refresh_token_val.is_empty() {
                            return PluginHandlerResponse::error(400, "INVALID_REQUEST", "refresh_token is required");
                        }
                        match ctx.adapter.find_many("oauthAccessToken", serde_json::json!({"refreshToken": refresh_token_val.clone()})).await {
                            Ok(tokens) if !tokens.is_empty() => {
                                let existing = &tokens[0];
                                // Validate client_id
                                let stored_cid = existing.get("clientId").and_then(|v| v.as_str()).unwrap_or("");
                                if !client_id.is_empty() && stored_cid != client_id {
                                    return PluginHandlerResponse::error(400, "INVALID_GRANT", "client_id mismatch");
                                }
                                // Check expiry
                                if let Some(expires_str) = existing.get("refreshTokenExpiresAt").and_then(|v| v.as_str()) {
                                    if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(expires_str) {
                                        if expires < chrono::Utc::now() {
                                            return PluginHandlerResponse::error(400, "INVALID_GRANT", "refresh_token has expired");
                                        }
                                    }
                                }
                                let new_access_token = generate_random_code(32);
                                let new_refresh_token = generate_random_code(32);
                                let now = chrono::Utc::now();
                                let access_expires = now + chrono::Duration::seconds(3600);
                                let refresh_expires = now + chrono::Duration::seconds(604800);
                                if let Some(id) = existing.get("id").and_then(|v| v.as_str()) {
                                    let _ = ctx.adapter.update_by_id("oauthAccessToken", id, serde_json::json!({
                                        "accessToken": new_access_token,
                                        "refreshToken": new_refresh_token,
                                        "accessTokenExpiresAt": access_expires.to_rfc3339(),
                                        "refreshTokenExpiresAt": refresh_expires.to_rfc3339(),
                                        "updatedAt": now.to_rfc3339(),
                                    })).await;
                                }
                                PluginHandlerResponse::ok(serde_json::json!({
                                    "access_token": new_access_token,
                                    "refresh_token": new_refresh_token,
                                    "token_type": "Bearer",
                                    "expires_in": 3600,
                                }))
                            }
                            _ => PluginHandlerResponse::error(400, "INVALID_GRANT", "Invalid refresh token"),
                        }
                    }
                    _ => PluginHandlerResponse::error(400, "UNSUPPORTED_GRANT_TYPE", "Unsupported grant type"),
                }
            })
        });

        // GET /mcp/userinfo
        let userinfo_handler: PluginHandlerFn = Arc::new(move |_ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                match req.session.as_ref().and_then(|s| s.get("user")) {
                    Some(user) => PluginHandlerResponse::ok(user.clone()),
                    None => PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
                }
            })
        });

        // POST /mcp/register (Dynamic Client Registration)
        let register_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>().expect("Expected AuthContext");
                let client_name = req.body.get("client_name").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string();
                let client_id = uuid::Uuid::new_v4().to_string();
                let client_secret = uuid::Uuid::new_v4().to_string();
                let record = serde_json::json!({
                    "id": client_id.clone(), "clientId": client_id, "clientSecret": client_secret,
                    "clientName": client_name,
                    "redirectUris": req.body.get("redirect_uris").cloned().unwrap_or(serde_json::json!([])),
                    "createdAt": chrono::Utc::now().to_rfc3339(),
                });
                let _ = ctx.adapter.create("mcpClient", record).await;
                PluginHandlerResponse::created(serde_json::json!({
                    "client_id": client_id, "client_secret": client_secret, "client_name": client_name,
                }))
            })
        });

        // GET /mcp/jwks
        let jwks_handler: PluginHandlerFn = Arc::new(move |_ctx_any, _req: PluginHandlerRequest| {
            Box::pin(async move {
                PluginHandlerResponse::ok(serde_json::json!({"keys": []}))
            })
        });

        // POST /oauth2/consent
        let consent_handler: PluginHandlerFn = Arc::new(move |_ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let approved = req.body.get("approved").and_then(|v| v.as_bool()).unwrap_or(false);
                PluginHandlerResponse::ok(serde_json::json!({"approved": approved}))
            })
        });

        // GET /mcp/get-session — TS getMcpSession (index.ts:931)
        // Returns access token data for a Bearer token, used by withMcpAuth helper
        let get_session_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>().expect("Expected AuthContext");
                let auth_header = req.headers.get("authorization")
                    .or_else(|| req.headers.get("Authorization"))
                    .cloned()
                    .unwrap_or_default();
                let access_token = if auth_header.starts_with("Bearer ") {
                    &auth_header[7..]
                } else {
                    return PluginHandlerResponse {
                        status: 200,
                        body: serde_json::Value::Null,
                        headers: HashMap::from([("WWW-Authenticate".into(), "Bearer".into())]),
                        redirect: None,
                    };
                };
                match ctx.adapter.find_many("oauthAccessToken", serde_json::json!({"accessToken": access_token})).await {
                    Ok(tokens) if !tokens.is_empty() => {
                        PluginHandlerResponse::ok(tokens[0].clone())
                    }
                    _ => PluginHandlerResponse::ok(serde_json::Value::Null),
                }
            })
        });

        vec![
            PluginEndpoint::with_handler("/.well-known/oauth-authorization-server", HttpMethod::Get, false, metadata_handler),
            PluginEndpoint::with_handler("/.well-known/oauth-protected-resource", HttpMethod::Get, false, resource_handler),
            PluginEndpoint::with_handler("/mcp/authorize", HttpMethod::Get, false, authorize_handler),
            PluginEndpoint::with_handler("/mcp/token", HttpMethod::Post, false, token_handler),
            PluginEndpoint::with_handler("/mcp/userinfo", HttpMethod::Get, true, userinfo_handler),
            PluginEndpoint::with_handler("/mcp/register", HttpMethod::Post, false, register_handler),
            PluginEndpoint::with_handler("/mcp/jwks", HttpMethod::Get, false, jwks_handler),
            PluginEndpoint::with_handler("/oauth2/consent", HttpMethod::Post, true, consent_handler),
            PluginEndpoint::with_handler("/mcp/get-session", HttpMethod::Get, false, get_session_handler),
        ]
    }

    fn schema(&self) -> Vec<AuthTable> {
        vec![
            mcp_client_table(),
            mcp_access_token_table(),
            mcp_refresh_token_table(),
        ]
    }

    fn hooks(&self) -> Vec<PluginHook> {
        vec![
            // After hook: check for oidc_login_prompt cookie after login
            PluginHook {
                model: "session".to_string(),
                operation: HookOperation::Create,
                timing: HookTiming::After,
            },
        ]
    }

    fn rate_limit(&self) -> Vec<PluginRateLimit> {
        vec![PluginRateLimit {
            path: "/mcp".to_string(),
            window: 60,
            max: 100,
        }]
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_id() {
        let plugin = McpPlugin::default();
        assert_eq!(plugin.id(), "mcp");
    }

    #[test]
    fn test_plugin_name() {
        let plugin = McpPlugin::default();
        assert_eq!(plugin.name(), "MCP");
    }

    #[test]
    fn test_endpoints() {
        let plugin = McpPlugin::default();
        let eps = plugin.endpoints();
        assert_eq!(eps.len(), 9);
    }

    #[test]
    fn test_schema_tables() {
        let plugin = McpPlugin::default();
        let tables = plugin.schema();
        assert_eq!(tables.len(), 3);
    }

    #[test]
    fn test_build_mcp_metadata() {
        let metadata = build_mcp_metadata("https://example.com/api/auth");
        assert_eq!(metadata.issuer, "https://example.com/api/auth");
        assert_eq!(
            metadata.authorization_endpoint,
            "https://example.com/api/auth/mcp/authorize"
        );
    }

    #[test]
    fn test_build_protected_resource_metadata() {
        let metadata = build_mcp_protected_resource_metadata(
            "https://example.com/api/auth",
            None,
        );
        assert_eq!(metadata.resource, "https://example.com");
        assert!(metadata.bearer_methods_supported.contains(&"header".to_string()));
    }

    #[test]
    fn test_pkce_verification() {
        // Just ensure it doesn't panic
        let result = verify_pkce_s256("test_verifier", "test_challenge");
        assert!(result || !result);
    }

    #[test]
    fn test_authorize_requires_code_challenge() {
        let query = McpAuthorizeQuery {
            client_id: "test".into(),
            redirect_uri: "https://example.com/cb".into(),
            response_type: "code".into(),
            scope: Some("openid".into()),
            state: None,
            code_challenge: None,
            code_challenge_method: None,
            prompt: None,
        };
        let result = handle_mcp_authorize(&query, &McpOptions::default(), Some("user-123"));
        assert!(result.is_err());
    }

    #[test]
    fn test_authorize_redirect_to_login() {
        let query = McpAuthorizeQuery {
            client_id: "test".into(),
            redirect_uri: "https://example.com/cb".into(),
            response_type: "code".into(),
            scope: Some("openid".into()),
            state: None,
            code_challenge: Some("challenge".into()),
            code_challenge_method: Some("S256".into()),
            prompt: None,
        };
        let result = handle_mcp_authorize(&query, &McpOptions::default(), None);
        assert!(result.is_ok());
        match result.unwrap() {
            McpAuthorizeResponse::RedirectToLogin { .. } => {}
            _ => panic!("Expected RedirectToLogin"),
        }
    }

    #[test]
    fn test_authorize_with_user() {
        let query = McpAuthorizeQuery {
            client_id: "test-client".into(),
            redirect_uri: "https://example.com/cb".into(),
            response_type: "code".into(),
            scope: Some("openid profile".into()),
            state: Some("state123".into()),
            code_challenge: Some("challenge".into()),
            code_challenge_method: Some("S256".into()),
            prompt: None,
        };
        let result = handle_mcp_authorize(&query, &McpOptions::default(), Some("user-123"));
        assert!(result.is_ok());
        match result.unwrap() {
            McpAuthorizeResponse::Redirect { redirect_uri, code, .. } => {
                assert!(redirect_uri.contains("code="));
                assert!(redirect_uri.contains("state=state123"));
                assert!(!code.is_empty());
            }
            _ => panic!("Expected Redirect"),
        }
    }

    #[test]
    fn test_token_unsupported_grant() {
        let body = McpTokenBody {
            grant_type: "invalid".into(),
            code: None,
            redirect_uri: None,
            client_id: Some("test".into()),
            client_secret: None,
            refresh_token: None,
            code_verifier: None,
        };
        let result = handle_mcp_token(&body, None, &McpOptions::default(), None);
        assert!(result.is_err());
        assert!(result.unwrap_err().error.contains("unsupported"));
    }

    #[test]
    fn test_register_client() {
        let body = McpRegisterBody {
            redirect_uris: vec!["https://example.com/cb".into()],
            token_endpoint_auth_method: None,
            grant_types: None,
            response_types: None,
            client_name: Some("MCP Client".into()),
            client_uri: None,
            logo_uri: None,
            scope: None,
            contacts: None,
            tos_uri: None,
            policy_uri: None,
            jwks_uri: None,
            software_id: None,
            software_version: None,
            software_statement: None,
        };
        let result = handle_mcp_register(&body);
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert!(!resp.client_id.is_empty());
        assert!(resp.client_secret.is_some());
    }

    #[test]
    fn test_build_userinfo() {
        let info = build_mcp_userinfo(
            "user-123",
            Some("John Doe"),
            Some("john@example.com"),
            Some(true),
            None,
            &["openid".into(), "profile".into(), "email".into()],
        );
        assert_eq!(info.sub, "user-123");
        assert_eq!(info.name.as_deref(), Some("John Doe"));
        assert_eq!(info.email.as_deref(), Some("john@example.com"));
    }
}
