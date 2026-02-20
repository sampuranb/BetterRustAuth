// OAuth callback route — maps to packages/better-auth/src/api/routes/callback.ts
//
// Handles OAuth provider callback with redirect-based error handling,
// state validation, user info processing, account linking, and session creation.

use std::sync::Arc;

use serde::Deserialize;

use crate::context::AuthContext;
use crate::internal_adapter::AdapterError;
use crate::oauth::link_account::{HandleOAuthOptions, OAuthAccountInfo, OAuthUserInfo, OAuthUserResult};

/// OAuth callback query parameters.
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
    /// User data from certain providers (e.g., Apple).
    #[serde(default)]
    pub user: Option<String>,
}

/// Callback result — either a redirect URL or an error redirect.
#[derive(Debug)]
pub enum CallbackResult {
    /// Redirect to the callback URL with session set.
    Redirect(String),
    /// Error redirect to the error URL.
    ErrorRedirect(String),
}

impl CallbackResult {
    /// Get the redirect URL regardless of variant.
    pub fn url(&self) -> &str {
        match self {
            Self::Redirect(url) | Self::ErrorRedirect(url) => url,
        }
    }
}

/// Build an error redirect URL with the given error code and optional description.
fn build_error_redirect(base_url: &str, error: &str, description: Option<&str>) -> String {
    let sep = if base_url.contains('?') { "&" } else { "?" };
    let mut url = format!("{}{}error={}", base_url, sep, error);
    if let Some(desc) = description {
        url.push_str(&format!("&error_description={}", desc));
    }
    url
}

/// Parse stored state data from the verification table.
struct ParsedState {
    provider: String,
    callback_url: String,
    error_url: Option<String>,
    new_user_url: Option<String>,
    code_verifier: Option<String>,
    link: Option<LinkData>,
    request_sign_up: bool,
}

/// Link data stored in state for account linking flow.
struct LinkData {
    user_id: String,
    email: String,
}

fn parse_state_data(value: &serde_json::Value) -> ParsedState {
    let data: serde_json::Value = value["value"]
        .as_str()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_else(|| value.clone());

    let link = if data["link"].is_object() {
        Some(LinkData {
            user_id: data["link"]["userId"].as_str().unwrap_or_default().to_string(),
            email: data["link"]["email"].as_str().unwrap_or_default().to_string(),
        })
    } else {
        None
    };

    ParsedState {
        provider: data["provider"].as_str().unwrap_or("unknown").to_string(),
        callback_url: data["callbackUrl"].as_str().unwrap_or("/").to_string(),
        error_url: data["errorUrl"].as_str().map(|s| s.to_string()),
        new_user_url: data["newUserUrl"].as_str().map(|s| s.to_string()),
        code_verifier: data["codeVerifier"].as_str().map(|s| s.to_string()),
        link,
        request_sign_up: data["requestSignUp"].as_bool().unwrap_or(false),
    }
}

/// Handle OAuth callback POST → GET redirect.
///
/// Matches TS behavior: when a POST arrives at `/callback/:id`, the handler
/// merges body + query parameters and issues a 302 redirect back to the same
/// path as GET with all params in the query string.
///
/// This ensures cookies can be properly set on the response (some browsers
/// restrict Set-Cookie on POST redirects).
pub fn handle_callback_post(
    base_url: &str,
    provider: &str,
    body: &CallbackQuery,
    query: &CallbackQuery,
) -> CallbackResult {
    // Merge body and query params (query takes precedence, matching TS `{ ...postData, ...queryData }`)
    let merged = CallbackQuery {
        code: query.code.clone().or_else(|| body.code.clone()),
        state: query.state.clone().or_else(|| body.state.clone()),
        error: query.error.clone().or_else(|| body.error.clone()),
        error_description: query.error_description.clone().or_else(|| body.error_description.clone()),
        device_id: query.device_id.clone().or_else(|| body.device_id.clone()),
        user: query.user.clone().or_else(|| body.user.clone()),
    };

    // Build query string from merged params
    let mut params = Vec::new();
    if let Some(ref v) = merged.code { params.push(format!("code={}", urlencoding::encode(v))); }
    if let Some(ref v) = merged.state { params.push(format!("state={}", urlencoding::encode(v))); }
    if let Some(ref v) = merged.error { params.push(format!("error={}", urlencoding::encode(v))); }
    if let Some(ref v) = merged.error_description { params.push(format!("error_description={}", urlencoding::encode(v))); }
    if let Some(ref v) = merged.device_id { params.push(format!("device_id={}", urlencoding::encode(v))); }
    if let Some(ref v) = merged.user { params.push(format!("user={}", urlencoding::encode(v))); }

    let query_string = params.join("&");
    let redirect_url = format!("{}/callback/{}?{}", base_url, provider, query_string);

    CallbackResult::Redirect(redirect_url)
}

/// Handle OAuth provider callback (GET).
///
/// Matches TS `callbackOAuth` with full flow:
///
/// 1. Handle OAuth errors via redirect
/// 2. Validate state from verification table
/// 3. Parse state data (provider, callbackURL, link info)
/// 4. Exchange authorization code for tokens
/// 5. Handle account linking flow
/// 6. Find or create user + account
/// 7. Create session
/// 8. Redirect to callback URL
pub async fn handle_callback(
    ctx: Arc<AuthContext>,
    query: CallbackQuery,
) -> Result<CallbackResult, AdapterError> {
    let default_error_url = format!(
        "{}/error",
        ctx.base_url.as_deref().unwrap_or("")
    );

    // 1. Handle OAuth errors
    if let Some(ref error) = query.error {
        let error_url = build_error_redirect(
            &default_error_url,
            error,
            query.error_description.as_deref(),
        );
        return Ok(CallbackResult::ErrorRedirect(error_url));
    }

    // Validate required params
    let state = match query.state.as_deref() {
        Some(s) => s,
        None => {
            let url = build_error_redirect(&default_error_url, "state_not_found", None);
            return Ok(CallbackResult::ErrorRedirect(url));
        }
    };

    let code = match query.code.as_deref() {
        Some(c) => c.to_string(),
        None => {
            let url = build_error_redirect(&default_error_url, "no_code", None);
            return Ok(CallbackResult::ErrorRedirect(url));
        }
    };

    // 2. Validate state
    let verification = match ctx.adapter.find_verification(state).await? {
        Some(v) => v,
        None => {
            let url = build_error_redirect(&default_error_url, "invalid_state", None);
            return Ok(CallbackResult::ErrorRedirect(url));
        }
    };

    // Clean up verification
    ctx.adapter.delete_verification(state).await?;

    // Check expiration
    if let Some(expires_str) = verification["expiresAt"].as_str() {
        if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(expires_str) {
            if expires < chrono::Utc::now() {
                let url = build_error_redirect(&default_error_url, "state_expired", None);
                return Ok(CallbackResult::ErrorRedirect(url));
            }
        }
    }

    // 3. Parse state data
    let parsed_state = parse_state_data(&verification);
    let error_url = parsed_state.error_url.as_deref().unwrap_or(&default_error_url);

    let redirect_on_error = |error: &str| -> CallbackResult {
        CallbackResult::ErrorRedirect(build_error_redirect(error_url, error, None))
    };

    let callback_url = &parsed_state.callback_url;

    // 4. Token exchange — look up the provider and exchange the code for tokens
    let provider = &parsed_state.provider;

    let oauth_provider = match ctx.get_social_provider(provider) {
        Some(p) => p,
        None => {
            return Ok(redirect_on_error("provider_not_found"));
        }
    };

    // Build redirect URI for code exchange
    let redirect_uri = format!(
        "{}{}/callback/{}",
        ctx.base_url.as_deref().unwrap_or(""),
        ctx.base_path,
        provider,
    );

    let code_data = better_auth_oauth2::provider::CodeValidationData {
        code: code.clone(),
        redirect_uri,
        code_verifier: parsed_state.code_verifier.clone(),
        device_id: query.device_id.clone(),
    };

    let tokens = match oauth_provider.validate_authorization_code(&code_data).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            return Ok(redirect_on_error("token_exchange_failed"));
        }
        Err(e) => {
            tracing::error!("OAuth token exchange failed for provider '{}': {}", provider, e);
            return Ok(redirect_on_error("token_exchange_failed"));
        }
    };

    // Get user info from the provider
    let user_info_result = match oauth_provider.get_user_info(&tokens).await {
        Ok(Some(info)) => info,
        Ok(None) => {
            return Ok(redirect_on_error("user_info_failed"));
        }
        Err(e) => {
            tracing::error!("OAuth get_user_info failed for provider '{}': {}", provider, e);
            return Ok(redirect_on_error("user_info_failed"));
        }
    };

    let provider_user = &user_info_result.user;

    // 5. Handle account linking flow
    if let Some(ref link) = parsed_state.link {
        let existing_account = ctx
            .adapter
            .find_account_by_provider(provider, &provider_user.id)
            .await?;

        if let Some(existing) = existing_account {
            let existing_user_id = existing["userId"].as_str().unwrap_or_default();
            if existing_user_id != link.user_id {
                return Ok(redirect_on_error("account_already_linked_to_different_user"));
            }
            // Account already linked to this user — just redirect
        } else {
            // Create new linked account with real token data
            let now = chrono::Utc::now().to_rfc3339();
            let access_token_expires = tokens.access_token_expires_at.map(|dt| dt.to_rfc3339());
            let refresh_token_expires = tokens.refresh_token_expires_at.map(|dt| dt.to_rfc3339());
            let scope_str = if tokens.scopes.is_empty() { None } else { Some(tokens.scopes.join(",")) };

            let account_data = serde_json::json!({
                "id": uuid::Uuid::new_v4().to_string(),
                "userId": link.user_id,
                "accountId": provider_user.id,
                "providerId": provider,
                "accessToken": tokens.access_token,
                "refreshToken": tokens.refresh_token,
                "idToken": tokens.id_token,
                "accessTokenExpiresAt": access_token_expires,
                "refreshTokenExpiresAt": refresh_token_expires,
                "scope": scope_str,
                "createdAt": now,
                "updatedAt": now,
            });
            ctx.adapter.create_account(account_data).await?;
        }

        return Ok(CallbackResult::Redirect(callback_url.clone()));
    }

    // 6. Find or create user + account using handle_oauth_user_info
    let access_token_expires = tokens.access_token_expires_at.map(|dt| dt.to_rfc3339());
    let refresh_token_expires = tokens.refresh_token_expires_at.map(|dt| dt.to_rfc3339());
    let scope_str = if tokens.scopes.is_empty() { None } else { Some(tokens.scopes.join(",")) };

    let oauth_user_info = OAuthUserInfo {
        id: provider_user.id.clone(),
        email: provider_user.email.clone().unwrap_or_default(),
        name: provider_user.name.clone(),
        image: provider_user.image.clone(),
        email_verified: provider_user.email_verified,
    };

    let oauth_account = OAuthAccountInfo {
        provider_id: provider.clone(),
        account_id: provider_user.id.clone(),
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token.clone(),
        id_token: tokens.id_token.clone(),
        access_token_expires_at: access_token_expires,
        refresh_token_expires_at: refresh_token_expires,
        scope: scope_str,
    };

    let disable_sign_up = oauth_provider.disable_sign_up()
        || (oauth_provider.disable_implicit_sign_up() && !parsed_state.request_sign_up);

    let oauth_opts = HandleOAuthOptions {
        callback_url: Some(callback_url.clone()),
        disable_sign_up,
        override_user_info: oauth_provider.options().override_user_info_on_sign_in,
        is_trusted_provider: false,
    };

    let oauth_result = crate::oauth::link_account::handle_oauth_user_info(
        ctx.clone(),
        oauth_user_info,
        oauth_account,
        oauth_opts,
    )
    .await?;

    match oauth_result {
        OAuthUserResult::Success { is_register, .. } => {
            // 7. Redirect — use newUserURL for new registrations, callbackURL otherwise
            let redirect_url = if is_register {
                parsed_state.new_user_url.as_deref().unwrap_or(callback_url)
            } else {
                callback_url
            };
            Ok(CallbackResult::Redirect(redirect_url.to_string()))
        }
        OAuthUserResult::Error { error, .. } => {
            Ok(redirect_on_error(&error))
        }
    }
}
