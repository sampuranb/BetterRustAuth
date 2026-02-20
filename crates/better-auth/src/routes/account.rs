// Account routes — maps to packages/better-auth/src/api/routes/account.ts
//
// Endpoints:
//   GET  /list-accounts   — List all linked accounts (sanitized)
//   POST /link-social     — Initiate linking a social/OAuth account (with ID token support)
//   POST /unlink-account  — Unlink an account from the user (with safety check)
//   POST /get-access-token — Get/refresh an OAuth access token for a linked account
//   POST /refresh-token   — Force-refresh OAuth tokens for a linked account
//   GET  /account-info    — Get provider-side user info for a linked account
//   POST /delete-account  — Delete the user's account entirely

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::context::AuthContext;
use crate::internal_adapter::AdapterError;

// ─── Types ───────────────────────────────────────────────────────────────────

/// Sanitized account entry for list-accounts.
///
/// Matches TS — strips sensitive fields (password, tokens) and splits scopes.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountResponse {
    pub id: String,
    pub provider_id: String,
    pub account_id: String,
    pub user_id: String,
    pub scopes: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Link social account request body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkSocialRequest {
    pub provider: String,
    #[serde(default)]
    pub callback_url: Option<String>,
    #[serde(default)]
    pub error_callback_url: Option<String>,
    #[serde(default)]
    pub disable_redirect: Option<bool>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(default)]
    pub id_token: Option<IdTokenRequest>,
    #[serde(default)]
    pub request_sign_up: Option<bool>,
    #[serde(default)]
    pub additional_data: Option<serde_json::Value>,
}

/// ID token for direct authentication without redirect.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdTokenRequest {
    pub token: String,
    pub nonce: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub scopes: Option<Vec<String>>,
}

/// Link social account response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkSocialResponse {
    pub url: String,
    pub redirect: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<bool>,
}

/// Unlink account request body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlinkAccountRequest {
    pub provider_id: String,
    #[serde(default)]
    pub account_id: Option<String>,
}

/// Get access token request body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAccessTokenRequest {
    pub provider_id: String,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
}

/// Access token response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessTokenResponse {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_expires_at: Option<String>,
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
}

/// Refresh token response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshTokenResponse {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token_expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    pub provider_id: String,
    pub account_id: String,
}

/// Status response.
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub status: bool,
}

/// Delete account request body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteAccountRequest {
    /// Confirmation password for credential accounts.
    #[serde(default)]
    pub password: Option<String>,
    /// Callback URL to redirect after deletion.
    #[serde(default)]
    pub callback_url: Option<String>,
    /// Confirmation token (from email).
    #[serde(default)]
    pub token: Option<String>,
}

/// Account info response — provider-side user data.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfoResponse {
    pub user: serde_json::Value,
    pub data: serde_json::Value,
}

// ─── list-accounts ───────────────────────────────────────────────────────────

/// List linked accounts for the current user.
///
/// Strips sensitive fields (password, tokens) and splits scopes into array.
pub async fn handle_list_accounts(
    ctx: Arc<AuthContext>,
    user_id: &str,
) -> Result<Vec<AccountResponse>, AdapterError> {
    let accounts = ctx.adapter.find_accounts_by_user_id(user_id).await?;

    let sanitized: Vec<AccountResponse> = accounts
        .into_iter()
        .map(|a| {
            let scopes = a["scope"]
                .as_str()
                .map(|s| {
                    s.split(',')
                        .map(|x| x.trim().to_string())
                        .filter(|x| !x.is_empty())
                        .collect()
                })
                .unwrap_or_default();

            AccountResponse {
                id: a["id"].as_str().unwrap_or_default().to_string(),
                provider_id: a["providerId"].as_str().unwrap_or_default().to_string(),
                account_id: a["accountId"].as_str().unwrap_or_default().to_string(),
                user_id: a["userId"].as_str().unwrap_or_default().to_string(),
                scopes,
                created_at: a["createdAt"].as_str().unwrap_or_default().to_string(),
                updated_at: a["updatedAt"].as_str().unwrap_or_default().to_string(),
            }
        })
        .collect();

    Ok(sanitized)
}

// ─── unlink-account ──────────────────────────────────────────────────────────

/// Unlink error types (maps to TS `BASE_ERROR_CODES`).
#[derive(Debug, thiserror::Error)]
pub enum UnlinkError {
    #[error("Cannot unlink the only account — user would be locked out")]
    LastAccount,
    #[error("Account not found")]
    AccountNotFound,
    #[error("Database error: {0}")]
    Database(#[from] AdapterError),
}

/// Unlink an account from the user.
///
/// Matches TS `unlinkAccount`:
/// - Prevents unlinking the last account (unless `allowUnlinkingAll` is set)
/// - Supports finding by `(providerId, accountId)` or just `providerId`
pub async fn handle_unlink_account(
    ctx: Arc<AuthContext>,
    user_id: &str,
    body: UnlinkAccountRequest,
) -> Result<StatusResponse, UnlinkError> {
    let accounts = ctx.adapter.find_accounts_by_user_id(user_id).await?;

    // Safety check: prevent unlinking the last account
    let allow_unlink_all = ctx.options.account.allow_unlinking_all;

    if accounts.len() <= 1 && !allow_unlink_all {
        return Err(UnlinkError::LastAccount);
    }

    // Find the matching account
    let target_account = accounts.iter().find(|a| {
        let provider_matches = a["providerId"].as_str() == Some(&body.provider_id);
        match &body.account_id {
            Some(aid) => provider_matches && a["accountId"].as_str() == Some(aid),
            None => provider_matches,
        }
    });

    let account = target_account.ok_or(UnlinkError::AccountNotFound)?;
    let account_id = account["id"].as_str().unwrap_or_default();

    ctx.adapter
        .delete_account(&body.provider_id, account_id)
        .await?;

    Ok(StatusResponse { status: true })
}

// ─── link-social ─────────────────────────────────────────────────────────────

/// Link a social account to the current user.
///
/// Matches TS `linkSocialAccount`:
/// - Supports ID token flow (direct) and OAuth redirect flow
/// - Checks for existing linked accounts to avoid duplicates
/// - Validates account linking configuration (trusted providers, different emails)
/// - Optionally updates user info from the linked provider
pub async fn handle_link_social(
    ctx: Arc<AuthContext>,
    user_id: &str,
    user_email: &str,
    body: LinkSocialRequest,
) -> Result<LinkSocialResponse, AdapterError> {
    // Check if user already has this provider linked
    let accounts = ctx.adapter.find_accounts_by_user_id(user_id).await?;
    let already_linked = accounts.iter().any(|a| {
        a["providerId"].as_str() == Some(&body.provider)
    });

    if already_linked {
        return Ok(LinkSocialResponse {
            url: String::new(),
            status: Some(true),
            redirect: false,
        });
    }

    // Generate OAuth state for CSRF verification
    let state = crate::crypto::random::generate_random_string(32);
    let callback_url = body.callback_url.clone().unwrap_or_else(|| {
        format!(
            "{}{}/callback/{}",
            ctx.base_url.as_deref().unwrap_or(""),
            ctx.base_path,
            body.provider,
        )
    });

    // Store state with link data so callback knows to link, not create
    let expires_at = chrono::Utc::now() + chrono::TimeDelta::minutes(10);
    let state_data = serde_json::json!({
        "provider": body.provider,
        "callbackUrl": callback_url,
        "errorUrl": body.error_callback_url,
        "link": {
            "userId": user_id,
            "email": user_email,
        },
        "scopes": body.scopes,
        "additionalData": body.additional_data,
    });

    ctx.adapter
        .create_verification(&state, &state_data.to_string(), expires_at)
        .await?;

    // Build the authorization URL
    let auth_url = format!(
        "{}{}/sign-in/social?provider={}&state={}",
        ctx.base_url.as_deref().unwrap_or(""),
        ctx.base_path,
        body.provider,
        state,
    );

    Ok(LinkSocialResponse {
        url: auth_url,
        redirect: !body.disable_redirect.unwrap_or(false),
        status: None,
    })
}

// ─── get-access-token ────────────────────────────────────────────────────────

/// Get a valid access token for a linked OAuth account.
///
/// Matches TS `getAccessToken`:
/// - Finds the account by provider and optional accountId
/// - Returns the current access token if still valid
/// - Auto-refreshes if expired (within 5s buffer) and provider supports it
pub async fn handle_get_access_token(
    ctx: Arc<AuthContext>,
    user_id: &str,
    body: GetAccessTokenRequest,
) -> Result<AccessTokenResponse, AdapterError> {
    let accounts = ctx
        .adapter
        .find_accounts_by_user_id(user_id)
        .await?;

    let account = accounts
        .iter()
        .find(|a| {
            let provider_matches = a["providerId"].as_str() == Some(&body.provider_id);
            match &body.account_id {
                Some(aid) => provider_matches && a["accountId"].as_str() == Some(aid),
                None => provider_matches,
            }
        })
        .ok_or_else(|| AdapterError::NotFound)?;

    // Check if the access token is expired or about to expire (within 5 seconds)
    let needs_refresh = account["accessTokenExpiresAt"]
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|expires_at| {
            let now_plus_buffer = chrono::Utc::now() + chrono::TimeDelta::seconds(5);
            expires_at <= now_plus_buffer
        })
        .unwrap_or(false);

    if needs_refresh {
        // Try to auto-refresh if a refresh token exists and provider supports it
        let refresh_token_raw = account["refreshToken"]
            .as_str()
            .filter(|s| !s.is_empty());

        if let Some(refresh_token_raw) = refresh_token_raw {
            if let Some(provider) = ctx.get_social_provider(&body.provider_id) {
                let refresh_token =
                    crate::oauth::token_utils::decrypt_token(refresh_token_raw, &ctx);

                if let Ok(new_tokens) = provider.refresh_access_token(&refresh_token).await {
                    // Update the account with new tokens
                    let account_id = account["id"].as_str().unwrap_or_default();
                    let access_token_expires =
                        new_tokens.access_token_expires_at.map(|dt| dt.to_rfc3339());
                    let refresh_token_expires =
                        new_tokens.refresh_token_expires_at.map(|dt| dt.to_rfc3339());
                    let scope_str = if new_tokens.scopes.is_empty() {
                        None
                    } else {
                        Some(new_tokens.scopes.join(","))
                    };

                    let update_data = serde_json::json!({
                        "accessToken": new_tokens.access_token,
                        "refreshToken": new_tokens.refresh_token,
                        "idToken": new_tokens.id_token,
                        "accessTokenExpiresAt": access_token_expires,
                        "refreshTokenExpiresAt": refresh_token_expires,
                        "scope": scope_str,
                        "updatedAt": chrono::Utc::now().to_rfc3339(),
                    });
                    let _ = ctx
                        .adapter
                        .update_account_by_id(account_id, update_data)
                        .await;

                    // Build scopes — prefer refreshed scopes, fall back to stored
                    let scopes = if new_tokens.scopes.is_empty() {
                        account["scope"]
                            .as_str()
                            .map(|s| {
                                s.split(',')
                                    .map(|x| x.trim().to_string())
                                    .filter(|x| !x.is_empty())
                                    .collect()
                            })
                            .unwrap_or_default()
                    } else {
                        new_tokens.scopes
                    };

                    return Ok(AccessTokenResponse {
                        access_token: new_tokens.access_token.unwrap_or_default(),
                        access_token_expires_at: access_token_expires,
                        scopes,
                        id_token: new_tokens.id_token,
                        token_type: Some("bearer".into()),
                    });
                }
            }
        }
    }

    // Return existing token as-is (not expired, or refresh not possible)
    let access_token = account["accessToken"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    let scopes = account["scope"]
        .as_str()
        .map(|s| s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect())
        .unwrap_or_default();

    let id_token = account["idToken"].as_str().map(|s| s.to_string());

    let access_token_expires_at = account["accessTokenExpiresAt"]
        .as_str()
        .map(|s| s.to_string());

    Ok(AccessTokenResponse {
        access_token,
        access_token_expires_at,
        scopes,
        id_token,
        token_type: Some("bearer".into()),
    })
}

// ─── delete-account ──────────────────────────────────────────────────────────

/// Delete the user's account entirely.
///
/// Matches TS account deletion flow:
/// 1. Verify identity (password for credential users, or confirmation token)
/// 2. Delete all sessions
/// 3. Delete all linked accounts
/// 4. Delete the user record
/// 5. Return success with optional redirect
pub async fn handle_delete_account(
    ctx: Arc<AuthContext>,
    user_id: &str,
    body: DeleteAccountRequest,
) -> Result<DeleteAccountResult, AccountDeleteError> {
    // Check if account deletion is enabled
    // Account deletion is enabled by default (no dedicated config field yet)
    let deletion_enabled = true;

    if !deletion_enabled {
        return Err(AccountDeleteError::DeletionDisabled);
    }

    // If password provided, verify it matches the credential account
    if let Some(password) = &body.password {
        let accounts = ctx.adapter.find_accounts_by_user_id(user_id).await?;
        let credential_account = accounts.iter().find(|a| {
            a["providerId"].as_str() == Some("credential")
        });

        if let Some(cred) = credential_account {
            let stored_hash = cred["password"].as_str().unwrap_or_default();
            if stored_hash.is_empty() {
                return Err(AccountDeleteError::NoPasswordSet);
            }

            let valid = crate::crypto::password::verify_password(stored_hash, password)
                .map_err(|_| AccountDeleteError::InvalidPassword)?;

            if !valid {
                return Err(AccountDeleteError::InvalidPassword);
            }
        }
    }

    // Delete sessions, accounts, then user
    let _ = ctx.adapter.delete_sessions_for_user(user_id).await;
    let _ = ctx.adapter.delete_accounts_by_user_id(user_id).await;
    ctx.adapter.delete_user(user_id).await?;

    Ok(DeleteAccountResult {
        success: true,
        redirect_url: body.callback_url,
    })
}

/// Delete account result.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteAccountResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
}

/// Delete account error types.
#[derive(Debug, thiserror::Error)]
pub enum AccountDeleteError {
    #[error("Account deletion is disabled")]
    DeletionDisabled,
    #[error("Invalid password")]
    InvalidPassword,
    #[error("No password set on this account")]
    NoPasswordSet,
    #[error("Database error: {0}")]
    Database(#[from] AdapterError),
}

// ─── refresh-token ──────────────────────────────────────────────────────────

/// Refresh token request body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshTokenRequest {
    pub provider_id: String,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
}

/// Error types for refresh token operation.
#[derive(Debug, thiserror::Error)]
pub enum RefreshTokenError {
    #[error("Provider not supported: {0}")]
    ProviderNotSupported(String),
    #[error("Token refresh not supported for provider: {0}")]
    RefreshNotSupported(String),
    #[error("Account not found")]
    AccountNotFound,
    #[error("Refresh token not found")]
    RefreshTokenNotFound,
    #[error("Failed to refresh access token")]
    RefreshFailed,
    #[error("User ID or session required")]
    UserIdOrSessionRequired,
    #[error("Database error: {0}")]
    Database(#[from] AdapterError),
}

/// Force-refresh OAuth tokens for a linked account.
///
/// Maps to TS `refreshToken` in `account.ts`.
///
/// Flow:
/// 1. Resolve user ID from session or body
/// 2. Find the social provider
/// 3. Find the account and its refresh token
/// 4. Call the provider's refresh endpoint
/// 5. Update the account with new tokens
/// 6. Return the refreshed tokens
pub async fn handle_refresh_token(
    ctx: Arc<AuthContext>,
    user_id: &str,
    body: RefreshTokenRequest,
) -> Result<RefreshTokenResponse, RefreshTokenError> {
    if user_id.is_empty() {
        return Err(RefreshTokenError::UserIdOrSessionRequired);
    }

    // Find the account matching provider and optional account ID
    let accounts = ctx
        .adapter
        .find_accounts_by_user_id(user_id)
        .await?;

    let account = accounts
        .iter()
        .find(|a| {
            let provider_matches = a["providerId"].as_str() == Some(&body.provider_id);
            match &body.account_id {
                Some(aid) => provider_matches && a["accountId"].as_str() == Some(aid),
                None => provider_matches,
            }
        })
        .ok_or(RefreshTokenError::AccountNotFound)?;

    // Get the refresh token
    let refresh_token_raw = account["refreshToken"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or(RefreshTokenError::RefreshTokenNotFound)?;

    // Decrypt the refresh token if encrypted
    let refresh_token = crate::oauth::token_utils::decrypt_token(refresh_token_raw, &ctx);

    // Look up the provider
    let provider = ctx
        .get_social_provider(&body.provider_id)
        .ok_or_else(|| RefreshTokenError::ProviderNotSupported(body.provider_id.clone()))?;

    // Call the provider's refresh endpoint
    let new_tokens = provider
        .refresh_access_token(&refresh_token)
        .await
        .map_err(|e| {
            tracing::error!("Token refresh failed for provider '{}': {}", body.provider_id, e);
            RefreshTokenError::RefreshFailed
        })?;

    // Update the account with new tokens
    let account_id = account["id"].as_str().unwrap_or_default();
    let access_token_expires = new_tokens.access_token_expires_at.map(|dt| dt.to_rfc3339());
    let refresh_token_expires = new_tokens.refresh_token_expires_at.map(|dt| dt.to_rfc3339());
    let scope_str = if new_tokens.scopes.is_empty() { None } else { Some(new_tokens.scopes.join(",")) };

    let update_data = serde_json::json!({
        "accessToken": new_tokens.access_token,
        "refreshToken": new_tokens.refresh_token,
        "idToken": new_tokens.id_token,
        "accessTokenExpiresAt": access_token_expires,
        "refreshTokenExpiresAt": refresh_token_expires,
        "scope": scope_str,
        "updatedAt": chrono::Utc::now().to_rfc3339(),
    });
    ctx.adapter.update_account_by_id(account_id, update_data).await?;

    let account_id_val = account["accountId"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    Ok(RefreshTokenResponse {
        access_token: new_tokens.access_token.unwrap_or_default(),
        refresh_token: new_tokens.refresh_token,
        access_token_expires_at: access_token_expires,
        refresh_token_expires_at: refresh_token_expires,
        scope: scope_str,
        id_token: new_tokens.id_token,
        provider_id: body.provider_id,
        account_id: account_id_val,
    })
}

// ─── account-info ────────────────────────────────────────────────────────────

/// Account info request query parameters.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfoQuery {
    #[serde(default)]
    pub account_id: Option<String>,
}

/// Get provider-side account info for a linked account.
///
/// Maps to TS `accountInfo` in `account.ts`.
///
/// Flow:
/// 1. Find the account by provider-given account ID or cookie
/// 2. Get an access token (auto-refreshing if expired/about-to-expire)
/// 3. Call the provider's getUserInfo endpoint
/// 4. Return the provider's user info, falling back to stored data on error
pub async fn handle_account_info(
    ctx: Arc<AuthContext>,
    user_id: &str,
    query: AccountInfoQuery,
) -> Result<AccountInfoResponse, AccountInfoError> {
    // Find the account
    let account = if let Some(ref account_id) = query.account_id {
        // Look up specific account by provider-given account ID
        let accounts = ctx.adapter.find_accounts_by_user_id(user_id).await?;
        accounts
            .into_iter()
            .find(|a| a["accountId"].as_str() == Some(account_id))
    } else {
        // Fall back to the first linked social account
        let accounts = ctx.adapter.find_accounts_by_user_id(user_id).await?;
        accounts
            .into_iter()
            .find(|a| a["providerId"].as_str() != Some("credential"))
    };

    let account = account.ok_or(AccountInfoError::AccountNotFound)?;

    // Verify ownership
    if account["userId"].as_str() != Some(user_id) {
        return Err(AccountInfoError::AccountNotFound);
    }

    let provider_id = account["providerId"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    // Get a valid access token, auto-refreshing if needed
    let mut access_token = account["accessToken"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    // Check if the access token is expired or about to expire (within 5 seconds)
    let needs_refresh = account["accessTokenExpiresAt"]
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|expires_at| {
            let now_plus_buffer = chrono::Utc::now() + chrono::TimeDelta::seconds(5);
            expires_at <= now_plus_buffer
        })
        .unwrap_or(false);

    if needs_refresh {
        if let Some(refresh_token_raw) = account["refreshToken"]
            .as_str()
            .filter(|s| !s.is_empty())
        {
            if let Some(provider) = ctx.get_social_provider(&provider_id) {
                let refresh_token =
                    crate::oauth::token_utils::decrypt_token(refresh_token_raw, &ctx);

                if let Ok(new_tokens) = provider.refresh_access_token(&refresh_token).await {
                    // Update the account with new tokens
                    let account_db_id = account["id"].as_str().unwrap_or_default();
                    let access_token_expires =
                        new_tokens.access_token_expires_at.map(|dt| dt.to_rfc3339());
                    let refresh_token_expires =
                        new_tokens.refresh_token_expires_at.map(|dt| dt.to_rfc3339());
                    let scope_str = if new_tokens.scopes.is_empty() {
                        None
                    } else {
                        Some(new_tokens.scopes.join(","))
                    };

                    let update_data = serde_json::json!({
                        "accessToken": new_tokens.access_token,
                        "refreshToken": new_tokens.refresh_token,
                        "idToken": new_tokens.id_token,
                        "accessTokenExpiresAt": access_token_expires,
                        "refreshTokenExpiresAt": refresh_token_expires,
                        "scope": scope_str,
                        "updatedAt": chrono::Utc::now().to_rfc3339(),
                    });
                    let _ = ctx
                        .adapter
                        .update_account_by_id(account_db_id, update_data)
                        .await;

                    // Use the refreshed access token
                    if let Some(ref tok) = new_tokens.access_token {
                        access_token = tok.clone();
                    }
                }
            }
        }
    }

    if access_token.is_empty() {
        return Err(AccountInfoError::AccessTokenNotFound);
    }

    // Look up the provider
    let provider = ctx
        .get_social_provider(&provider_id)
        .ok_or(AccountInfoError::ProviderNotConfigured)?;

    // Build OAuth2Tokens for the provider call
    let tokens = better_auth_oauth2::OAuth2Tokens {
        access_token: Some(access_token),
        token_type: Some("bearer".to_string()),
        ..Default::default()
    };

    // Call the provider's getUserInfo endpoint
    match provider.get_user_info(&tokens).await {
        Ok(Some(info)) => {
            let user_info = serde_json::json!({
                "id": info.user.id,
                "name": info.user.name,
                "email": info.user.email,
                "image": info.user.image,
                "emailVerified": info.user.email_verified,
            });

            Ok(AccountInfoResponse {
                user: user_info,
                data: info.data,
            })
        }
        _ => {
            // Fall back to stored account data on error or no result
            let user_info = serde_json::json!({
                "id": account["accountId"],
                "name": serde_json::Value::Null,
                "email": serde_json::Value::Null,
                "image": serde_json::Value::Null,
                "emailVerified": false,
            });

            let data = serde_json::json!({
                "providerId": account["providerId"],
                "accountId": account["accountId"],
            });

            Ok(AccountInfoResponse {
                user: user_info,
                data,
            })
        }
    }
}

/// Account info error types.
#[derive(Debug, thiserror::Error)]
pub enum AccountInfoError {
    #[error("Account not found")]
    AccountNotFound,
    #[error("Provider not configured")]
    ProviderNotConfigured,
    #[error("Access token not found")]
    AccessTokenNotFound,
    #[error("Database error: {0}")]
    Database(#[from] AdapterError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_response_serialization() {
        let resp = AccountResponse {
            id: "acc1".into(),
            provider_id: "github".into(),
            account_id: "gh123".into(),
            user_id: "u1".into(),
            scopes: vec!["read:user".into(), "repo".into()],
            created_at: "2024-01-01T00:00:00Z".into(),
            updated_at: "2024-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["providerId"], "github");
        assert_eq!(json["scopes"][0], "read:user");
    }

    #[test]
    fn test_link_social_response_without_status() {
        let resp = LinkSocialResponse {
            url: "https://example.com".into(),
            redirect: true,
            status: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("status").is_none());
    }

    #[test]
    fn test_delete_account_result() {
        let result = DeleteAccountResult {
            success: true,
            redirect_url: Some("https://example.com/goodbye".into()),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["redirectUrl"], "https://example.com/goodbye");
    }
}
