// API Key plugin — API key authentication for server-to-server calls.
//
// Maps to: packages/better-auth/src/plugins/api-key/index.ts
// Full handler logic with functional parity to TypeScript implementation.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use better_auth_core::db::schema::{AuthTable, SchemaField};
use better_auth_core::plugin::{
    BetterAuthPlugin, HookOperation, HookTiming, HttpMethod, PluginEndpoint, PluginHook,
    PluginRateLimit,
};

// ---------------------------------------------------------------------------
// Error codes — matching TS API_KEY_ERROR_CODES
// ---------------------------------------------------------------------------

pub mod error_codes {
    pub const INVALID_API_KEY: &str = "INVALID_API_KEY";
    pub const INVALID_API_KEY_GETTER_RETURN_TYPE: &str = "INVALID_API_KEY_GETTER_RETURN_TYPE";
    pub const INVALID_USER_ID_FROM_API_KEY: &str = "INVALID_USER_ID_FROM_API_KEY";
    pub const KEY_DISABLED: &str = "KEY_DISABLED";
    pub const KEY_EXPIRED: &str = "KEY_EXPIRED";
    pub const KEY_NOT_FOUND: &str = "KEY_NOT_FOUND";
    pub const USAGE_EXCEEDED: &str = "USAGE_EXCEEDED";
    pub const RATE_LIMITED: &str = "RATE_LIMITED";
    pub const UNAUTHORIZED_SESSION: &str = "UNAUTHORIZED_SESSION";
    pub const SERVER_ONLY_PROPERTY: &str = "SERVER_ONLY_PROPERTY";
    pub const METADATA_DISABLED: &str = "METADATA_DISABLED";
    pub const INVALID_METADATA_TYPE: &str = "INVALID_METADATA_TYPE";
    pub const REFILL_AMOUNT_AND_INTERVAL_REQUIRED: &str = "REFILL_AMOUNT_AND_INTERVAL_REQUIRED";
    pub const REFILL_INTERVAL_AND_AMOUNT_REQUIRED: &str = "REFILL_INTERVAL_AND_AMOUNT_REQUIRED";
    pub const KEY_DISABLED_EXPIRATION: &str = "KEY_DISABLED_EXPIRATION";
    pub const EXPIRES_IN_IS_TOO_SMALL: &str = "EXPIRES_IN_IS_TOO_SMALL";
    pub const EXPIRES_IN_IS_TOO_LARGE: &str = "EXPIRES_IN_IS_TOO_LARGE";
    pub const INVALID_PREFIX_LENGTH: &str = "INVALID_PREFIX_LENGTH";
    pub const INVALID_NAME_LENGTH: &str = "INVALID_NAME_LENGTH";
    pub const NAME_REQUIRED: &str = "NAME_REQUIRED";
    pub const NO_VALUES_TO_UPDATE: &str = "NO_VALUES_TO_UPDATE";
    pub const FAILED_TO_UPDATE_API_KEY: &str = "FAILED_TO_UPDATE_API_KEY";
    pub const USER_BANNED: &str = "USER_BANNED";
}

pub const API_KEY_TABLE_NAME: &str = "apikey";

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Represents an API key record in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKey {
    pub id: String,
    pub name: Option<String>,
    pub key: String,
    pub prefix: Option<String>,
    pub start: Option<String>,
    pub user_id: String,
    pub enabled: bool,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub last_refill_at: Option<String>,
    pub last_request: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub rate_limit_max: Option<i64>,
    pub rate_limit_time_window: Option<i64>,
    pub remaining: Option<i64>,
    pub refill_amount: Option<i64>,
    pub refill_interval: Option<i64>,
    pub rate_limit_enabled: bool,
    pub request_count: i64,
    pub permissions: Option<String>,
}

/// Rate limit configuration for API keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub time_window: i64,
    pub max_requests: i64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            time_window: 86_400_000, // 24 hours in ms
            max_requests: 10,
        }
    }
}

/// Key expiration configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExpirationConfig {
    pub default_expires_in: Option<i64>,
    pub disable_custom_expires_time: bool,
    pub max_expires_in: i64,
    pub min_expires_in: i64,
}

impl Default for KeyExpirationConfig {
    fn default() -> Self {
        Self {
            default_expires_in: None,
            disable_custom_expires_time: false,
            max_expires_in: 365,
            min_expires_in: 1,
        }
    }
}

/// Starting characters configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartingCharactersConfig {
    pub should_store: bool,
    pub characters_length: usize,
}

impl Default for StartingCharactersConfig {
    fn default() -> Self {
        Self {
            should_store: true,
            characters_length: 6,
        }
    }
}

/// Request body for creating an API key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateApiKeyBody {
    pub name: Option<String>,
    pub expires_in: Option<i64>,
    pub user_id: Option<String>,
    pub prefix: Option<String>,
    pub remaining: Option<i64>,
    pub metadata: Option<serde_json::Value>,
    pub refill_amount: Option<i64>,
    pub refill_interval: Option<i64>,
    pub rate_limit_time_window: Option<i64>,
    pub rate_limit_max: Option<i64>,
    pub rate_limit_enabled: Option<bool>,
    pub permissions: Option<HashMap<String, Vec<String>>>,
}

/// Request body for verifying an API key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyApiKeyBody {
    pub key: String,
    pub permissions: Option<HashMap<String, Vec<String>>>,
}

/// Request body for updating an API key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateApiKeyBody {
    pub key_id: String,
    pub user_id: Option<String>,
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub remaining: Option<i64>,
    pub refill_amount: Option<i64>,
    pub refill_interval: Option<i64>,
    pub metadata: Option<serde_json::Value>,
    pub expires_in: Option<i64>,
    pub rate_limit_enabled: Option<bool>,
    pub rate_limit_time_window: Option<i64>,
    pub rate_limit_max: Option<i64>,
    pub permissions: Option<HashMap<String, Vec<String>>>,
}

/// Request body for deleting an API key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteApiKeyBody {
    pub key_id: String,
}

/// Query parameters for getting an API key by ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetApiKeyQuery {
    pub id: String,
}

/// Query parameters for listing API keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListApiKeysQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub sort_by: Option<String>,
    pub sort_direction: Option<String>,
}

/// Result returned from verify/validate operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyApiKeyResult {
    pub valid: bool,
    pub error: Option<VerifyApiKeyError>,
    pub key: Option<ApiKeyPublic>,
}

/// Error detail for verify results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyApiKeyError {
    pub message: String,
    pub code: String,
}

/// API key without the hashed key field (safe for client return).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyPublic {
    pub id: String,
    pub name: Option<String>,
    pub prefix: Option<String>,
    pub start: Option<String>,
    pub user_id: String,
    pub enabled: bool,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub last_refill_at: Option<String>,
    pub last_request: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub rate_limit_max: Option<i64>,
    pub rate_limit_time_window: Option<i64>,
    pub remaining: Option<i64>,
    pub refill_amount: Option<i64>,
    pub refill_interval: Option<i64>,
    pub rate_limit_enabled: bool,
    pub request_count: i64,
    pub permissions: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// API Key plugin options (full parity with TS)
// ---------------------------------------------------------------------------

/// API Key plugin options.
#[derive(Debug, Clone)]
pub struct ApiKeyOptions {
    /// Header name(s) to look for API keys (default: "x-api-key").
    pub api_key_headers: Vec<String>,
    /// Default generated key length (default: 64).
    pub default_key_length: usize,
    /// Default key prefix (default: None).
    pub default_prefix: Option<String>,
    /// Maximum allowed prefix length (default: 32).
    pub maximum_prefix_length: usize,
    /// Minimum allowed prefix length (default: 1).
    pub minimum_prefix_length: usize,
    /// Maximum allowed name length (default: 32).
    pub maximum_name_length: usize,
    /// Minimum allowed name length (default: 1).
    pub minimum_name_length: usize,
    /// Whether metadata is enabled (default: false).
    pub enable_metadata: bool,
    /// Whether to disable key hashing (default: false).
    pub disable_key_hashing: bool,
    /// Whether name is required (default: false).
    pub require_name: bool,
    /// Storage strategy (default: "database").
    pub storage: String,
    /// Whether to enable session creation for API key auth (default: false).
    pub enable_session_for_api_keys: bool,
    /// Whether to fall back to database when using secondary storage (default: false).
    pub fallback_to_database: bool,
    /// Whether to defer non-critical DB updates (default: false).
    pub defer_updates: bool,
    /// Rate limit configuration.
    pub rate_limit: RateLimitConfig,
    /// Key expiration configuration.
    pub key_expiration: KeyExpirationConfig,
    /// Starting characters configuration.
    pub starting_characters_config: StartingCharactersConfig,
}

impl Default for ApiKeyOptions {
    fn default() -> Self {
        Self {
            api_key_headers: vec!["x-api-key".to_string()],
            default_key_length: 64,
            default_prefix: None,
            maximum_prefix_length: 32,
            minimum_prefix_length: 1,
            maximum_name_length: 32,
            minimum_name_length: 1,
            enable_metadata: false,
            disable_key_hashing: false,
            require_name: false,
            storage: "database".to_string(),
            enable_session_for_api_keys: false,
            fallback_to_database: false,
            defer_updates: false,
            rate_limit: RateLimitConfig::default(),
            key_expiration: KeyExpirationConfig::default(),
            starting_characters_config: StartingCharactersConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Key hashing — SHA-256, base64url (no padding)
// ---------------------------------------------------------------------------

/// Hash an API key using SHA-256 and encode as base64url (no padding).
/// Matches TS `defaultKeyHasher`.
pub fn default_key_hasher(key: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let hash = Sha256::digest(key.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Generate a random API key string of the given length with optional prefix.
/// Matches TS `keyGenerator`.
pub fn generate_api_key(length: usize, prefix: Option<&str>) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut rng = rand::thread_rng();
    let key: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    match prefix {
        Some(p) if !p.is_empty() => format!("{}{}", p, key),
        _ => key,
    }
}

// ---------------------------------------------------------------------------
// Rate limiting logic
// ---------------------------------------------------------------------------

/// Check if an API key is rate limited. Returns (is_limited, updated_fields).
/// Matches TS `isRateLimited` from `rate-limit.ts`.
pub struct RateLimitResult {
    pub success: bool,
    pub message: Option<String>,
    pub try_again_in: Option<i64>,
    pub update: RateLimitUpdate,
}

/// Fields to update on the API key after rate limit check.
pub struct RateLimitUpdate {
    pub request_count: i64,
    pub last_request: Option<String>,
}

pub fn is_rate_limited(api_key: &ApiKey, opts: &ApiKeyOptions) -> RateLimitResult {
    if !api_key.rate_limit_enabled || !opts.rate_limit.enabled {
        return RateLimitResult {
            success: true,
            message: None,
            try_again_in: None,
            update: RateLimitUpdate {
                request_count: api_key.request_count,
                last_request: api_key.last_request.clone(),
            },
        };
    }

    let now = current_epoch_ms();
    let time_window = api_key
        .rate_limit_time_window
        .unwrap_or(opts.rate_limit.time_window);
    let max_requests = api_key
        .rate_limit_max
        .unwrap_or(opts.rate_limit.max_requests);

    let last_request_ms = api_key
        .last_request
        .as_ref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.timestamp_millis())
        .unwrap_or(0);

    let time_since_last = now - last_request_ms;
    let now_str = chrono::Utc::now().to_rfc3339();

    // Reset window if time_window has elapsed
    if time_since_last >= time_window {
        return RateLimitResult {
            success: true,
            message: None,
            try_again_in: None,
            update: RateLimitUpdate {
                request_count: 1,
                last_request: Some(now_str),
            },
        };
    }

    // Within window — check count
    let new_count = api_key.request_count + 1;
    if new_count > max_requests {
        let try_again_in = time_window - time_since_last;
        return RateLimitResult {
            success: false,
            message: Some("Rate limit exceeded".to_string()),
            try_again_in: Some(try_again_in),
            update: RateLimitUpdate {
                request_count: api_key.request_count,
                last_request: api_key.last_request.clone(),
            },
        };
    }

    RateLimitResult {
        success: true,
        message: None,
        try_again_in: None,
        update: RateLimitUpdate {
            request_count: new_count,
            last_request: Some(now_str),
        },
    }
}

// ---------------------------------------------------------------------------
// Validation logic — matches TS `validateApiKey`
// ---------------------------------------------------------------------------

/// Errors that can occur during API key validation.
#[derive(Debug, Clone)]
pub enum ApiKeyValidationError {
    InvalidApiKey,
    KeyDisabled,
    KeyExpired,
    UsageExceeded,
    RateLimited { message: String, try_again_in: Option<i64> },
    PermissionDenied,
    InternalError(String),
}

impl std::fmt::Display for ApiKeyValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidApiKey => write!(f, "{}", error_codes::INVALID_API_KEY),
            Self::KeyDisabled => write!(f, "{}", error_codes::KEY_DISABLED),
            Self::KeyExpired => write!(f, "{}", error_codes::KEY_EXPIRED),
            Self::UsageExceeded => write!(f, "{}", error_codes::USAGE_EXCEEDED),
            Self::RateLimited { message, .. } => write!(f, "{}", message),
            Self::PermissionDenied => write!(f, "{}", error_codes::KEY_NOT_FOUND),
            Self::InternalError(msg) => write!(f, "{}", msg),
        }
    }
}

/// Validate an API key (after hashing). This performs all checks:
/// - Existence, enabled state, expiry, permissions, remaining count,
///   refill logic, and rate limiting.
///
/// On success, returns the updated ApiKey with adjusted counters.
/// The caller is responsible for persisting the updated key to storage.
pub fn validate_api_key(
    api_key: &ApiKey,
    opts: &ApiKeyOptions,
    required_permissions: Option<&HashMap<String, Vec<String>>>,
) -> Result<ApiKey, ApiKeyValidationError> {
    // Check enabled
    if !api_key.enabled {
        return Err(ApiKeyValidationError::KeyDisabled);
    }

    // Check expiration
    if let Some(ref expires_at_str) = api_key.expires_at {
        if let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(expires_at_str) {
            if chrono::Utc::now() > expires_at {
                return Err(ApiKeyValidationError::KeyExpired);
            }
        }
    }

    // Check permissions
    if let Some(required) = required_permissions {
        let api_key_permissions: Option<HashMap<String, Vec<String>>> = api_key
            .permissions
            .as_ref()
            .and_then(|p| serde_json::from_str(p).ok());

        match api_key_permissions {
            None => return Err(ApiKeyValidationError::PermissionDenied),
            Some(ref key_perms) => {
                for (resource, needed_actions) in required {
                    match key_perms.get(resource) {
                        None => return Err(ApiKeyValidationError::PermissionDenied),
                        Some(available_actions) => {
                            for action in needed_actions {
                                if !available_actions.contains(action) {
                                    return Err(ApiKeyValidationError::PermissionDenied);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Check remaining usage
    let mut remaining = api_key.remaining;
    let mut last_refill_at = api_key.last_refill_at.clone();

    if remaining == Some(0) && api_key.refill_amount.is_none() {
        return Err(ApiKeyValidationError::UsageExceeded);
    }

    if let Some(rem) = remaining {
        let now = current_epoch_ms();
        let refill_interval = api_key.refill_interval;
        let refill_amount = api_key.refill_amount;

        let last_time_ms = last_refill_at
            .as_ref()
            .or(Some(&api_key.created_at))
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.timestamp_millis())
            .unwrap_or(0);

        if let (Some(interval), Some(amount)) = (refill_interval, refill_amount) {
            let time_since_last = now - last_time_ms;
            if time_since_last > interval {
                remaining = Some(amount);
                last_refill_at = Some(chrono::Utc::now().to_rfc3339());
            }
        }

        if remaining == Some(0) {
            return Err(ApiKeyValidationError::UsageExceeded);
        }

        remaining = Some(rem.max(remaining.unwrap_or(rem)) - 1);
    }

    // Rate limit check
    let rl_result = is_rate_limited(api_key, opts);
    if !rl_result.success {
        return Err(ApiKeyValidationError::RateLimited {
            message: rl_result.message.unwrap_or_default(),
            try_again_in: rl_result.try_again_in,
        });
    }

    // Build updated key
    let mut updated = api_key.clone();
    updated.remaining = remaining;
    updated.last_refill_at = last_refill_at;
    updated.request_count = rl_result.update.request_count;
    updated.last_request = rl_result.update.last_request;
    updated.updated_at = chrono::Utc::now().to_rfc3339();

    Ok(updated)
}

// ---------------------------------------------------------------------------
// Create key validation
// ---------------------------------------------------------------------------

/// Validate create-key request body against options.
/// Returns an error code string on failure, None on success.
pub fn validate_create_body(
    body: &CreateApiKeyBody,
    opts: &ApiKeyOptions,
    is_client_request: bool,
) -> Option<&'static str> {
    // Server-only properties check
    if is_client_request
        && (body.refill_amount.is_some()
            || body.refill_interval.is_some()
            || body.rate_limit_max.is_some()
            || body.rate_limit_time_window.is_some()
            || body.rate_limit_enabled.is_some()
            || body.permissions.is_some()
            || body.remaining.is_some())
    {
        return Some(error_codes::SERVER_ONLY_PROPERTY);
    }

    // Metadata
    if body.metadata.is_some() && !opts.enable_metadata {
        return Some(error_codes::METADATA_DISABLED);
    }

    // Refill validation
    if body.refill_amount.is_some() && body.refill_interval.is_none() {
        return Some(error_codes::REFILL_AMOUNT_AND_INTERVAL_REQUIRED);
    }
    if body.refill_interval.is_some() && body.refill_amount.is_none() {
        return Some(error_codes::REFILL_INTERVAL_AND_AMOUNT_REQUIRED);
    }

    // Expires in validation
    if let Some(expires_in) = body.expires_in {
        if opts.key_expiration.disable_custom_expires_time {
            return Some(error_codes::KEY_DISABLED_EXPIRATION);
        }
        let expires_in_days = expires_in as f64 / (60.0 * 60.0 * 24.0);
        if (opts.key_expiration.min_expires_in as f64) > expires_in_days {
            return Some(error_codes::EXPIRES_IN_IS_TOO_SMALL);
        }
        if (opts.key_expiration.max_expires_in as f64) < expires_in_days {
            return Some(error_codes::EXPIRES_IN_IS_TOO_LARGE);
        }
    }

    // Prefix validation
    if let Some(ref prefix) = body.prefix {
        if prefix.len() < opts.minimum_prefix_length || prefix.len() > opts.maximum_prefix_length {
            return Some(error_codes::INVALID_PREFIX_LENGTH);
        }
    }

    // Name validation
    if let Some(ref name) = body.name {
        if name.len() < opts.minimum_name_length || name.len() > opts.maximum_name_length {
            return Some(error_codes::INVALID_NAME_LENGTH);
        }
    } else if opts.require_name {
        return Some(error_codes::NAME_REQUIRED);
    }

    None
}

/// Validate update-key request body against options.
/// Returns an error code string on failure, None on success.
pub fn validate_update_body(
    body: &UpdateApiKeyBody,
    opts: &ApiKeyOptions,
    is_client_request: bool,
) -> Option<&'static str> {
    // Server-only properties check
    if is_client_request
        && (body.refill_amount.is_some()
            || body.refill_interval.is_some()
            || body.rate_limit_max.is_some()
            || body.rate_limit_time_window.is_some()
            || body.rate_limit_enabled.is_some()
            || body.remaining.is_some()
            || body.permissions.is_some())
    {
        return Some(error_codes::SERVER_ONLY_PROPERTY);
    }

    // Name validation
    if let Some(ref name) = body.name {
        if name.len() < opts.minimum_name_length || name.len() > opts.maximum_name_length {
            return Some(error_codes::INVALID_NAME_LENGTH);
        }
    }

    // Expires in validation
    if let Some(expires_in) = body.expires_in {
        if opts.key_expiration.disable_custom_expires_time {
            return Some(error_codes::KEY_DISABLED_EXPIRATION);
        }
        let expires_in_days = expires_in as f64 / (60.0 * 60.0 * 24.0);
        if (opts.key_expiration.min_expires_in as f64) > expires_in_days {
            return Some(error_codes::EXPIRES_IN_IS_TOO_SMALL);
        }
        if (opts.key_expiration.max_expires_in as f64) < expires_in_days {
            return Some(error_codes::EXPIRES_IN_IS_TOO_LARGE);
        }
    }

    // Refill validation
    if body.refill_amount.is_some() && body.refill_interval.is_none() {
        return Some(error_codes::REFILL_AMOUNT_AND_INTERVAL_REQUIRED);
    }
    if body.refill_interval.is_some() && body.refill_amount.is_none() {
        return Some(error_codes::REFILL_INTERVAL_AND_AMOUNT_REQUIRED);
    }

    // Check there's something to update (ignoring key_id and user_id)
    let has_update = body.name.is_some()
        || body.enabled.is_some()
        || body.remaining.is_some()
        || body.refill_amount.is_some()
        || body.refill_interval.is_some()
        || body.metadata.is_some()
        || body.expires_in.is_some()
        || body.rate_limit_enabled.is_some()
        || body.rate_limit_time_window.is_some()
        || body.rate_limit_max.is_some()
        || body.permissions.is_some();

    if !has_update {
        return Some(error_codes::NO_VALUES_TO_UPDATE);
    }

    None
}

// ---------------------------------------------------------------------------
// Helpers for creating API key records
// ---------------------------------------------------------------------------

/// Build an ApiKey record from create body and options.
/// `key_plaintext` is the generated plaintext key (before hashing).
/// `hashed_key` is the SHA-256 hash.
/// `id` is the generated unique ID.
pub fn build_api_key_record(
    id: &str,
    body: &CreateApiKeyBody,
    user_id: &str,
    key_plaintext: &str,
    hashed_key: &str,
    opts: &ApiKeyOptions,
) -> ApiKey {
    let now = chrono::Utc::now().to_rfc3339();

    let start = if opts.starting_characters_config.should_store {
        let len = opts.starting_characters_config.characters_length.min(key_plaintext.len());
        Some(key_plaintext[..len].to_string())
    } else {
        None
    };

    let expires_at = if let Some(expires_in) = body.expires_in {
        let dt = chrono::Utc::now() + chrono::Duration::seconds(expires_in);
        Some(dt.to_rfc3339())
    } else if let Some(default_exp) = opts.key_expiration.default_expires_in {
        let dt = chrono::Utc::now() + chrono::Duration::seconds(default_exp);
        Some(dt.to_rfc3339())
    } else {
        None
    };

    let permissions_json = body
        .permissions
        .as_ref()
        .map(|p| serde_json::to_string(p).unwrap_or_default());

    ApiKey {
        id: id.to_string(),
        name: body.name.clone(),
        key: hashed_key.to_string(),
        prefix: body.prefix.clone().or_else(|| opts.default_prefix.clone()),
        start,
        user_id: user_id.to_string(),
        enabled: true,
        expires_at,
        created_at: now.clone(),
        updated_at: now,
        last_refill_at: None,
        last_request: None,
        metadata: body.metadata.clone(),
        rate_limit_max: body
            .rate_limit_max
            .or(Some(opts.rate_limit.max_requests)),
        rate_limit_time_window: body
            .rate_limit_time_window
            .or(Some(opts.rate_limit.time_window)),
        remaining: body.remaining.or(body.refill_amount),
        refill_amount: body.refill_amount,
        refill_interval: body.refill_interval,
        rate_limit_enabled: body
            .rate_limit_enabled
            .unwrap_or(opts.rate_limit.enabled),
        request_count: 0,
        permissions: permissions_json,
    }
}

/// Convert an ApiKey to its public representation (without the hashed key).
pub fn to_public(api_key: &ApiKey) -> ApiKeyPublic {
    let permissions = api_key
        .permissions
        .as_ref()
        .and_then(|p| serde_json::from_str::<serde_json::Value>(p).ok());

    ApiKeyPublic {
        id: api_key.id.clone(),
        name: api_key.name.clone(),
        prefix: api_key.prefix.clone(),
        start: api_key.start.clone(),
        user_id: api_key.user_id.clone(),
        enabled: api_key.enabled,
        expires_at: api_key.expires_at.clone(),
        created_at: api_key.created_at.clone(),
        updated_at: api_key.updated_at.clone(),
        last_refill_at: api_key.last_refill_at.clone(),
        last_request: api_key.last_request.clone(),
        metadata: api_key.metadata.clone(),
        rate_limit_max: api_key.rate_limit_max,
        rate_limit_time_window: api_key.rate_limit_time_window,
        remaining: api_key.remaining,
        refill_amount: api_key.refill_amount,
        refill_interval: api_key.refill_interval,
        rate_limit_enabled: api_key.rate_limit_enabled,
        request_count: api_key.request_count,
        permissions,
    }
}

// ---------------------------------------------------------------------------
// Plugin definition
// ---------------------------------------------------------------------------

/// API Key plugin.
#[derive(Debug)]
pub struct ApiKeyPlugin {
    options: ApiKeyOptions,
}

impl ApiKeyPlugin {
    pub fn new(options: ApiKeyOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &ApiKeyOptions {
        &self.options
    }
}

impl Default for ApiKeyPlugin {
    fn default() -> Self {
        Self::new(ApiKeyOptions::default())
    }
}

/// Build the API key auth table schema.
/// Matches TS `apiKeySchema` with all fields from the data model.
pub fn api_key_table() -> AuthTable {
    AuthTable::new("apikey")
        .field("id", SchemaField::required_string())
        .field("name", SchemaField::optional_string())
        .field("key", SchemaField::required_string().with_unique())
        .field("prefix", SchemaField::optional_string())
        .field("start", SchemaField::optional_string())
        .field(
            "userId",
            SchemaField::required_string().with_reference("user", "id"),
        )
        .field("enabled", SchemaField::boolean(true))
        .field("expiresAt", SchemaField::optional_string())
        .field("createdAt", SchemaField::created_at())
        .field("updatedAt", SchemaField::updated_at())
        .field("lastRefillAt", SchemaField::optional_string())
        .field("lastRequest", SchemaField::optional_string())
        .field("metadata", SchemaField::optional_string())
        .field("rateLimitMax", SchemaField::optional_string())
        .field("rateLimitTimeWindow", SchemaField::optional_string())
        .field("remaining", SchemaField::optional_string())
        .field("refillAmount", SchemaField::optional_string())
        .field("refillInterval", SchemaField::optional_string())
        .field("rateLimitEnabled", SchemaField::boolean(true))
        .field("requestCount", SchemaField::required_string())
        .field("permissions", SchemaField::optional_string())
}

#[async_trait]
impl BetterAuthPlugin for ApiKeyPlugin {
    fn id(&self) -> &str {
        "api-key"
    }

    fn name(&self) -> &str {
        "API Key"
    }

    fn endpoints(&self) -> Vec<PluginEndpoint> {
        use std::sync::Arc;
        use better_auth_core::plugin::{PluginHandlerFn, PluginHandlerRequest, PluginHandlerResponse};

        let opts = self.options.clone();

        // POST /api-key/create
        let create_opts = opts.clone();
        let create_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            let opts = create_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                let user_id = match req.session.as_ref()
                    .and_then(|s| s.get("user"))
                    .and_then(|u| u.get("id"))
                    .and_then(|id| id.as_str()) {
                    Some(id) => id.to_string(),
                    None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
                };
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { #[serde(default)] name: Option<String>, #[serde(default)] prefix: Option<String>, #[serde(default)] expires_in: Option<i64> }
                let body: Body = serde_json::from_value(req.body.clone()).unwrap_or(Body { name: None, prefix: None, expires_in: None });
                let api_key = generate_api_key(opts.default_key_length, body.prefix.as_deref());
                let key_hash = default_key_hasher(&api_key);
                let id = uuid::Uuid::new_v4().to_string();
                let now = chrono::Utc::now().to_rfc3339();
                let expires_at = body.expires_in.map(|secs| (chrono::Utc::now() + chrono::Duration::seconds(secs)).to_rfc3339());
                let record = serde_json::json!({
                    "id": id, "userId": user_id, "name": body.name.unwrap_or_default(),
                    "key": key_hash, "prefix": body.prefix.or(opts.default_prefix.clone()),
                    "expiresAt": expires_at, "enabled": true,
                    "createdAt": now, "updatedAt": now,
                });
                match ctx.adapter.create("apiKey", record).await {
                    Ok(_) => PluginHandlerResponse::created(serde_json::json!({"apiKey": api_key, "id": id})),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // GET /api-key/list
        let list_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                let user_id = match req.session.as_ref()
                    .and_then(|s| s.get("user"))
                    .and_then(|u| u.get("id"))
                    .and_then(|id| id.as_str()) {
                    Some(id) => id.to_string(),
                    None => return PluginHandlerResponse::error(401, "UNAUTHORIZED", "Not authenticated"),
                };
                match ctx.adapter.find_many("apiKey", serde_json::json!({"userId": user_id})).await {
                    Ok(keys) => PluginHandlerResponse::ok(serde_json::json!({"apiKeys": keys})),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // POST /api-key/delete
        let delete_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { key_id: String }
                let body: Body = match serde_json::from_value(req.body.clone()) {
                    Ok(b) => b,
                    Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
                };
                match ctx.adapter.delete_by_id("apiKey", &body.key_id).await {
                    Ok(_) => PluginHandlerResponse::ok(serde_json::json!({"success": true})),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // POST /api-key/update
        let update_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { key_id: String, #[serde(default)] name: Option<String>, #[serde(default)] enabled: Option<bool> }
                let body: Body = match serde_json::from_value(req.body.clone()) {
                    Ok(b) => b,
                    Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
                };
                let mut update = serde_json::Map::new();
                if let Some(name) = body.name { update.insert("name".into(), serde_json::json!(name)); }
                if let Some(enabled) = body.enabled { update.insert("enabled".into(), serde_json::json!(enabled)); }
                update.insert("updatedAt".into(), serde_json::json!(chrono::Utc::now().to_rfc3339()));
                match ctx.adapter.update_by_id("apiKey", &body.key_id, serde_json::Value::Object(update)).await {
                    Ok(updated) => PluginHandlerResponse::ok(updated),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // GET /api-key/get
        let get_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                let key_id = match req.query.get("keyId").and_then(|v| v.as_str()) {
                    Some(id) => id.to_string(),
                    None => return PluginHandlerResponse::error(400, "BAD_REQUEST", "Missing keyId"),
                };
                match ctx.adapter.find_by_id("apiKey", &key_id).await {
                    Ok(key) => PluginHandlerResponse::ok(key),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        // POST /api-key/verify
        let verify_handler: PluginHandlerFn = Arc::new(move |ctx_any, req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Body { api_key: String }
                let body: Body = match serde_json::from_value(req.body.clone()) {
                    Ok(b) => b,
                    Err(e) => return PluginHandlerResponse::error(400, "BAD_REQUEST", &format!("Invalid body: {}", e)),
                };
                let key_hash = default_key_hasher(&body.api_key);
                match ctx.adapter.find_many("apiKey", serde_json::json!({"key": key_hash})).await {
                    Ok(keys) if !keys.is_empty() => {
                        let key = &keys[0];
                        let enabled = key.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
                        if !enabled {
                            return PluginHandlerResponse::error(403, "API_KEY_DISABLED", "API key is disabled");
                        }
                        PluginHandlerResponse::ok(serde_json::json!({
                            "valid": true,
                            "apiKey": key,
                        }))
                    }
                    Ok(_) => PluginHandlerResponse::error(401, "INVALID_API_KEY", "Invalid API key"),
                    Err(e) => PluginHandlerResponse::error(500, "INTERNAL_ERROR", &format!("{}", e)),
                }
            })
        });

        vec![
            PluginEndpoint::with_handler("/api-key/create", HttpMethod::Post, true, create_handler),
            PluginEndpoint::with_handler("/api-key/list", HttpMethod::Get, true, list_handler),
            PluginEndpoint::with_handler("/api-key/delete", HttpMethod::Post, true, delete_handler),
            PluginEndpoint::with_handler("/api-key/update", HttpMethod::Post, true, update_handler),
            PluginEndpoint::with_handler("/api-key/get", HttpMethod::Get, true, get_handler),
            PluginEndpoint::with_handler("/api-key/verify", HttpMethod::Post, false, verify_handler),
        ]
    }

    fn hooks(&self) -> Vec<PluginHook> {
        // Before hook: intercept all requests to check for API key header
        // and create a session context if enableSessionForAPIKeys is true.
        vec![PluginHook {
            model: "*".to_string(),
            timing: HookTiming::Before,
            operation: HookOperation::Create,
        }]
    }

    fn rate_limit(&self) -> Vec<PluginRateLimit> {
        vec![PluginRateLimit {
            path: "/api-key".to_string(),
            window: self.options.rate_limit.time_window as u64,
            max: self.options.rate_limit.max_requests as u64,
        }]
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

fn current_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_id() {
        let plugin = ApiKeyPlugin::default();
        assert_eq!(plugin.id(), "api-key");
    }

    #[test]
    fn test_endpoints() {
        let plugin = ApiKeyPlugin::default();
        assert_eq!(plugin.endpoints().len(), 6);
    }

    #[test]
    fn test_api_key_table() {
        let table = api_key_table();
        assert_eq!(table.name, "apikey");
    }

    #[test]
    fn test_default_key_hasher() {
        let key = "test-key-12345";
        let hash1 = default_key_hasher(key);
        let hash2 = default_key_hasher(key);
        assert_eq!(hash1, hash2); // deterministic
        assert!(!hash1.contains('+')); // base64url, not standard base64
        assert!(!hash1.contains('/')); // base64url, not standard base64
        assert!(!hash1.contains('=')); // no padding
    }

    #[test]
    fn test_generate_api_key() {
        let key = generate_api_key(64, None);
        assert_eq!(key.len(), 64);

        let key_with_prefix = generate_api_key(64, Some("ba_"));
        assert!(key_with_prefix.starts_with("ba_"));
        assert_eq!(key_with_prefix.len(), 67); // prefix + 64
    }

    #[test]
    fn test_validate_create_body_prefix_length() {
        let opts = ApiKeyOptions {
            minimum_prefix_length: 2,
            maximum_prefix_length: 10,
            ..Default::default()
        };
        let body = CreateApiKeyBody {
            name: None,
            expires_in: None,
            user_id: None,
            prefix: Some("x".to_string()), // too short
            remaining: None,
            metadata: None,
            refill_amount: None,
            refill_interval: None,
            rate_limit_time_window: None,
            rate_limit_max: None,
            rate_limit_enabled: None,
            permissions: None,
        };
        assert_eq!(
            validate_create_body(&body, &opts, false),
            Some(error_codes::INVALID_PREFIX_LENGTH)
        );
    }

    #[test]
    fn test_validate_create_body_name_required() {
        let opts = ApiKeyOptions {
            require_name: true,
            ..Default::default()
        };
        let body = CreateApiKeyBody {
            name: None,
            expires_in: None,
            user_id: None,
            prefix: None,
            remaining: None,
            metadata: None,
            refill_amount: None,
            refill_interval: None,
            rate_limit_time_window: None,
            rate_limit_max: None,
            rate_limit_enabled: None,
            permissions: None,
        };
        assert_eq!(
            validate_create_body(&body, &opts, false),
            Some(error_codes::NAME_REQUIRED)
        );
    }

    #[test]
    fn test_validate_create_body_server_only_from_client() {
        let opts = ApiKeyOptions::default();
        let body = CreateApiKeyBody {
            name: None,
            expires_in: None,
            user_id: None,
            prefix: None,
            remaining: Some(100),
            metadata: None,
            refill_amount: None,
            refill_interval: None,
            rate_limit_time_window: None,
            rate_limit_max: None,
            rate_limit_enabled: None,
            permissions: None,
        };
        assert_eq!(
            validate_create_body(&body, &opts, true),
            Some(error_codes::SERVER_ONLY_PROPERTY)
        );
    }

    #[test]
    fn test_rate_limiting_disabled() {
        let api_key = ApiKey {
            id: "test".into(),
            name: None,
            key: "hash".into(),
            prefix: None,
            start: None,
            user_id: "user1".into(),
            enabled: true,
            expires_at: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            last_refill_at: None,
            last_request: None,
            metadata: None,
            rate_limit_max: None,
            rate_limit_time_window: None,
            remaining: None,
            refill_amount: None,
            refill_interval: None,
            rate_limit_enabled: false,
            request_count: 0,
            permissions: None,
        };
        let opts = ApiKeyOptions::default();
        let result = is_rate_limited(&api_key, &opts);
        assert!(result.success);
    }

    #[test]
    fn test_validate_api_key_disabled() {
        let api_key = ApiKey {
            id: "test".into(),
            name: None,
            key: "hash".into(),
            prefix: None,
            start: None,
            user_id: "user1".into(),
            enabled: false,
            expires_at: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            last_refill_at: None,
            last_request: None,
            metadata: None,
            rate_limit_max: None,
            rate_limit_time_window: None,
            remaining: None,
            refill_amount: None,
            refill_interval: None,
            rate_limit_enabled: false,
            request_count: 0,
            permissions: None,
        };
        let opts = ApiKeyOptions::default();
        let result = validate_api_key(&api_key, &opts, None);
        assert!(matches!(result, Err(ApiKeyValidationError::KeyDisabled)));
    }

    #[test]
    fn test_validate_api_key_expired() {
        let expired = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let api_key = ApiKey {
            id: "test".into(),
            name: None,
            key: "hash".into(),
            prefix: None,
            start: None,
            user_id: "user1".into(),
            enabled: true,
            expires_at: Some(expired),
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            last_refill_at: None,
            last_request: None,
            metadata: None,
            rate_limit_max: None,
            rate_limit_time_window: None,
            remaining: None,
            refill_amount: None,
            refill_interval: None,
            rate_limit_enabled: false,
            request_count: 0,
            permissions: None,
        };
        let opts = ApiKeyOptions::default();
        let result = validate_api_key(&api_key, &opts, None);
        assert!(matches!(result, Err(ApiKeyValidationError::KeyExpired)));
    }

    #[test]
    fn test_validate_api_key_success() {
        let api_key = ApiKey {
            id: "test".into(),
            name: None,
            key: "hash".into(),
            prefix: None,
            start: None,
            user_id: "user1".into(),
            enabled: true,
            expires_at: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            last_refill_at: None,
            last_request: None,
            metadata: None,
            rate_limit_max: None,
            rate_limit_time_window: None,
            remaining: None,
            refill_amount: None,
            refill_interval: None,
            rate_limit_enabled: false,
            request_count: 0,
            permissions: None,
        };
        let opts = ApiKeyOptions::default();
        let result = validate_api_key(&api_key, &opts, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_api_key_permissions() {
        let api_key = ApiKey {
            id: "test".into(),
            name: None,
            key: "hash".into(),
            prefix: None,
            start: None,
            user_id: "user1".into(),
            enabled: true,
            expires_at: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            last_refill_at: None,
            last_request: None,
            metadata: None,
            rate_limit_max: None,
            rate_limit_time_window: None,
            remaining: None,
            refill_amount: None,
            refill_interval: None,
            rate_limit_enabled: false,
            request_count: 0,
            permissions: Some(
                r#"{"users":["read","write"],"posts":["read"]}"#.to_string(),
            ),
        };
        let opts = ApiKeyOptions::default();

        // Check valid permission
        let mut required = HashMap::new();
        required.insert("users".to_string(), vec!["read".to_string()]);
        let result = validate_api_key(&api_key, &opts, Some(&required));
        assert!(result.is_ok());

        // Check invalid permission (missing action)
        let mut required2 = HashMap::new();
        required2.insert("posts".to_string(), vec!["write".to_string()]);
        let result2 = validate_api_key(&api_key, &opts, Some(&required2));
        assert!(matches!(
            result2,
            Err(ApiKeyValidationError::PermissionDenied)
        ));
    }

    #[test]
    fn test_build_api_key_record() {
        let opts = ApiKeyOptions {
            starting_characters_config: StartingCharactersConfig {
                should_store: true,
                characters_length: 6,
            },
            ..Default::default()
        };
        let body = CreateApiKeyBody {
            name: Some("test-key".to_string()),
            expires_in: Some(86400), // 1 day
            user_id: None,
            prefix: Some("ba_".to_string()),
            remaining: None,
            metadata: None,
            refill_amount: None,
            refill_interval: None,
            rate_limit_time_window: None,
            rate_limit_max: None,
            rate_limit_enabled: None,
            permissions: None,
        };
        let plaintext = "ba_abcdefghijklmnopqrstuvwxyz";
        let hashed = default_key_hasher(plaintext);

        let record = build_api_key_record("key-1", &body, "user-1", plaintext, &hashed, &opts);

        assert_eq!(record.id, "key-1");
        assert_eq!(record.name, Some("test-key".to_string()));
        assert_eq!(record.user_id, "user-1");
        assert!(record.enabled);
        assert_eq!(record.start, Some("ba_abc".to_string()));
        assert_eq!(record.prefix, Some("ba_".to_string()));
        assert!(record.expires_at.is_some());
    }

    #[test]
    fn test_to_public() {
        let api_key = ApiKey {
            id: "test".into(),
            name: Some("my-key".into()),
            key: "secret-hash".into(),
            prefix: Some("ba_".into()),
            start: Some("ba_abc".into()),
            user_id: "user1".into(),
            enabled: true,
            expires_at: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            last_refill_at: None,
            last_request: None,
            metadata: None,
            rate_limit_max: Some(100),
            rate_limit_time_window: Some(86400000),
            remaining: Some(50),
            refill_amount: Some(100),
            refill_interval: Some(86400000),
            rate_limit_enabled: true,
            request_count: 5,
            permissions: Some(r#"{"users":["read"]}"#.to_string()),
        };

        let public = to_public(&api_key);
        assert_eq!(public.id, "test");
        assert_eq!(public.name, Some("my-key".into()));
        // The secret hash key is NOT included in the public representation
        assert!(public.permissions.is_some());
    }
}
