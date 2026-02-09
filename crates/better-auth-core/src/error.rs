// Error codes matching BASE_ERROR_CODES from the TypeScript version exactly.
// See: packages/core/src/error/codes.ts

use std::fmt;

use serde::{Deserialize, Serialize};

/// All error codes defined in BASE_ERROR_CODES.
/// Each variant maps 1:1 to the TypeScript `BASE_ERROR_CODES` constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    UserNotFound,
    FailedToCreateUser,
    FailedToCreateSession,
    FailedToGetSession,
    FailedToUpdateUser,
    FailedToUnlinkAccount,
    InvalidEmailOrPassword,
    InvalidPassword,
    InvalidEmail,
    UserAlreadyExists,
    EmailNotVerified,
    PasswordTooShort,
    PasswordTooLong,
    ProviderNotFound,
    InvalidToken,
    IdTokenNotSupported,
    FailedToGetUserInfo,
    AccountNotFound,
    SessionExpired,
    SocialAccountAlreadyLinked,
    CouldNotRetrieveSession,
    CouldNotRefreshAccessToken,
    SessionNotFound,
    FailedToLinkAccount,
    Unauthorized,
    OauthAccountAlreadyLinked,
    ProviderAlreadyLinked,
    CredentialAccountNotFound,
    CallbackUrlRequired,
    InvalidCallbackUrl,
    InvalidRedirectUrl,
    InvalidOrigin,
    InvalidErrorCallbackUrl,
    InvalidNewUserCallbackUrl,
    MissingOrNullOrigin,
    CrossSiteNavigationLoginBlocked,
    CouldNotParseBody,
    EmailAndPasswordNotEnabled,
    SignupDisabled,
    RateLimitExceeded,
    InternalServerError,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::UserNotFound => "User not found",
            Self::FailedToCreateUser => "Failed to create user",
            Self::FailedToCreateSession => "Failed to create session",
            Self::FailedToGetSession => "Failed to get session",
            Self::FailedToUpdateUser => "Failed to update user",
            Self::FailedToUnlinkAccount => "Failed to unlink account",
            Self::InvalidEmailOrPassword => "Invalid email or password",
            Self::InvalidPassword => "Invalid password",
            Self::InvalidEmail => "Invalid email",
            Self::UserAlreadyExists => "User already exists",
            Self::EmailNotVerified => "Email not verified",
            Self::PasswordTooShort => "Password too short",
            Self::PasswordTooLong => "Password too long",
            Self::ProviderNotFound => "Provider not found",
            Self::InvalidToken => "Invalid token",
            Self::IdTokenNotSupported => "ID token not supported",
            Self::FailedToGetUserInfo => "Failed to get user info",
            Self::AccountNotFound => "Account not found",
            Self::SessionExpired => "Session expired",
            Self::SocialAccountAlreadyLinked => "Social account already linked",
            Self::CouldNotRetrieveSession => "Could not retrieve session",
            Self::CouldNotRefreshAccessToken => "Could not refresh access token",
            Self::SessionNotFound => "Session not found",
            Self::FailedToLinkAccount => "Failed to link account",
            Self::Unauthorized => "Unauthorized",
            Self::OauthAccountAlreadyLinked => "OAuth account already linked",
            Self::ProviderAlreadyLinked => "Provider already linked",
            Self::CredentialAccountNotFound => "Credential account not found",
            Self::CallbackUrlRequired => "Callback URL is required",
            Self::InvalidCallbackUrl => "Invalid callback URL",
            Self::InvalidRedirectUrl => "Invalid redirect URL",
            Self::InvalidOrigin => "Invalid origin",
            Self::InvalidErrorCallbackUrl => "Invalid error callback URL",
            Self::InvalidNewUserCallbackUrl => "Invalid new user callback URL",
            Self::MissingOrNullOrigin => "Missing or null origin",
            Self::CrossSiteNavigationLoginBlocked => "Cross-site navigation login blocked",
            Self::CouldNotParseBody => "Could not parse body",
            Self::EmailAndPasswordNotEnabled => "Email and password not enabled",
            Self::SignupDisabled => "Signup disabled",
            Self::RateLimitExceeded => "Rate limit exceeded",
            Self::InternalServerError => "Internal server error",
        };
        write!(f, "{msg}")
    }
}

/// HTTP status codes used by the API error system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpStatus {
    Ok = 200,
    MovedPermanently = 301,
    Found = 302,
    BadRequest = 400,
    Unauthorized = 401,
    Forbidden = 403,
    NotFound = 404,
    MethodNotAllowed = 405,
    Conflict = 409,
    UnprocessableEntity = 422,
    TooManyRequests = 429,
    InternalServerError = 500,
}

impl HttpStatus {
    pub fn status_code(&self) -> u16 {
        *self as u16
    }
}

impl fmt::Display for HttpStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.status_code())
    }
}

/// API error — corresponds to the TypeScript `APIError`.
/// Carries an HTTP status, an error code, and an optional human-readable message.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{status} {code}: {message}")]
pub struct ApiError {
    pub status: HttpStatus,
    pub code: ErrorCode,
    pub message: String,
}

impl ApiError {
    pub fn new(status: HttpStatus, code: ErrorCode) -> Self {
        Self {
            message: code.to_string(),
            status,
            code,
        }
    }

    pub fn with_message(status: HttpStatus, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    /// Convenience constructors matching `APIError.from(STATUS, CODE)`.
    pub fn bad_request(code: ErrorCode) -> Self {
        Self::new(HttpStatus::BadRequest, code)
    }

    pub fn unauthorized(code: ErrorCode) -> Self {
        Self::new(HttpStatus::Unauthorized, code)
    }

    pub fn forbidden(code: ErrorCode) -> Self {
        Self::new(HttpStatus::Forbidden, code)
    }

    pub fn not_found(code: ErrorCode) -> Self {
        Self::new(HttpStatus::NotFound, code)
    }

    pub fn internal(code: ErrorCode) -> Self {
        Self::new(HttpStatus::InternalServerError, code)
    }

    pub fn too_many_requests() -> Self {
        Self::new(HttpStatus::TooManyRequests, ErrorCode::RateLimitExceeded)
    }

    /// Build a JSON body for the error response.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "code": self.code,
            "message": self.message,
        })
    }
}

/// Internal (non-HTTP) error — corresponds to `BetterAuthError` in TypeScript.
/// Used for configuration errors, internal logic failures, etc.
#[derive(Debug, thiserror::Error)]
pub enum BetterAuthError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Plugin error: {0}")]
    Plugin(String),

    #[error("{0}")]
    Other(String),

    #[error(transparent)]
    Api(#[from] ApiError),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

/// Unified result type for better-auth operations.
pub type Result<T> = std::result::Result<T, BetterAuthError>;
