//! OAuth Provider error codes.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthProviderError {
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable,
    InvalidClient,
    InvalidGrant,
    UnsupportedGrantType,
    InvalidToken,
    InsufficientScope,
    ConsentRequired,
    LoginRequired,
    ClientNotFound,
    InvalidRedirectUri,
    InvalidCodeChallenge,
}

impl OAuthProviderError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::AccessDenied => "access_denied",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidToken => "invalid_token",
            Self::InsufficientScope => "insufficient_scope",
            Self::ConsentRequired => "consent_required",
            Self::LoginRequired => "login_required",
            Self::ClientNotFound => "client_not_found",
            Self::InvalidRedirectUri => "invalid_redirect_uri",
            Self::InvalidCodeChallenge => "invalid_code_challenge",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "The request is missing a required parameter",
            Self::UnauthorizedClient => "The client is not authorized",
            Self::AccessDenied => "The resource owner denied the request",
            Self::UnsupportedResponseType => "The response type is not supported",
            Self::InvalidScope => "The requested scope is invalid",
            Self::ServerError => "The server encountered an unexpected error",
            Self::TemporarilyUnavailable => "The server is temporarily unavailable",
            Self::InvalidClient => "Client authentication failed",
            Self::InvalidGrant => "The provided grant is invalid",
            Self::UnsupportedGrantType => "The grant type is not supported",
            Self::InvalidToken => "The access token is invalid",
            Self::InsufficientScope => "Insufficient scope for this request",
            Self::ConsentRequired => "User consent is required",
            Self::LoginRequired => "User authentication is required",
            Self::ClientNotFound => "The client was not found",
            Self::InvalidRedirectUri => "The redirect URI is invalid",
            Self::InvalidCodeChallenge => "The code challenge is invalid",
        }
    }
}

impl std::fmt::Display for OAuthProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.description())
    }
}

impl std::error::Error for OAuthProviderError {}
