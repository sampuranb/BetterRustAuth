//! Client error types.
//!
//! Maps HTTP status codes to typed error variants, mirroring the structure
//! of the TS client's error handling in `@better-fetch/fetch`.

use std::fmt;

/// Errors that can occur when using the Better Auth client.
///
/// Each variant maps to a specific HTTP error status code, with structured
/// `code` and `message` fields extracted from the server's JSON error response.
///
/// ## TS Parity
/// - In TS, `BetterFetchError` carries `{ code, message, status }`.
/// - This Rust enum provides dedicated variants for each status, making
///   pattern matching ergonomic while preserving the same information.
#[derive(Debug, Clone)]
pub enum ClientError {
    /// Network-level error (DNS, connection refused, timeout, TLS).
    Network(String),

    /// 400 Bad Request — invalid input.
    BadRequest {
        code: String,
        message: String,
    },

    /// 401 Unauthorized — missing or invalid credentials.
    Unauthorized {
        code: String,
        message: String,
    },

    /// 403 Forbidden — insufficient permissions or CSRF failure.
    Forbidden {
        code: String,
        message: String,
    },

    /// 404 Not Found — endpoint or resource doesn't exist.
    NotFound {
        message: String,
    },

    /// 409 Conflict — resource already exists (e.g. duplicate email).
    Conflict {
        code: String,
        message: String,
    },

    /// 422 Unprocessable Entity — validation error.
    UnprocessableEntity {
        code: String,
        message: String,
    },

    /// 429 Too Many Requests — rate limited.
    TooManyRequests {
        message: String,
    },

    /// 5xx Server Error.
    Server {
        status: u16,
        message: String,
    },

    /// Failed to deserialize the response body.
    Deserialization(String),
}

impl ClientError {
    /// Create a network error from a reqwest error.
    pub fn network(err: reqwest::Error) -> Self {
        Self::Network(err.to_string())
    }

    /// Get the error code, if available.
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::BadRequest { code, .. } => Some(code),
            Self::Unauthorized { code, .. } => Some(code),
            Self::Forbidden { code, .. } => Some(code),
            Self::Conflict { code, .. } => Some(code),
            Self::UnprocessableEntity { code, .. } => Some(code),
            _ => None,
        }
    }

    /// Get the error message.
    pub fn message(&self) -> &str {
        match self {
            Self::Network(msg) => msg,
            Self::BadRequest { message, .. } => message,
            Self::Unauthorized { message, .. } => message,
            Self::Forbidden { message, .. } => message,
            Self::NotFound { message } => message,
            Self::Conflict { message, .. } => message,
            Self::UnprocessableEntity { message, .. } => message,
            Self::TooManyRequests { message } => message,
            Self::Server { message, .. } => message,
            Self::Deserialization(msg) => msg,
        }
    }

    /// Get the HTTP status code, if applicable.
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::BadRequest { .. } => Some(400),
            Self::Unauthorized { .. } => Some(401),
            Self::Forbidden { .. } => Some(403),
            Self::NotFound { .. } => Some(404),
            Self::Conflict { .. } => Some(409),
            Self::UnprocessableEntity { .. } => Some(422),
            Self::TooManyRequests { .. } => Some(429),
            Self::Server { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// Returns `true` if this is an authentication error (401).
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, Self::Unauthorized { .. })
    }

    /// Returns `true` if this is a network-level error.
    pub fn is_network(&self) -> bool {
        matches!(self, Self::Network(_))
    }

    /// Returns `true` if this is a rate-limit error (429).
    pub fn is_rate_limited(&self) -> bool {
        matches!(self, Self::TooManyRequests { .. })
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(msg) => write!(f, "Network error: {}", msg),
            Self::BadRequest { code, message } => {
                write!(f, "Bad Request [{}]: {}", code, message)
            }
            Self::Unauthorized { code, message } => {
                write!(f, "Unauthorized [{}]: {}", code, message)
            }
            Self::Forbidden { code, message } => {
                write!(f, "Forbidden [{}]: {}", code, message)
            }
            Self::NotFound { message } => write!(f, "Not Found: {}", message),
            Self::Conflict { code, message } => {
                write!(f, "Conflict [{}]: {}", code, message)
            }
            Self::UnprocessableEntity { code, message } => {
                write!(f, "Unprocessable Entity [{}]: {}", code, message)
            }
            Self::TooManyRequests { message } => {
                write!(f, "Too Many Requests: {}", message)
            }
            Self::Server { status, message } => {
                write!(f, "Server Error ({}): {}", status, message)
            }
            Self::Deserialization(msg) => write!(f, "Deserialization error: {}", msg),
        }
    }
}

impl std::error::Error for ClientError {}
