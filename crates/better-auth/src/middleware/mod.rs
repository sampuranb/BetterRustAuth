// Middleware module — maps to packages/better-auth/src/api/middlewares/
//
// Origin/CSRF validation, rate limiting, and trusted origin matching.

pub mod origin_check;
pub mod rate_limiter;
pub mod trusted_origins;

use std::fmt;

/// Middleware error types.
#[derive(Debug, Clone)]
pub enum MiddlewareError {
    /// 403 Forbidden — origin/CSRF/callback validation failure.
    Forbidden {
        code: &'static str,
        message: String,
    },
    /// 429 Too Many Requests — rate limit exceeded.
    TooManyRequests {
        retry_after: u64,
        message: String,
    },
}

impl fmt::Display for MiddlewareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Forbidden { code, message } => {
                write!(f, "Forbidden ({}): {}", code, message)
            }
            Self::TooManyRequests {
                retry_after,
                message,
            } => {
                write!(f, "Too Many Requests (retry after {}s): {}", retry_after, message)
            }
        }
    }
}

impl std::error::Error for MiddlewareError {}
