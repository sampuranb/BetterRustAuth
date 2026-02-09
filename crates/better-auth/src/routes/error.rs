// Error handling — maps to packages/better-auth/src/api/routes/error.ts
//                  and @better-auth/core/error (APIError + BASE_ERROR_CODES)
//
// Provides:
//   - `ApiError` — rich, typed API error with HTTP status, code, and message
//   - `BASE_ERROR_CODES` — all standard error codes from the TS `BASE_ERROR_CODES` const
//   - `ApiErrorResponse` — JSON-serializable error response body
//   - `render_error_page` — HTML error page matching the TS error rendering

use serde::Serialize;

// ─── API Error ────────────────────────────────────────────────────────────────

/// API error type that maps to the TS `APIError` class.
///
/// Contains HTTP status code, error code, and human-readable message.
#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    /// Convert to JSON response body.
    pub fn to_response(&self) -> ApiErrorResponse {
        ApiErrorResponse {
            message: self.message.clone(),
            code: Some(self.code.to_string()),
            status: Some(self.status),
        }
    }

    // ── Common constructors ──

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(401, "UNAUTHORIZED", message)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(403, "FORBIDDEN", message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(404, "NOT_FOUND", message)
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(400, "BAD_REQUEST", message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(500, "INTERNAL_SERVER_ERROR", message)
    }

    pub fn method_not_allowed(message: impl Into<String>) -> Self {
        Self::new(405, "METHOD_NOT_ALLOWED", message)
    }

    pub fn too_many_requests(message: impl Into<String>) -> Self {
        Self::new(429, "TOO_MANY_REQUESTS", message)
    }

    /// Create from a typed error code.
    pub fn from_code(code: ErrorCode) -> Self {
        let (status, code_str, message) = code.details();
        Self::new(status, code_str, message)
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {} ({})", self.status, self.message, self.code)
    }
}

impl std::error::Error for ApiError {}

// ─── Error Response ──────────────────────────────────────────────────────────

/// Standard API error response body.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiErrorResponse {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
}

impl ApiErrorResponse {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: None,
            status: None,
        }
    }

    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }

    pub fn with_status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }
}

// ─── BASE_ERROR_CODES ────────────────────────────────────────────────────────

/// All standard error codes from the TS `BASE_ERROR_CODES`.
///
/// Each variant maps to a (HTTP status, code string, message) triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    // Auth / Session
    Unauthorized,
    SessionNotFresh,
    FailedToGetSession,
    MethodNotAllowedDeferSessionRequired,

    // User / Email
    UserNotFound,
    UserAlreadyExists,
    UserEmailNotFound,
    EmailCanNotBeUpdated,
    FailedToCreateUser,
    BodyMustBeAnObject,

    // Password
    InvalidPassword,
    PasswordTooShort,
    PasswordTooLong,
    PasswordAlreadySet,
    CredentialAccountNotFound,

    // Account
    AccountNotFound,
    FailedToUnlinkLastAccount,
    LinkingNotAllowed,
    LinkingDifferentEmailsNotAllowed,
    LinkingFailed,

    // Provider / OAuth
    ProviderNotFound,
    IdTokenNotSupported,
    InvalidToken,
    FailedToGetUserInfo,
    FailedToGetAccessToken,
    FailedToRefreshAccessToken,
    ProviderNotSupported,
    TokenRefreshNotSupported,
    RefreshTokenNotFound,

    // Email Verification
    InvalidEmailVerificationToken,
    EmailVerificationTokenExpired,
    FailedToSendVerificationEmail,

    // Social
    SocialAccountAlreadyLinked,
    SocialSignInDisabled,

    // Rate Limiting
    RateLimitExceeded,

    // CSRF / Origin
    InvalidOrigin,

    // General
    InternalServerError,
    NotFound,
}

impl ErrorCode {
    /// Returns (HTTP status, code string, message) for each error code.
    pub fn details(self) -> (u16, &'static str, &'static str) {
        match self {
            Self::Unauthorized => (401, "UNAUTHORIZED", "Unauthorized"),
            Self::SessionNotFresh => (403, "SESSION_NOT_FRESH", "Session is not fresh. Please re-authenticate."),
            Self::FailedToGetSession => (500, "FAILED_TO_GET_SESSION", "Failed to get session"),
            Self::MethodNotAllowedDeferSessionRequired => (405, "METHOD_NOT_ALLOWED", "POST method requires deferSessionRefresh to be enabled"),

            Self::UserNotFound => (404, "USER_NOT_FOUND", "User not found"),
            Self::UserAlreadyExists => (409, "USER_ALREADY_EXISTS", "User already exists"),
            Self::UserEmailNotFound => (400, "USER_EMAIL_NOT_FOUND", "User email not found"),
            Self::EmailCanNotBeUpdated => (400, "EMAIL_CAN_NOT_BE_UPDATED", "Email can not be updated through this endpoint. Use the change-email endpoint instead."),
            Self::FailedToCreateUser => (500, "FAILED_TO_CREATE_USER", "Failed to create user"),
            Self::BodyMustBeAnObject => (400, "BODY_MUST_BE_AN_OBJECT", "Body must be an object"),

            Self::InvalidPassword => (400, "INVALID_PASSWORD", "Invalid password"),
            Self::PasswordTooShort => (400, "PASSWORD_TOO_SHORT", "Password is too short"),
            Self::PasswordTooLong => (400, "PASSWORD_TOO_LONG", "Password is too long"),
            Self::PasswordAlreadySet => (400, "PASSWORD_ALREADY_SET", "Password already set"),
            Self::CredentialAccountNotFound => (400, "CREDENTIAL_ACCOUNT_NOT_FOUND", "Credential account not found"),

            Self::AccountNotFound => (400, "ACCOUNT_NOT_FOUND", "Account not found"),
            Self::FailedToUnlinkLastAccount => (400, "FAILED_TO_UNLINK_LAST_ACCOUNT", "Cannot unlink the only linked account"),
            Self::LinkingNotAllowed => (401, "LINKING_NOT_ALLOWED", "Account linking is not allowed"),
            Self::LinkingDifferentEmailsNotAllowed => (401, "LINKING_DIFFERENT_EMAILS_NOT_ALLOWED", "Account linking with different emails is not allowed"),
            Self::LinkingFailed => (417, "LINKING_FAILED", "Account not linked — unable to create account"),

            Self::ProviderNotFound => (404, "PROVIDER_NOT_FOUND", "Provider not found. Make sure to add the provider in your auth config."),
            Self::IdTokenNotSupported => (404, "ID_TOKEN_NOT_SUPPORTED", "Provider does not support ID token verification"),
            Self::InvalidToken => (401, "INVALID_TOKEN", "Invalid token"),
            Self::FailedToGetUserInfo => (401, "FAILED_TO_GET_USER_INFO", "Failed to get user info from provider"),
            Self::FailedToGetAccessToken => (400, "FAILED_TO_GET_ACCESS_TOKEN", "Failed to get a valid access token"),
            Self::FailedToRefreshAccessToken => (400, "FAILED_TO_REFRESH_ACCESS_TOKEN", "Failed to refresh access token"),
            Self::ProviderNotSupported => (400, "PROVIDER_NOT_SUPPORTED", "Provider is not supported"),
            Self::TokenRefreshNotSupported => (400, "TOKEN_REFRESH_NOT_SUPPORTED", "Provider does not support token refreshing"),
            Self::RefreshTokenNotFound => (400, "REFRESH_TOKEN_NOT_FOUND", "Refresh token not found"),

            Self::InvalidEmailVerificationToken => (400, "INVALID_EMAIL_VERIFICATION_TOKEN", "Invalid email verification token"),
            Self::EmailVerificationTokenExpired => (400, "EMAIL_VERIFICATION_TOKEN_EXPIRED", "Email verification token has expired"),
            Self::FailedToSendVerificationEmail => (500, "FAILED_TO_SEND_VERIFICATION_EMAIL", "Failed to send verification email"),

            Self::SocialAccountAlreadyLinked => (409, "SOCIAL_ACCOUNT_ALREADY_LINKED", "Social account is already linked"),
            Self::SocialSignInDisabled => (403, "SOCIAL_SIGN_IN_DISABLED", "Social sign-in is disabled"),

            Self::RateLimitExceeded => (429, "RATE_LIMIT_EXCEEDED", "Too many requests. Please try again later."),

            Self::InvalidOrigin => (403, "INVALID_ORIGIN", "Invalid origin"),

            Self::InternalServerError => (500, "INTERNAL_SERVER_ERROR", "Internal server error"),
            Self::NotFound => (404, "NOT_FOUND", "Not found"),
        }
    }
}

// ─── Error Page ──────────────────────────────────────────────────────────────

/// Render an HTML error page matching the TS error page styling.
///
/// Used by the `/error` GET endpoint to display errors to the user.
pub fn render_error_page(code: &str, description: Option<&str>) -> String {
    let sanitized_code = sanitize_html(code);
    let desc_html = description
        .map(|d| format!(
            r#"<p style="font-size: var(--text-sm); line-height: var(--text-sm--line-height); color: var(--muted-foreground); margin: 0;">{}</p>"#,
            sanitize_html(d)
        ))
        .unwrap_or_default();

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Error</title>
    <style>
      * {{ box-sizing: border-box; }}
      body {{
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        background: var(--background);
        color: var(--foreground);
        margin: 0;
      }}
      :root, :host {{
        --spacing: 0.25rem;
        --text-sm: 0.875rem;
        --text-sm--line-height: calc(1.25 / 0.875);
        --text-2xl: 1.5rem;
        --text-2xl--line-height: calc(2 / 1.5);
        --text-6xl: 3rem;
        --text-6xl--line-height: 1;
        --font-weight-semibold: 600;
        --font-weight-bold: 700;
        --radius: 0.625rem;
        --primary: black;
        --primary-foreground: white;
        --background: white;
        --foreground: oklch(0.271 0 0);
        --border: oklch(0.89 0 0);
        --destructive: oklch(0.55 0.15 25.723);
        --muted-foreground: oklch(0.545 0 0);
        --corner-border: #404040;
      }}
      @media (prefers-color-scheme: dark) {{
        :root, :host {{
          --primary: white;
          --primary-foreground: black;
          --background: oklch(0.15 0 0);
          --foreground: oklch(0.98 0 0);
          --border: oklch(0.27 0 0);
          --destructive: oklch(0.65 0.15 25.723);
          --muted-foreground: oklch(0.65 0 0);
          --corner-border: #a0a0a0;
        }}
      }}
    </style>
  </head>
  <body style="width: 100vw; min-height: 100vh; overflow-x: hidden; overflow-y: auto;">
    <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 1.5rem; position: relative; width: 100%; min-height: 100vh; padding: 1rem;">
      <div style="position: relative; z-index: 10; border: 2px solid var(--border); background: var(--background); padding: 1.5rem; max-width: 42rem; width: 100%;">
        <div style="display: flex; flex-direction: column; gap: 1rem;">
          <div style="display: flex; align-items: center; gap: 0.75rem;">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="30" height="30" fill="none" stroke="var(--destructive)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="10"/>
              <path d="m15 9-6 6"/>
              <path d="m9 9 6 6"/>
            </svg>
            <h2 style="font-size: var(--text-2xl); line-height: var(--text-2xl--line-height); font-weight: var(--font-weight-semibold); margin: 0;">Authentication Error</h2>
          </div>
          <p style="font-size: var(--text-sm); line-height: var(--text-sm--line-height); color: var(--muted-foreground); margin: 0;">Error Code: {sanitized_code}</p>
          {desc_html}
          <a href="/" style="display: inline-flex; align-items: center; gap: 0.5rem; background: var(--primary); color: var(--primary-foreground); padding: 0.5rem 1rem; border-radius: var(--radius); text-decoration: none; font-size: var(--text-sm); font-weight: var(--font-weight-semibold); margin-top: 0.5rem; width: fit-content;">
            Go Home
          </a>
        </div>
      </div>
    </div>
  </body>
</html>"#
    )
}

/// Sanitize a string for safe HTML embedding (prevent XSS).
fn sanitize_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_error_constructors() {
        let err = ApiError::unauthorized("Not logged in");
        assert_eq!(err.status, 401);
        assert_eq!(err.code, "UNAUTHORIZED");

        let err = ApiError::bad_request("Invalid input");
        assert_eq!(err.status, 400);
    }

    #[test]
    fn test_error_code_details() {
        let (status, code, _msg) = ErrorCode::InvalidPassword.details();
        assert_eq!(status, 400);
        assert_eq!(code, "INVALID_PASSWORD");
    }

    #[test]
    fn test_api_error_from_code() {
        let err = ApiError::from_code(ErrorCode::SessionNotFresh);
        assert_eq!(err.status, 403);
        assert_eq!(err.code, "SESSION_NOT_FRESH");
    }

    #[test]
    fn test_error_response_serialization() {
        let resp = ApiErrorResponse::new("Something went wrong")
            .with_code("INTERNAL_SERVER_ERROR")
            .with_status(500);
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["message"], "Something went wrong");
        assert_eq!(json["code"], "INTERNAL_SERVER_ERROR");
        assert_eq!(json["status"], 500);
    }

    #[test]
    fn test_sanitize_html() {
        assert_eq!(sanitize_html("<script>alert('xss')</script>"), "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;");
    }

    #[test]
    fn test_render_error_page() {
        let html = render_error_page("UNAUTHORIZED", Some("You must be logged in"));
        assert!(html.contains("UNAUTHORIZED"));
        assert!(html.contains("You must be logged in"));
        assert!(html.contains("<!DOCTYPE html>"));
    }
}
