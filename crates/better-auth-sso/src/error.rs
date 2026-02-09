//! SSO error codes.

/// SSO/SAML-specific error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsoError {
    ConnectionNotFound,
    InvalidSamlResponse,
    SignatureVerificationFailed,
    AssertionExpired,
    UserNotFound,
    InvalidIssuer,
    MissingAttribute,
    InvalidConfiguration,
    ProviderNotSupported,
    SessionCreationFailed,
    InvalidRelayState,
    MetadataFetchFailed,
}

impl SsoError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::ConnectionNotFound => "CONNECTION_NOT_FOUND",
            Self::InvalidSamlResponse => "INVALID_SAML_RESPONSE",
            Self::SignatureVerificationFailed => "SIGNATURE_VERIFICATION_FAILED",
            Self::AssertionExpired => "ASSERTION_EXPIRED",
            Self::UserNotFound => "USER_NOT_FOUND",
            Self::InvalidIssuer => "INVALID_ISSUER",
            Self::MissingAttribute => "MISSING_ATTRIBUTE",
            Self::InvalidConfiguration => "INVALID_CONFIGURATION",
            Self::ProviderNotSupported => "PROVIDER_NOT_SUPPORTED",
            Self::SessionCreationFailed => "SESSION_CREATION_FAILED",
            Self::InvalidRelayState => "INVALID_RELAY_STATE",
            Self::MetadataFetchFailed => "METADATA_FETCH_FAILED",
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::ConnectionNotFound => "SSO connection not found",
            Self::InvalidSamlResponse => "Invalid SAML response",
            Self::SignatureVerificationFailed => "SAML signature verification failed",
            Self::AssertionExpired => "SAML assertion has expired",
            Self::UserNotFound => "User not found for SSO assertion",
            Self::InvalidIssuer => "Invalid SAML issuer",
            Self::MissingAttribute => "Required SAML attribute is missing",
            Self::InvalidConfiguration => "Invalid SSO configuration",
            Self::ProviderNotSupported => "SSO provider not supported",
            Self::SessionCreationFailed => "Failed to create session after SSO",
            Self::InvalidRelayState => "Invalid relay state",
            Self::MetadataFetchFailed => "Failed to fetch IdP metadata",
        }
    }
}

impl std::fmt::Display for SsoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for SsoError {}
