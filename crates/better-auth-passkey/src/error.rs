//! Passkey error codes.
//! Maps to TS `error-codes.ts`.

/// Passkey-specific error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyError {
    ChallengeNotFound,
    NotAllowedToRegister,
    FailedToVerifyRegistration,
    PasskeyNotFound,
    AuthenticationFailed,
    UnableToCreateSession,
    FailedToUpdatePasskey,
}

impl PasskeyError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::ChallengeNotFound => "CHALLENGE_NOT_FOUND",
            Self::NotAllowedToRegister => "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY",
            Self::FailedToVerifyRegistration => "FAILED_TO_VERIFY_REGISTRATION",
            Self::PasskeyNotFound => "PASSKEY_NOT_FOUND",
            Self::AuthenticationFailed => "AUTHENTICATION_FAILED",
            Self::UnableToCreateSession => "UNABLE_TO_CREATE_SESSION",
            Self::FailedToUpdatePasskey => "FAILED_TO_UPDATE_PASSKEY",
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::ChallengeNotFound => "Challenge not found",
            Self::NotAllowedToRegister => "You are not allowed to register this passkey",
            Self::FailedToVerifyRegistration => "Failed to verify registration",
            Self::PasskeyNotFound => "Passkey not found",
            Self::AuthenticationFailed => "Authentication failed",
            Self::UnableToCreateSession => "Unable to create session",
            Self::FailedToUpdatePasskey => "Failed to update passkey",
        }
    }
}

impl std::fmt::Display for PasskeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for PasskeyError {}
