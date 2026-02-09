// Error codes — mirrors packages/electron/src/error-codes.ts

use serde::{Deserialize, Serialize};

/// Error codes for the Electron plugin.
///
/// Maps to TS `ELECTRON_ERROR_CODES`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElectronErrorCodes {
    pub invalid_token: &'static str,
    pub state_mismatch: &'static str,
    pub missing_code_challenge: &'static str,
    pub invalid_code_verifier: &'static str,
    pub missing_state: &'static str,
    pub missing_pkce: &'static str,
}

/// The static error codes instance.
pub static ELECTRON_ERROR_CODES: ElectronErrorCodes = ElectronErrorCodes {
    invalid_token: "Invalid or expired token.",
    state_mismatch: "state mismatch",
    missing_code_challenge: "missing code challenge",
    invalid_code_verifier: "Invalid code verifier",
    missing_state: "state is required",
    missing_pkce: "pkce is required",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes() {
        assert_eq!(ELECTRON_ERROR_CODES.invalid_token, "Invalid or expired token.");
        assert_eq!(ELECTRON_ERROR_CODES.state_mismatch, "state mismatch");
        assert_eq!(ELECTRON_ERROR_CODES.missing_pkce, "pkce is required");
    }
}
