// Types — mirrors packages/electron/src/types/options.ts
//
// Configuration options for the Electron plugin.

use serde::{Deserialize, Serialize};

/// Options for the Electron plugin.
///
/// Maps to TS `ElectronOptions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElectronOptions {
    /// Code expiration in seconds (default: 300 = 5 minutes).
    #[serde(default = "default_code_expires_in")]
    pub code_expires_in: u64,

    /// Redirect cookie expiration in seconds (default: 120 = 2 minutes).
    #[serde(default = "default_redirect_cookie_expires_in")]
    pub redirect_cookie_expires_in: u64,

    /// Cookie name prefix (default: "better-auth").
    #[serde(default = "default_cookie_prefix")]
    pub cookie_prefix: String,

    /// Client identifier (default: "electron").
    #[serde(default = "default_client_id")]
    pub client_id: String,

    /// Disable origin override for Electron API routes.
    /// When true, the `electron-origin` header will not be used to override origin.
    #[serde(default)]
    pub disable_origin_override: bool,
}

fn default_code_expires_in() -> u64 {
    300
}
fn default_redirect_cookie_expires_in() -> u64 {
    120
}
fn default_cookie_prefix() -> String {
    "better-auth".to_string()
}
fn default_client_id() -> String {
    "electron".to_string()
}

impl Default for ElectronOptions {
    fn default() -> Self {
        Self {
            code_expires_in: 300,
            redirect_cookie_expires_in: 120,
            cookie_prefix: "better-auth".to_string(),
            client_id: "electron".to_string(),
            disable_origin_override: false,
        }
    }
}
