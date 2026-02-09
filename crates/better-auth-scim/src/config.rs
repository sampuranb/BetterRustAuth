//! SCIM plugin configuration.

use serde::{Deserialize, Serialize};

/// SCIM plugin configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimOptions {
    /// Bearer token for authenticating SCIM requests.
    pub bearer_token: String,
    /// Base URL for SCIM endpoints.
    pub scim_base_path: String,
    /// Maximum results per page.
    #[serde(default = "default_max_results")]
    pub max_results: usize,
    /// Auto-provision users on SCIM create.
    #[serde(default = "default_true")]
    pub auto_provision: bool,
    /// Auto-deprovision (deactivate) users on SCIM delete.
    #[serde(default = "default_true")]
    pub auto_deprovision: bool,
}

fn default_max_results() -> usize { 200 }
fn default_true() -> bool { true }

impl Default for ScimOptions {
    fn default() -> Self {
        Self {
            bearer_token: String::new(),
            scim_base_path: "/scim/v2".to_string(),
            max_results: 200,
            auto_provision: true,
            auto_deprovision: true,
        }
    }
}
