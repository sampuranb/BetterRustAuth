//! One Tap client plugin. Maps to TS `plugins/one-tap/client.ts`.
//! Note: The browser-specific Google Identity Services logic is TS/browser-only.
//! This Rust client provides the server callback method.
use crate::BetterAuthClient;
use crate::error::ClientError;
use crate::plugin::ClientPlugin;

pub struct OneTapClient;
impl ClientPlugin for OneTapClient {
    fn id(&self) -> &str { "one-tap" }
}

impl BetterAuthClient {
    /// Send a Google ID token to the server for verification.
    pub async fn one_tap_callback(&self, id_token: &str) -> Result<serde_json::Value, ClientError> {
        self.post("/one-tap/callback", &serde_json::json!({"idToken": id_token})).await
    }
}
