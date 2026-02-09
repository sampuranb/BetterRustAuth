//! Generic OAuth client plugin. Maps to TS `plugins/generic-oauth/client.ts`.
use crate::plugin::ClientPlugin;

pub struct GenericOAuthClient;
impl ClientPlugin for GenericOAuthClient {
    fn id(&self) -> &str { "generic-oauth-client" }
}
