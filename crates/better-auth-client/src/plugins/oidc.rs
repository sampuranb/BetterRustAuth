//! OIDC client plugin. Maps to TS `plugins/oidc-provider/client.ts`.
use crate::plugin::ClientPlugin;

pub struct OidcClient;
impl ClientPlugin for OidcClient {
    fn id(&self) -> &str { "oidc-client" }
}
