// Social providers — data-driven registry of all 33 OAuth providers.
//
// Each provider is defined by a `ProviderConfig` struct containing its endpoints,
// default scopes, auth method, and user info API details.
// A generic `GenericOAuthProvider` then implements the `OAuthProvider` trait
// using this config, avoiding 33 separate trait implementations.
//
// Provider-specific overrides (Discord avatar, GitHub email, Apple/Google JWT, etc.)
// are in `provider_overrides`.

pub mod registry;
pub mod provider_overrides;
pub use registry::*;
pub use provider_overrides::*;

