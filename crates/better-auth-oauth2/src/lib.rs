#![doc = include_str!("../README.md")]

pub mod authorization_url;
pub mod client_credentials;
pub mod code_exchange;
pub mod pkce;
pub mod provider;
pub mod providers;
pub mod refresh;
pub mod tokens;

// Re-exports
pub use authorization_url::create_authorization_url;
pub use code_exchange::validate_authorization_code;
pub use pkce::generate_code_challenge;
pub use provider::{OAuthProvider, ProviderOptions};
pub use providers::{GenericOAuthProvider, get_provider_config, PROVIDER_IDS};
pub use refresh::refresh_access_token;
pub use tokens::{OAuth2Tokens, OAuth2UserInfo};
