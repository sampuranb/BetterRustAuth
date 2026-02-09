//! # better-auth-oauth-provider
//!
//! OAuth 2.0 Authorization Server for Better Auth.
//! Maps to TS `packages/oauth-provider/` (8,547 lines, 25 files).
//!
//! Implements:
//! - Authorization Code Grant (with PKCE)
//! - Client Credentials Grant
//! - Refresh Token Grant
//! - Token Introspection (RFC 7662)
//! - Token Revocation (RFC 7009)
//! - Client Registration
//! - Consent Management
//! - Discovery Metadata (RFC 8414)

pub mod types;
pub mod config;
pub mod pkce;
pub mod token;
pub mod grants;
pub mod client;
pub mod consent;
pub mod discovery;
pub mod error;
pub mod schema;

pub use config::*;
pub use types::*;
pub use error::*;
