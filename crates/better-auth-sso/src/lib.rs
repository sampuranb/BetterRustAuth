//! # better-auth-sso
//!
//! SSO/SAML plugin for Better Auth.
//! Maps to TS `packages/sso/` (6,099 lines, 21 files).
//!
//! Provides:
//! - SAML Service Provider (SP) implementation
//! - SSO connection management (IdP configuration)
//! - SAML request generation and response parsing
//! - Attribute mapping and user provisioning

pub mod types;
pub mod config;
pub mod saml;
pub mod schema;
pub mod routes;
pub mod error;

pub use config::*;
pub use types::*;
pub use error::*;
