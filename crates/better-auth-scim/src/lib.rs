//! # better-auth-scim
//!
//! SCIM 2.0 plugin for Better Auth.
//! Maps to TS `packages/scim/` (2,054 lines, 14 files).
//!
//! Implements [RFC 7644](https://tools.ietf.org/html/rfc7644) — System for
//! Cross-domain Identity Management.
//!
//! ## Endpoints
//! - GET /scim/v2/Users — List users
//! - GET /scim/v2/Users/:id — Get user
//! - POST /scim/v2/Users — Create user
//! - PUT /scim/v2/Users/:id — Replace user
//! - PATCH /scim/v2/Users/:id — Update user
//! - DELETE /scim/v2/Users/:id — Delete user
//! - GET /scim/v2/Groups — List groups
//! - GET /scim/v2/Groups/:id — Get group
//! - POST /scim/v2/Groups — Create group
//! - PATCH /scim/v2/Groups/:id — Update group
//! - DELETE /scim/v2/Groups/:id — Delete group
//! - GET /scim/v2/Schemas — Schema discovery
//! - GET /scim/v2/ServiceProviderConfig — Service provider config
//! - GET /scim/v2/ResourceTypes — Resource types

pub mod types;
pub mod patch;
pub mod filter;
pub mod schema;
pub mod config;
pub mod error;

pub use config::*;
pub use types::*;
pub use error::*;
