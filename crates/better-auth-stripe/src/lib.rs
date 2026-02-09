//! # better-auth-stripe
//!
//! Stripe plugin for Better Auth.
//! Maps to TS `packages/stripe/` (3,342 lines, 10 files).
//!
//! ## Endpoints
//! - POST /stripe/webhook — Handle Stripe webhook events
//! - POST /stripe/create-checkout — Create checkout session
//! - POST /stripe/create-portal — Create customer portal session
//! - GET /stripe/subscription — Get user's subscription
//! - GET /stripe/customer — Get/sync Stripe customer

pub mod types;
pub mod webhook;
pub mod schema;
pub mod config;
pub mod error;

pub use config::*;
pub use types::*;
pub use error::*;
