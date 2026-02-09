//! Client-side plugin implementations for all Better Auth plugins.
//!
//! Each plugin provides typed async methods that call the server endpoints.
//! Maps to the TS `client.ts` files in each plugin directory.

mod two_factor;
mod admin;
mod organization;
mod api_key;
mod email_otp;
mod magic_link;
mod username;
mod phone_number;
mod anonymous;
mod multi_session;
mod jwt;
mod oidc;
mod device_auth;
mod one_tap;
mod siwe;
mod generic_oauth;
mod one_time_token;

pub use two_factor::*;
pub use admin::*;
pub use organization::*;
pub use api_key::*;
pub use email_otp::*;
pub use magic_link::*;
pub use username::*;
pub use phone_number::*;
pub use anonymous::*;
pub use multi_session::*;
pub use jwt::*;
pub use oidc::*;
pub use device_auth::*;
pub use one_tap::*;
pub use siwe::*;
pub use generic_oauth::*;
pub use one_time_token::*;
