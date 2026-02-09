// Plugin module — all Better Auth plugins live here, feature-gated.
//
// Each plugin is a separate module implementing `BetterAuthPlugin`.
// Enable via Cargo features in Cargo.toml.

// ─── Tier 1: Schema-Only / Simple ───────────────────────────────

#[cfg(feature = "plugin-bearer")]
pub mod bearer;

#[cfg(feature = "plugin-additional-fields")]
pub mod additional_fields;

#[cfg(feature = "plugin-haveibeenpwned")]
pub mod haveibeenpwned;

#[cfg(feature = "plugin-last-login-method")]
pub mod last_login_method;

#[cfg(feature = "plugin-custom-session")]
pub mod custom_session;

#[cfg(feature = "plugin-one-time-token")]
pub mod one_time_token;

// ─── Tier 2: Auth Methods ───────────────────────────────────────

#[cfg(feature = "plugin-username")]
pub mod username;

#[cfg(feature = "plugin-anonymous")]
pub mod anonymous;

#[cfg(feature = "plugin-magic-link")]
pub mod magic_link;

#[cfg(feature = "plugin-email-otp")]
pub mod email_otp;

#[cfg(feature = "plugin-phone-number")]
pub mod phone_number;

#[cfg(feature = "plugin-one-tap")]
pub mod one_tap;

#[cfg(feature = "plugin-generic-oauth")]
pub mod generic_oauth;

#[cfg(feature = "plugin-oauth-proxy")]
pub mod oauth_proxy;

#[cfg(feature = "plugin-siwe")]
pub mod siwe;

#[cfg(feature = "plugin-captcha")]
pub mod captcha;

// ─── Tier 3: Security & Management ─────────────────────────────

#[cfg(feature = "plugin-two-factor")]
pub mod two_factor;

#[cfg(feature = "plugin-admin")]
pub mod admin;

#[cfg(feature = "plugin-access")]
pub mod access;

#[cfg(feature = "plugin-organization")]
pub mod organization;

// ─── Tier 4: Advanced / Niche ───────────────────────────────────

#[cfg(feature = "plugin-api-key")]
pub mod api_key;

#[cfg(feature = "plugin-jwt")]
pub mod jwt;

#[cfg(feature = "plugin-multi-session")]
pub mod multi_session;

#[cfg(feature = "plugin-device-authorization")]
pub mod device_authorization;

#[cfg(feature = "plugin-oidc-provider")]
pub mod oidc_provider;

#[cfg(feature = "plugin-open-api")]
pub mod open_api;

#[cfg(feature = "plugin-mcp")]
pub mod mcp;
