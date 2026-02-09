// Route handlers module — maps to packages/better-auth/src/api/routes/
//
// Each sub-module implements one or more API endpoints matching the TS version.
// All 30 core endpoints from the TS API are implemented.

pub mod account;
pub mod callback;
pub mod email_verification;
pub mod error;
pub mod error_page;
pub mod ok;
pub mod password;
pub mod session;
pub mod sign_in;
pub mod sign_out;
pub mod sign_up;
pub mod update_user;
