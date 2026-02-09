// Utility functions — ID generation, URL helpers.
//
// Maps to: packages/core/src/utils/

pub mod id;
pub mod url;

pub use id::generate_id;
pub use url::{get_origin, get_host, normalize_pathname};
