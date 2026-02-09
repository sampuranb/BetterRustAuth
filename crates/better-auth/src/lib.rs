// better-auth — main library crate
//
// Wires together crypto, cookies, state, internal adapter, routes, middleware, and plugins.

pub mod api;
pub mod context;
pub mod cookies;
pub mod crypto;
pub mod db;
pub mod handler;
pub mod init;
pub mod internal_adapter;
pub mod middleware;
pub mod oauth;
pub mod plugins;
pub mod plugin_runtime;
pub mod routes;
pub mod state;
pub mod utils;
pub mod verification;
