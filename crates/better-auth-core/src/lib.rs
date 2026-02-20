#![doc = include_str!("../README.md")]

pub mod db;
pub mod env;
pub mod error;
pub mod hooks;
pub mod logger;
pub mod options;
pub mod plugin;
pub mod utils;

// Re-exports for convenience
pub use db::adapter::Adapter;
pub use db::models::{Account, Session, User, Verification};
pub use db::secondary_storage::{SecondaryStorage, SecondaryStorageError, MemorySecondaryStorage};
pub use db::secondary_storage::{RateLimitStorage, RateLimitData, MemoryRateLimitStorage};
pub use error::{ApiError, BetterAuthError, ErrorCode};
pub use hooks::{AsyncHook, AsyncHookRegistry, HookEvent, HookResult};
pub use logger::{AuthLogger, LoggerConfig, LogLevel, LogHandler};
pub use options::BetterAuthOptions;
pub use plugin::BetterAuthPlugin;
