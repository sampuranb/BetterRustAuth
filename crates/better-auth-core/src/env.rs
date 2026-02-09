// Environment detection and logger configuration.
//
// Maps to: packages/core/src/env/env-impl.ts + packages/core/src/env/logger.ts

use std::sync::OnceLock;

/// Cached environment mode.
static ENV_MODE: OnceLock<EnvMode> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvMode {
    Production,
    Development,
    Test,
}

/// Detect the current environment mode from environment variables.
/// Checks `NODE_ENV`, `BETTER_AUTH_ENV`, and `RUST_ENV` in order.
pub fn detect_env_mode() -> EnvMode {
    *ENV_MODE.get_or_init(|| {
        let env_val = std::env::var("BETTER_AUTH_ENV")
            .or_else(|_| std::env::var("RUST_ENV"))
            .or_else(|_| std::env::var("NODE_ENV"))
            .unwrap_or_default()
            .to_lowercase();

        match env_val.as_str() {
            "production" | "prod" => EnvMode::Production,
            "test" | "testing" => EnvMode::Test,
            _ => EnvMode::Development,
        }
    })
}

pub fn is_production() -> bool {
    detect_env_mode() == EnvMode::Production
}

pub fn is_development() -> bool {
    detect_env_mode() == EnvMode::Development
}

pub fn is_test() -> bool {
    detect_env_mode() == EnvMode::Test
}

/// Get the BETTER_AUTH_SECRET from environment variables.
pub fn get_secret_from_env() -> Option<String> {
    std::env::var("BETTER_AUTH_SECRET").ok()
}

/// Get the BETTER_AUTH_URL from environment variables.
pub fn get_url_from_env() -> Option<String> {
    std::env::var("BETTER_AUTH_URL").ok()
}

/// Initialize the `tracing` subscriber with appropriate defaults.
/// In production, uses JSON format. In development, uses pretty format.
pub fn init_logger() {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            if is_production() {
                EnvFilter::new("better_auth=info")
            } else {
                EnvFilter::new("better_auth=debug")
            }
        });

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(false)
        .init();
}

/// Log levels matching the TypeScript logger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Success,
    Disabled,
}

impl From<&str> for LogLevel {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "debug" => Self::Debug,
            "info" => Self::Info,
            "warn" => Self::Warn,
            "error" => Self::Error,
            "success" => Self::Success,
            "disabled" | "off" => Self::Disabled,
            _ => Self::Info,
        }
    }
}
