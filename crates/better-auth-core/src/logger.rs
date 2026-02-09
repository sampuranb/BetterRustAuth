// Auth logger — maps to packages/core/src/env/logger.ts
//
// Structured logger with colored output, level filtering, and custom log
// handler support. Matches the TS `createLogger` and `InternalLogger` types exactly.

use std::fmt;
use std::sync::Arc;

/// ANSI color codes matching TS `TTY_COLORS`.
pub mod ansi {
    pub const RESET: &str = "\x1b[0m";
    pub const BRIGHT: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";

    pub mod fg {
        pub const RED: &str = "\x1b[31m";
        pub const GREEN: &str = "\x1b[32m";
        pub const YELLOW: &str = "\x1b[33m";
        pub const BLUE: &str = "\x1b[34m";
        pub const MAGENTA: &str = "\x1b[35m";
        pub const CYAN: &str = "\x1b[36m";
    }
}

/// Log levels matching the TypeScript `LogLevel` type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogLevel {
    Debug = 0,
    Info = 1,
    Success = 2,
    Warn = 3,
    Error = 4,
}

impl LogLevel {
    /// ANSI color for this log level.
    pub fn color(&self) -> &'static str {
        match self {
            LogLevel::Debug => ansi::fg::MAGENTA,
            LogLevel::Info => ansi::fg::BLUE,
            LogLevel::Success => ansi::fg::GREEN,
            LogLevel::Warn => ansi::fg::YELLOW,
            LogLevel::Error => ansi::fg::RED,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Success => "SUCCESS",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<&str> for LogLevel {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "debug" => Self::Debug,
            "info" => Self::Info,
            "success" => Self::Success,
            "warn" | "warning" => Self::Warn,
            "error" => Self::Error,
            _ => Self::Warn,
        }
    }
}

/// Logger configuration options.
///
/// Maps to the TypeScript `Logger` interface.
#[derive(Debug, Clone)]
pub struct LoggerConfig {
    /// Whether logging is disabled entirely.
    pub disabled: bool,
    /// Whether to disable ANSI color output.
    pub disable_colors: bool,
    /// The minimum log level to emit.
    pub level: LogLevel,
    /// Optional custom log handler (overrides default stderr/stdout output).
    pub custom_handler: Option<Arc<dyn LogHandler>>,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            disabled: false,
            disable_colors: false,
            level: LogLevel::Warn,
            custom_handler: None,
        }
    }
}

/// Custom log handler trait for user-provided logging backends.
///
/// Maps to the `log` callback in the TS `Logger` interface.
pub trait LogHandler: Send + Sync + fmt::Debug {
    fn handle(&self, level: LogLevel, message: &str, args: &[&str]);
}

/// The internal auth logger used throughout the system.
///
/// Maps to the TypeScript `InternalLogger` type.
/// Provides methods for each log level: debug, info, success, warn, error.
#[derive(Clone)]
pub struct AuthLogger {
    config: LoggerConfig,
}

impl fmt::Debug for AuthLogger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthLogger")
            .field("level", &self.config.level)
            .field("disabled", &self.config.disabled)
            .finish()
    }
}

impl AuthLogger {
    /// Create a new logger with the given configuration.
    ///
    /// Maps to TS `createLogger(options)`.
    pub fn new(config: LoggerConfig) -> Self {
        Self { config }
    }

    /// Create a default logger (warn level, colors enabled).
    pub fn default_logger() -> Self {
        Self::new(LoggerConfig::default())
    }

    /// Get the current log level.
    pub fn level(&self) -> LogLevel {
        self.config.level
    }

    /// Whether a given level should be published.
    ///
    /// Maps to TS `shouldPublishLog(currentLogLevel, logLevel)`.
    pub fn should_publish(&self, level: LogLevel) -> bool {
        if self.config.disabled {
            return false;
        }
        level >= self.config.level
    }

    /// Log a debug message.
    pub fn debug(&self, message: &str) {
        self.log(LogLevel::Debug, message, &[]);
    }

    /// Log an info message.
    pub fn info(&self, message: &str) {
        self.log(LogLevel::Info, message, &[]);
    }

    /// Log a success message.
    pub fn success(&self, message: &str) {
        self.log(LogLevel::Success, message, &[]);
    }

    /// Log a warning message.
    pub fn warn(&self, message: &str) {
        self.log(LogLevel::Warn, message, &[]);
    }

    /// Log an error message.
    pub fn error(&self, message: &str) {
        self.log(LogLevel::Error, message, &[]);
    }

    /// Log a message with extra arguments.
    pub fn log(&self, level: LogLevel, message: &str, args: &[&str]) {
        if !self.should_publish(level) {
            return;
        }

        // If custom handler is configured, delegate to it
        if let Some(ref handler) = self.config.custom_handler {
            // Map "success" to "info" for custom handlers (matching TS behavior)
            let handler_level = if level == LogLevel::Success {
                LogLevel::Info
            } else {
                level
            };
            handler.handle(handler_level, message, args);
            return;
        }

        let formatted = self.format_message(level, message);

        match level {
            LogLevel::Error => eprintln!("{}{}", formatted, format_args_str(args)),
            LogLevel::Warn => eprintln!("{}{}", formatted, format_args_str(args)),
            _ => println!("{}{}", formatted, format_args_str(args)),
        }
    }

    /// Format a log message with timestamp, level, and prefix.
    ///
    /// Maps to TS `formatMessage(level, message, colorsEnabled)`.
    fn format_message(&self, level: LogLevel, message: &str) -> String {
        let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let colors_enabled = !self.config.disable_colors;

        if colors_enabled {
            format!(
                "{dim}{timestamp}{reset} {color}{level}{reset} {bright}[Better Auth]:{reset} {message}",
                dim = ansi::DIM,
                reset = ansi::RESET,
                color = level.color(),
                level = level.as_str(),
                bright = ansi::BRIGHT,
                timestamp = timestamp,
                message = message,
            )
        } else {
            format!("{} {} [Better Auth]: {}", timestamp, level.as_str(), message)
        }
    }
}

impl Default for AuthLogger {
    fn default() -> Self {
        Self::default_logger()
    }
}

/// Format additional log arguments for output.
fn format_args_str(args: &[&str]) -> String {
    if args.is_empty() {
        String::new()
    } else {
        format!(" {}", args.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Success);
        assert!(LogLevel::Success < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
    }

    #[test]
    fn test_log_level_from_str() {
        assert_eq!(LogLevel::from("debug"), LogLevel::Debug);
        assert_eq!(LogLevel::from("info"), LogLevel::Info);
        assert_eq!(LogLevel::from("success"), LogLevel::Success);
        assert_eq!(LogLevel::from("warn"), LogLevel::Warn);
        assert_eq!(LogLevel::from("error"), LogLevel::Error);
        // Default fallback
        assert_eq!(LogLevel::from("unknown"), LogLevel::Warn);
    }

    #[test]
    fn test_should_publish() {
        let logger = AuthLogger::new(LoggerConfig {
            level: LogLevel::Warn,
            ..Default::default()
        });
        assert!(!logger.should_publish(LogLevel::Debug));
        assert!(!logger.should_publish(LogLevel::Info));
        assert!(!logger.should_publish(LogLevel::Success));
        assert!(logger.should_publish(LogLevel::Warn));
        assert!(logger.should_publish(LogLevel::Error));
    }

    #[test]
    fn test_disabled_logger() {
        let logger = AuthLogger::new(LoggerConfig {
            disabled: true,
            ..Default::default()
        });
        assert!(!logger.should_publish(LogLevel::Error));
    }

    #[test]
    fn test_format_message_no_color() {
        let logger = AuthLogger::new(LoggerConfig {
            disable_colors: true,
            level: LogLevel::Debug,
            ..Default::default()
        });
        let msg = logger.format_message(LogLevel::Info, "test message");
        assert!(msg.contains("INFO"));
        assert!(msg.contains("[Better Auth]:"));
        assert!(msg.contains("test message"));
        // Should NOT contain ANSI codes
        assert!(!msg.contains("\x1b["));
    }

    #[test]
    fn test_format_message_with_color() {
        let logger = AuthLogger::new(LoggerConfig {
            disable_colors: false,
            level: LogLevel::Debug,
            ..Default::default()
        });
        let msg = logger.format_message(LogLevel::Error, "something failed");
        assert!(msg.contains("\x1b[")); // contains ANSI codes
        assert!(msg.contains("ERROR"));
        assert!(msg.contains("something failed"));
    }

    #[test]
    fn test_default_logger() {
        let logger = AuthLogger::default();
        assert_eq!(logger.level(), LogLevel::Warn);
        assert!(!logger.config.disabled);
    }

    #[test]
    fn test_log_level_colors() {
        assert_eq!(LogLevel::Debug.color(), ansi::fg::MAGENTA);
        assert_eq!(LogLevel::Info.color(), ansi::fg::BLUE);
        assert_eq!(LogLevel::Success.color(), ansi::fg::GREEN);
        assert_eq!(LogLevel::Warn.color(), ansi::fg::YELLOW);
        assert_eq!(LogLevel::Error.color(), ansi::fg::RED);
    }

    #[derive(Debug)]
    struct TestHandler {
        captured: std::sync::Mutex<Vec<(LogLevel, String)>>,
    }

    impl TestHandler {
        fn new() -> Self {
            Self {
                captured: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl LogHandler for TestHandler {
        fn handle(&self, level: LogLevel, message: &str, _args: &[&str]) {
            self.captured.lock().unwrap().push((level, message.to_string()));
        }
    }

    #[test]
    fn test_custom_handler() {
        let handler = Arc::new(TestHandler::new());
        let logger = AuthLogger::new(LoggerConfig {
            level: LogLevel::Debug,
            custom_handler: Some(handler.clone()),
            ..Default::default()
        });
        logger.info("custom log");
        logger.error("custom error");

        let captured = handler.captured.lock().unwrap();
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].0, LogLevel::Info);
        assert_eq!(captured[0].1, "custom log");
        assert_eq!(captured[1].0, LogLevel::Error);
        assert_eq!(captured[1].1, "custom error");
    }

    #[test]
    fn test_success_maps_to_info_in_custom_handler() {
        let handler = Arc::new(TestHandler::new());
        let logger = AuthLogger::new(LoggerConfig {
            level: LogLevel::Debug,
            custom_handler: Some(handler.clone()),
            ..Default::default()
        });
        logger.success("it worked");

        let captured = handler.captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        // Success maps to Info for custom handlers (matching TS behavior)
        assert_eq!(captured[0].0, LogLevel::Info);
    }

    #[test]
    fn test_format_args_str_empty() {
        assert_eq!(format_args_str(&[]), "");
    }

    #[test]
    fn test_format_args_str_multiple() {
        assert_eq!(format_args_str(&["a", "b"]), " a b");
    }
}
