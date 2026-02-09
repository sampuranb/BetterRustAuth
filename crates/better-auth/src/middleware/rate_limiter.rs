// Rate limiter — maps to packages/better-auth/src/api/rate-limiter/index.ts
//
// Fixed-window, IP-based rate limiting with in-memory storage.
// Supports per-path special rules and custom limits.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::MiddlewareError;

/// Rate limit configuration.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Enable rate limiting.
    pub enabled: bool,
    /// Default window size in seconds.
    pub window: u64,
    /// Default maximum requests per window.
    pub max: u64,
    /// Custom rules per path pattern.
    pub custom_rules: HashMap<String, RateLimitRule>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window: 60,
            max: 100,
            custom_rules: HashMap::new(),
        }
    }
}

/// A rate limit rule for a specific path.
#[derive(Debug, Clone)]
pub struct RateLimitRule {
    pub window: u64,
    pub max: u64,
}

/// An in-memory rate limit entry.
#[derive(Debug, Clone)]
struct RateLimitEntry {
    count: u64,
    window_start: Instant,
}

/// In-memory rate limiter using a fixed-window algorithm.
///
/// Thread-safe via `Mutex<HashMap>`. For production use at scale,
/// consider replacing with `DashMap` or Redis-backed storage.
pub struct RateLimiter {
    config: RateLimitConfig,
    store: Mutex<HashMap<String, RateLimitEntry>>,
}

impl RateLimiter {
    /// Create a new rate limiter with the given configuration.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            store: Mutex::new(HashMap::new()),
        }
    }

    /// Check if the request should be rate limited.
    ///
    /// Returns `Ok(())` if the request is allowed, or `Err(MiddlewareError::TooManyRequests)`
    /// if the rate limit has been exceeded.
    pub fn check(&self, ip: &str, path: &str) -> Result<(), MiddlewareError> {
        if !self.config.enabled {
            return Ok(());
        }

        // Determine effective limits for this path
        let (window, max) = self.effective_limits(path);
        let key = format!("{}:{}", ip, path);

        let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let window_duration = Duration::from_secs(window);

        match store.get_mut(&key) {
            Some(entry) => {
                let elapsed = now.duration_since(entry.window_start);

                if elapsed >= window_duration {
                    // Window has passed — reset
                    entry.count = 1;
                    entry.window_start = now;
                    Ok(())
                } else if entry.count >= max {
                    // Rate limit exceeded
                    let retry_after = (window_duration - elapsed).as_secs() + 1;
                    Err(MiddlewareError::TooManyRequests {
                        retry_after,
                        message: "Too many requests. Please try again later.".into(),
                    })
                } else {
                    // Increment counter
                    entry.count += 1;
                    Ok(())
                }
            }
            None => {
                // First request — create entry
                store.insert(
                    key,
                    RateLimitEntry {
                        count: 1,
                        window_start: now,
                    },
                );
                Ok(())
            }
        }
    }

    /// Determine the effective window and max for a given path.
    ///
    /// Priority: custom rules > special rules > defaults.
    fn effective_limits(&self, path: &str) -> (u64, u64) {
        // Check custom rules first
        for (pattern, rule) in &self.config.custom_rules {
            if path_matches(path, pattern) {
                return (rule.window, rule.max);
            }
        }

        // Check default special rules (auth-sensitive endpoints)
        if let Some(rule) = get_special_rule(path) {
            return (rule.window, rule.max);
        }

        // Fall back to defaults
        (self.config.window, self.config.max)
    }

    /// Clean up expired entries to prevent memory growth.
    pub fn cleanup(&self) {
        let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        store.retain(|_, entry| {
            let elapsed = now.duration_since(entry.window_start);
            // Keep entries that are within 2x the default window
            elapsed < Duration::from_secs(self.config.window * 2)
        });
    }
}

/// Default special rules for auth-sensitive endpoints.
///
/// Matches TS `getDefaultSpecialRules`:
/// - sign-in, sign-up, change-password, change-email: 3 requests per 10 seconds
fn get_special_rule(path: &str) -> Option<RateLimitRule> {
    let sensitive_paths = [
        "/sign-in",
        "/sign-up",
        "/change-password",
        "/change-email",
    ];

    if sensitive_paths.iter().any(|p| path.starts_with(p)) {
        Some(RateLimitRule {
            window: 10,
            max: 3,
        })
    } else {
        None
    }
}

/// Simple path pattern matching.
///
/// Supports:
/// - Exact match: `/sign-in` matches `/sign-in`
/// - Prefix match: `/sign-in` matches `/sign-in/email`
/// - Wildcard: `/api/*` matches `/api/anything`
fn path_matches(path: &str, pattern: &str) -> bool {
    if pattern.contains('*') {
        let prefix = pattern.trim_end_matches('*');
        path.starts_with(prefix)
    } else {
        path == pattern || path.starts_with(pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let config = RateLimitConfig {
            enabled: true,
            window: 60,
            max: 5,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        for _ in 0..5 {
            assert!(limiter.check("127.0.0.1", "/api/test").is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let config = RateLimitConfig {
            enabled: true,
            window: 60,
            max: 3,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        // First 3 should pass
        for _ in 0..3 {
            assert!(limiter.check("127.0.0.1", "/api/test").is_ok());
        }

        // 4th should be blocked
        let result = limiter.check("127.0.0.1", "/api/test");
        assert!(result.is_err());
        match result.unwrap_err() {
            MiddlewareError::TooManyRequests { retry_after, .. } => {
                assert!(retry_after > 0);
            }
            _ => panic!("Expected TooManyRequests"),
        }
    }

    #[test]
    fn test_rate_limiter_different_ips() {
        let config = RateLimitConfig {
            enabled: true,
            window: 60,
            max: 1,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        assert!(limiter.check("127.0.0.1", "/api/test").is_ok());
        assert!(limiter.check("127.0.0.2", "/api/test").is_ok());
        assert!(limiter.check("127.0.0.1", "/api/test").is_err());
    }

    #[test]
    fn test_rate_limiter_disabled() {
        let config = RateLimitConfig {
            enabled: false,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        // Should always pass when disabled
        for _ in 0..1000 {
            assert!(limiter.check("127.0.0.1", "/api/test").is_ok());
        }
    }

    #[test]
    fn test_special_rules_for_auth_endpoints() {
        let config = RateLimitConfig {
            enabled: true,
            window: 60,
            max: 100,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        // Auth endpoints have special rule: 3 req / 10s
        for _ in 0..3 {
            assert!(limiter.check("127.0.0.1", "/sign-in").is_ok());
        }
        assert!(limiter.check("127.0.0.1", "/sign-in").is_err());
    }

    #[test]
    fn test_custom_rules() {
        let mut custom_rules = HashMap::new();
        custom_rules.insert(
            "/api/heavy".to_string(),
            RateLimitRule { window: 60, max: 1 },
        );

        let config = RateLimitConfig {
            enabled: true,
            window: 60,
            max: 100,
            custom_rules,
        };
        let limiter = RateLimiter::new(config);

        assert!(limiter.check("127.0.0.1", "/api/heavy").is_ok());
        assert!(limiter.check("127.0.0.1", "/api/heavy").is_err());
        // Normal endpoint still allows many
        assert!(limiter.check("127.0.0.1", "/api/normal").is_ok());
    }

    #[test]
    fn test_path_matches() {
        assert!(path_matches("/sign-in", "/sign-in"));
        assert!(path_matches("/sign-in/email", "/sign-in"));
        assert!(path_matches("/api/anything", "/api/*"));
        assert!(!path_matches("/other", "/sign-in"));
    }

    #[test]
    fn test_cleanup() {
        let config = RateLimitConfig {
            enabled: true,
            window: 1, // 1 second window
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        limiter.check("127.0.0.1", "/test").ok();
        limiter.cleanup();

        // Entry should still be there (within 2x window)
        let store = limiter.store.lock().unwrap();
        assert_eq!(store.len(), 1);
    }
}
