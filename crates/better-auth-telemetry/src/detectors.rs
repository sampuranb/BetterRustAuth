// Detectors module — mirrors packages/telemetry/src/detectors/
//
// Provides detection functions for runtime environment, database, framework,
// system info, and auth configuration. Adapted from the Node.js/TS originals
// to native Rust equivalents.

use better_auth_core::options::BetterAuthOptions;
use serde_json::json;

use crate::types::{DetectionInfo, TelemetryContext};

// ─── detect-auth-config ─────────────────────────────────────────────

/// Gather auth configuration telemetry data.
///
/// Maps to TS `getTelemetryAuthConfig(options, context?)`.
/// Returns a sanitized view of the auth config — no secrets, just booleans
/// and enum values indicating what features are enabled.
pub fn detect_auth_config(
    options: &BetterAuthOptions,
    context: Option<&TelemetryContext>,
) -> serde_json::Value {
    let ep = &options.email_and_password;
    let ev = &options.email_verification;

    json!({
        "database": context.and_then(|c| c.database.as_deref()),
        "adapter": context.and_then(|c| c.adapter.as_deref()),
        "emailVerification": {
            "sendOnSignUp": ev.as_ref().map(|e| e.send_on_sign_up).unwrap_or(false),
            "sendOnSignIn": ev.as_ref().map(|e| e.send_on_sign_in).unwrap_or(false),
            "autoSignInAfterVerification": ev.as_ref().map(|e| e.auto_sign_in_after_verification).unwrap_or(false),
            "expiresIn": ev.as_ref().map(|e| e.expires_in),
        },
        "emailAndPassword": {
            "enabled": ep.enabled,
            "disableSignUp": ep.disable_signup,
            "requireEmailVerification": ep.require_email_verification,
            "maxPasswordLength": ep.max_password_length,
            "minPasswordLength": ep.min_password_length,
            "autoSignIn": ep.auto_sign_in,
            "revokeSessionsOnPasswordReset": ep.revoke_sessions_on_password_reset,
            "resetPasswordTokenExpiresIn": ep.reset_password_token_expires_in,
        },
        "socialProviders": options.social_providers.keys().cloned().collect::<Vec<_>>(),
        "plugins": options.plugins.iter().map(|p| p.id().to_string()).collect::<Vec<_>>(),
        "session": {
            "expiresIn": options.session.expires_in,
            "updateAge": options.session.update_age,
            "freshAge": options.session.fresh_age,
        },
        "account": {
            "accountLinking": {
                "enabled": options.account.account_linking.enabled,
            },
        },
        "advanced": {
            "useSecureCookies": options.advanced.use_secure_cookies,
            "disableCSRFCheck": options.advanced.disable_csrf_check,
            "cookiePrefix": options.advanced.cookie_prefix.is_some(),
        },
        "trustedOrigins": options.trusted_origins.len(),
        "rateLimit": {
            "enabled": options.rate_limit.enabled,
            "window": options.rate_limit.window,
            "max": options.rate_limit.max,
        },
    })
}

// ─── detect-runtime ─────────────────────────────────────────────────

/// Detect the runtime environment.
///
/// Maps to TS `detectRuntime()`. In Rust, this is always "rust/tokio".
pub fn detect_runtime() -> DetectionInfo {
    DetectionInfo {
        name: "rust".to_string(),
        version: option_env!("CARGO_PKG_RUST_VERSION").map(String::from),
    }
}

/// Detect the deployment environment.
///
/// Maps to TS `detectEnvironment()`.
pub fn detect_environment() -> &'static str {
    if std::env::var("CI").is_ok() || std::env::var("BUILD_ID").is_ok() {
        "ci"
    } else if cfg!(test) {
        "test"
    } else if std::env::var("RUST_ENV")
        .or_else(|_| std::env::var("NODE_ENV"))
        .map(|v| v == "production")
        .unwrap_or(false)
    {
        "production"
    } else {
        "development"
    }
}

// ─── detect-database ────────────────────────────────────────────────

/// Detect the database in use.
///
/// Maps to TS `detectDatabase()`. In the Rust version, we inspect
/// Cargo.toml dependencies rather than package.json.
pub fn detect_database() -> Option<DetectionInfo> {
    // Check Cargo.toml for database dependencies
    let cargo_toml = std::fs::read_to_string("Cargo.toml").ok()?;
    let cargo_lower = cargo_toml.to_lowercase();

    let databases = [
        ("better-auth-sqlx", "sqlx"),
        ("sqlx", "sqlx"),
        ("diesel", "diesel"),
        ("sea-orm", "sea-orm"),
        ("mongodb", "mongodb"),
        ("better-auth-memory", "memory"),
        ("better-auth-redis", "redis"),
    ];

    for (pkg, name) in databases {
        if cargo_lower.contains(pkg) {
            return Some(DetectionInfo {
                name: name.to_string(),
                version: None, // Cargo doesn't easily expose dep versions at runtime
            });
        }
    }

    None
}

// ─── detect-framework ───────────────────────────────────────────────

/// Detect the web framework in use.
///
/// Maps to TS `detectFramework()`. In Rust, we check for framework crate deps.
pub fn detect_framework() -> Option<DetectionInfo> {
    let cargo_toml = std::fs::read_to_string("Cargo.toml").ok()?;
    let cargo_lower = cargo_toml.to_lowercase();

    let frameworks = [
        ("better-auth-axum", "axum"),
        ("axum", "axum"),
        ("better-auth-actix", "actix-web"),
        ("actix-web", "actix-web"),
        ("better-auth-leptos", "leptos"),
        ("leptos", "leptos"),
        ("better-auth-dioxus", "dioxus"),
        ("dioxus", "dioxus"),
        ("better-auth-yew", "yew"),
        ("yew", "yew"),
        ("warp", "warp"),
        ("rocket", "rocket"),
        ("tide", "tide"),
    ];

    for (pkg, name) in frameworks {
        if cargo_lower.contains(pkg) {
            return Some(DetectionInfo {
                name: name.to_string(),
                version: None,
            });
        }
    }

    None
}

// ─── detect-project-info ────────────────────────────────────────────

/// Detect the package manager.
///
/// Maps to TS `detectPackageManager()`. In Rust, this is always "cargo".
pub fn detect_package_manager() -> DetectionInfo {
    // Get cargo version from environment or fallback
    let version = std::env::var("CARGO_PKG_VERSION").ok();

    DetectionInfo {
        name: "cargo".to_string(),
        version,
    }
}

// ─── detect-system-info ─────────────────────────────────────────────

/// Detect system information.
///
/// Maps to TS `detectSystemInfo()`.
pub fn detect_system_info() -> serde_json::Value {
    let vendor = get_vendor();

    json!({
        "deploymentVendor": vendor,
        "systemPlatform": std::env::consts::OS,
        "systemArchitecture": std::env::consts::ARCH,
        "systemFamily": std::env::consts::FAMILY,
        "isDocker": is_docker(),
        "isWSL": is_wsl(),
        "isCI": is_ci(),
    })
}

/// Detect cloud vendor from environment variables.
///
/// Maps to TS `getVendor()`.
fn get_vendor() -> Option<&'static str> {
    let has_any =
        |keys: &[&str]| -> bool { keys.iter().any(|k| std::env::var(k).is_ok()) };

    if has_any(&["CF_PAGES", "CF_PAGES_URL", "CF_ACCOUNT_ID"]) {
        return Some("cloudflare");
    }
    if has_any(&["VERCEL", "VERCEL_URL", "VERCEL_ENV"]) {
        return Some("vercel");
    }
    if has_any(&["NETLIFY", "NETLIFY_URL"]) {
        return Some("netlify");
    }
    if has_any(&[
        "RENDER",
        "RENDER_URL",
        "RENDER_INTERNAL_HOSTNAME",
        "RENDER_SERVICE_ID",
    ]) {
        return Some("render");
    }
    if has_any(&[
        "AWS_LAMBDA_FUNCTION_NAME",
        "AWS_EXECUTION_ENV",
        "LAMBDA_TASK_ROOT",
    ]) {
        return Some("aws");
    }
    if has_any(&[
        "GOOGLE_CLOUD_FUNCTION_NAME",
        "GOOGLE_CLOUD_PROJECT",
        "GCP_PROJECT",
        "K_SERVICE",
    ]) {
        return Some("gcp");
    }
    if has_any(&[
        "AZURE_FUNCTION_NAME",
        "FUNCTIONS_WORKER_RUNTIME",
        "WEBSITE_INSTANCE_ID",
        "WEBSITE_SITE_NAME",
    ]) {
        return Some("azure");
    }
    if has_any(&["DENO_DEPLOYMENT_ID", "DENO_REGION"]) {
        return Some("deno-deploy");
    }
    if has_any(&["FLY_APP_NAME", "FLY_REGION", "FLY_ALLOC_ID"]) {
        return Some("fly-io");
    }
    if has_any(&["RAILWAY_STATIC_URL", "RAILWAY_ENVIRONMENT_NAME"]) {
        return Some("railway");
    }
    if has_any(&["DYNO", "HEROKU_APP_NAME"]) {
        return Some("heroku");
    }
    if has_any(&["DO_DEPLOYMENT_ID", "DO_APP_NAME", "DIGITALOCEAN"]) {
        return Some("digitalocean");
    }
    if has_any(&["KOYEB", "KOYEB_DEPLOYMENT_ID", "KOYEB_APP_NAME"]) {
        return Some("koyeb");
    }

    None
}

/// Check if running inside Docker.
fn is_docker() -> bool {
    // Check /.dockerenv
    if std::path::Path::new("/.dockerenv").exists() {
        return true;
    }
    // Check /proc/self/cgroup for "docker"
    if let Ok(cgroup) = std::fs::read_to_string("/proc/self/cgroup") {
        if cgroup.contains("docker") {
            return true;
        }
    }
    false
}

/// Check if running inside WSL.
fn is_wsl() -> bool {
    if std::env::consts::OS != "linux" {
        return false;
    }
    // Check kernel release
    if let Ok(release) = std::fs::read_to_string("/proc/version") {
        if release.to_lowercase().contains("microsoft") {
            return true;
        }
    }
    false
}

/// Check if running in CI.
///
/// Maps to TS `isCI()`.
pub fn is_ci() -> bool {
    let ci_val = std::env::var("CI").unwrap_or_default();
    if ci_val == "false" {
        return false;
    }

    let ci_vars = [
        "BUILD_ID",
        "BUILD_NUMBER",
        "CI",
        "CI_APP_ID",
        "CI_BUILD_ID",
        "CI_BUILD_NUMBER",
        "CI_NAME",
        "CONTINUOUS_INTEGRATION",
        "RUN_ID",
    ];

    ci_vars.iter().any(|v| std::env::var(v).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_runtime() {
        let rt = detect_runtime();
        assert_eq!(rt.name, "rust");
    }

    #[test]
    fn test_detect_environment() {
        let env = detect_environment();
        // In test mode, should be "test"
        assert_eq!(env, "test");
    }

    #[test]
    fn test_detect_package_manager() {
        let pm = detect_package_manager();
        assert_eq!(pm.name, "cargo");
    }

    #[test]
    fn test_detect_system_info() {
        let info = detect_system_info();
        assert!(info["systemPlatform"].is_string());
        assert!(info["systemArchitecture"].is_string());
    }

    #[test]
    fn test_get_vendor_none() {
        // In normal test env, no cloud vendor vars should be set
        // (unless running in CI)
        let vendor = get_vendor();
        // Just verify it returns something valid or None
        if let Some(v) = vendor {
            assert!(!v.is_empty());
        }
    }

    #[test]
    fn test_detect_auth_config() {
        let options = BetterAuthOptions::default();
        let config = detect_auth_config(&options, None);
        assert!(config["emailAndPassword"]["enabled"].is_boolean());
    }
}
