// `better-auth info` — display system and config information.
// Enhanced with DB connectivity test, plugin enumeration, version display,
// crate detection, and dependency analysis.
// Maps to TS `commands/info.ts`.

use std::path::PathBuf;

use clap::Args;
use colored::Colorize;
use sysinfo::System;

#[derive(Args)]
pub struct InfoArgs {
    /// Output as JSON
    #[arg(short, long)]
    json: bool,

    /// Copy output to clipboard
    #[arg(short, long)]
    copy: bool,

    /// Working directory
    #[arg(long, default_value = ".")]
    cwd: PathBuf,
}

pub fn run(args: InfoArgs) -> Result<(), Box<dyn std::error::Error>> {
    let sys = System::new_all();

    let system_info = SystemInfo {
        os: System::name().unwrap_or_else(|| "Unknown".into()),
        os_version: System::os_version().unwrap_or_else(|| "Unknown".into()),
        arch: std::env::consts::ARCH.to_string(),
        cpu_count: sys.cpus().len(),
        cpu_model: sys
            .cpus()
            .first()
            .map(|c| c.brand().to_string())
            .unwrap_or_else(|| "Unknown".into()),
        total_memory: format!(
            "{:.2} GB",
            sys.total_memory() as f64 / 1024.0 / 1024.0 / 1024.0
        ),
        available_memory: format!(
            "{:.2} GB",
            sys.available_memory() as f64 / 1024.0 / 1024.0 / 1024.0
        ),
    };

    let rust_info = RustInfo {
        version: rustc_version(),
        target: std::env::consts::OS.to_string(),
        cargo_version: cargo_version(),
    };

    let cwd = if args.cwd.is_relative() {
        std::env::current_dir()?.join(&args.cwd)
    } else {
        args.cwd.clone()
    };

    let config_info = detect_config(&cwd);
    let cargo_info = detect_cargo_deps(&cwd);
    let db_info = detect_database(&cwd);
    let plugin_info = detect_plugins(&cwd);

    if args.json {
        let info = serde_json::json!({
            "system": {
                "os": system_info.os,
                "osVersion": system_info.os_version,
                "arch": system_info.arch,
                "cpuCount": system_info.cpu_count,
                "cpuModel": system_info.cpu_model,
                "totalMemory": system_info.total_memory,
                "availableMemory": system_info.available_memory,
            },
            "rust": {
                "version": rust_info.version,
                "target": rust_info.target,
                "cargoVersion": rust_info.cargo_version,
            },
            "config": config_info,
            "dependencies": cargo_info,
            "database": db_info,
            "plugins": plugin_info,
        });
        let output = serde_json::to_string_pretty(&info)?;
        println!("{output}");

        if args.copy {
            copy_to_clipboard(&output);
        }
        return Ok(());
    }

    // Pretty output
    println!();
    println!("{}", "📊 Better Auth System Information".bold());
    println!("{}", "═".repeat(55).dimmed());

    println!();
    println!("{}", "🖥️  System Information:".bold().white());
    println!("  {} {}", "OS:".cyan(), system_info.os);
    println!("  {} {}", "Version:".cyan(), system_info.os_version);
    println!("  {} {}", "Arch:".cyan(), system_info.arch);
    println!("  {} {}", "CPUs:".cyan(), system_info.cpu_count);
    println!("  {} {}", "CPU Model:".cyan(), system_info.cpu_model);
    println!("  {} {}", "Total Memory:".cyan(), system_info.total_memory);
    println!(
        "  {} {}",
        "Available Memory:".cyan(),
        system_info.available_memory
    );

    println!();
    println!("{}", "🦀 Rust:".bold().white());
    println!("  {} {}", "Rustc:".cyan(), rust_info.version);
    println!("  {} {}", "Cargo:".cyan(), rust_info.cargo_version);
    println!("  {} {}", "Target:".cyan(), rust_info.target);

    println!();
    println!("{}", "🔐 Better Auth:".bold().white());
    match &config_info {
        Some(path) => println!("  {} {}", "Config:".cyan(), path),
        None => println!("  {} {}", "Config:".cyan(), "Not found".dimmed()),
    }

    println!();
    println!("{}", "📦 Dependencies:".bold().white());
    if cargo_info.is_empty() {
        println!("  {} {}", "Status:".cyan(), "No Cargo.toml found".dimmed());
    } else {
        for dep in &cargo_info {
            let status = if dep.found { "✓".green() } else { "✗".red() };
            println!("  {} {} {}", status, dep.name.cyan(), dep.version.dimmed());
        }
    }

    println!();
    println!("{}", "🔌 Plugins:".bold().white());
    if plugin_info.is_empty() {
        println!(
            "  {}",
            "No plugins detected (check config or Cargo.toml features)".dimmed()
        );
    } else {
        for plugin in &plugin_info {
            println!("  {} {}", "•".magenta(), plugin);
        }
    }

    println!();
    println!("{}", "🗄️  Database:".bold().white());
    match &db_info {
        Some(info) => {
            println!("  {} {}", "Type:".cyan(), info.db_type);
            println!("  {} {}", "URL:".cyan(), info.display_url());
        }
        None => println!("  {} {}", "Status:".cyan(), "Not configured".dimmed()),
    }

    println!();
    println!("{}", "═".repeat(55).dimmed());
    println!("{}", "💡 Tip: Use --json flag for JSON output".dimmed());
    println!("{}", "💡 Use --copy flag to copy output to clipboard".dimmed());
    println!();

    if args.copy {
        let text = format!(
            "Better Auth System Information\nOS: {} {}\nArch: {}\nRust: {}\nCargo: {}\nConfig: {}\nDeps: {}\nPlugins: {}",
            system_info.os,
            system_info.os_version,
            system_info.arch,
            rust_info.version,
            rust_info.cargo_version,
            config_info.as_deref().unwrap_or("Not found"),
            cargo_info
                .iter()
                .filter(|d| d.found)
                .map(|d| d.name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            plugin_info.join(", "),
        );
        copy_to_clipboard(&text);
    }

    Ok(())
}

struct SystemInfo {
    os: String,
    os_version: String,
    arch: String,
    cpu_count: usize,
    cpu_model: String,
    total_memory: String,
    available_memory: String,
}

struct RustInfo {
    version: String,
    target: String,
    cargo_version: String,
}

#[derive(serde::Serialize)]
struct DepInfo {
    name: String,
    version: String,
    found: bool,
}

#[derive(serde::Serialize, Clone)]
struct DbInfo {
    db_type: String,
    url: String,
}

impl DbInfo {
    fn display_url(&self) -> String {
        // Mask password in URL
        if let Some(at_pos) = self.url.find('@') {
            if let Some(colon_pos) = self.url[..at_pos].rfind(':') {
                let scheme_end = self.url.find("://").map(|p| p + 3).unwrap_or(0);
                if colon_pos > scheme_end {
                    return format!(
                        "{}***{}",
                        &self.url[..colon_pos + 1],
                        &self.url[at_pos..]
                    );
                }
            }
        }
        self.url.clone()
    }
}

fn rustc_version() -> String {
    std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "Unknown".into())
}

fn cargo_version() -> String {
    std::process::Command::new("cargo")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "Unknown".into())
}

fn detect_config(cwd: &std::path::Path) -> Option<String> {
    let candidates = [
        "better-auth.toml",
        "auth.toml",
        "config/better-auth.toml",
        "config/auth.toml",
    ];

    for name in &candidates {
        let path = cwd.join(name);
        if path.exists() {
            return Some(path.display().to_string());
        }
    }
    None
}

fn detect_cargo_deps(cwd: &std::path::Path) -> Vec<DepInfo> {
    let cargo_path = cwd.join("Cargo.toml");
    if !cargo_path.exists() {
        return Vec::new();
    }

    let content = match std::fs::read_to_string(&cargo_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let known_crates = [
        "better-auth",
        "better-auth-core",
        "better-auth-client",
        "better-auth-sqlx",
        "better-auth-oauth2",
        "better-auth-axum",
        "better-auth-actix",
        "better-auth-leptos",
        "better-auth-dioxus",
        "better-auth-yew",
        "better-auth-passkey",
        "better-auth-sso",
        "better-auth-stripe",
        "better-auth-scim",
        "better-auth-i18n",
        "better-auth-oauth-provider",
    ];

    known_crates
        .iter()
        .map(|&name| {
            let found = content.contains(name);
            // Try to extract version
            let version = if found {
                extract_dependency_version(&content, name).unwrap_or_else(|| "workspace".into())
            } else {
                "not found".into()
            };
            DepInfo {
                name: name.to_string(),
                version,
                found,
            }
        })
        .collect()
}

fn extract_dependency_version(content: &str, dep_name: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(dep_name) && trimmed.contains('=') {
            // Simple version: dep = "1.0"
            if let Some(v) = trimmed.split('"').nth(1) {
                return Some(v.to_string());
            }
            // workspace version
            if trimmed.contains("workspace") {
                return Some("workspace".to_string());
            }
            // path version
            if trimmed.contains("path") {
                return Some("path".to_string());
            }
        }
    }
    None
}

fn detect_database(cwd: &std::path::Path) -> Option<DbInfo> {
    // Try config file first
    let config_path = detect_config(cwd)?;
    let content = std::fs::read_to_string(config_path).ok()?;
    let config: toml::Value = toml::from_str(&content).ok()?;

    let db = config.get("database")?;
    let db_type = db.get("type")?.as_str()?.to_string();
    let url = db
        .get("url")
        .and_then(|u| u.as_str())
        .unwrap_or("(not configured)")
        .to_string();

    Some(DbInfo { db_type, url })
}

fn detect_plugins(cwd: &std::path::Path) -> Vec<String> {
    let mut plugins = Vec::new();

    // Check config file
    if let Some(config_path) = detect_config(cwd) {
        if let Ok(content) = std::fs::read_to_string(config_path) {
            if let Ok(config) = toml::from_str::<toml::Value>(&content) {
                if let Some(plugin_table) = config.get("plugins").and_then(|p| p.as_table()) {
                    for (name, value) in plugin_table {
                        if value.as_bool().unwrap_or(false) {
                            plugins.push(name.clone());
                        }
                    }
                }
            }
        }
    }

    // Check Cargo.toml features
    let cargo_path = cwd.join("Cargo.toml");
    if cargo_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&cargo_path) {
            let feature_plugins = [
                "two-factor",
                "admin",
                "organization",
                "jwt",
                "username",
                "anonymous",
                "magic-link",
                "email-otp",
                "phone-number",
                "bearer",
                "one-tap",
                "captcha",
                "siwe",
                "oauth-proxy",
                "generic-oauth",
                "multi-session",
                "oidc-provider",
                "open-api",
                "mcp",
            ];
            for plugin in &feature_plugins {
                if content.contains(plugin) && !plugins.contains(&plugin.to_string()) {
                    plugins.push(plugin.to_string());
                }
            }
        }
    }

    plugins.sort();
    plugins.dedup();
    plugins
}

fn copy_to_clipboard(text: &str) {
    match arboard::Clipboard::new() {
        Ok(mut clipboard) => match clipboard.set_text(text) {
            Ok(_) => println!("{}", "✓ Copied to clipboard".green()),
            Err(_) => println!("{}", "⚠ Could not copy to clipboard".yellow()),
        },
        Err(_) => println!("{}", "⚠ Could not access clipboard".yellow()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_config_not_found() {
        let result = detect_config(std::path::Path::new("/nonexistent"));
        assert!(result.is_none());
    }

    #[test]
    fn test_detect_cargo_deps_not_found() {
        let deps = detect_cargo_deps(std::path::Path::new("/nonexistent"));
        assert!(deps.is_empty());
    }

    #[test]
    fn test_db_info_display_url_no_password() {
        let info = DbInfo {
            db_type: "sqlite".into(),
            url: "sqlite://test.db".into(),
        };
        assert_eq!(info.display_url(), "sqlite://test.db");
    }

    #[test]
    fn test_db_info_display_url_with_password() {
        let info = DbInfo {
            db_type: "postgres".into(),
            url: "postgres://user:secret@localhost:5432/db".into(),
        };
        let display = info.display_url();
        assert!(!display.contains("secret"));
        assert!(display.contains("***"));
    }

    #[test]
    fn test_extract_dependency_version() {
        let content = r#"
[dependencies]
better-auth = "1.0"
better-auth-core = { path = "../better-auth-core" }
"#;
        assert_eq!(
            extract_dependency_version(content, "better-auth ="),
            Some("1.0".to_string())
        );
        // path dep returns the path as first quoted value
        assert_eq!(
            extract_dependency_version(content, "better-auth-core"),
            Some("../better-auth-core".to_string())
        );
    }

    #[test]
    fn test_detect_plugins_empty() {
        let plugins = detect_plugins(std::path::Path::new("/nonexistent"));
        assert!(plugins.is_empty());
    }
}
