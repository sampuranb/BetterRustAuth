// `better-auth init` — interactive project scaffolding.
// Enhanced with Cargo.toml dependency detection, Rust auth config generation,
// framework detection, and social provider setup.
// Maps to TS `commands/init.ts` (1,176 lines).

use std::path::PathBuf;

use clap::Args;
use colored::Colorize;

#[derive(Args)]
pub struct InitArgs {
    /// Working directory
    #[arg(short, long, default_value = ".")]
    cwd: PathBuf,

    /// Skip database setup
    #[arg(long)]
    skip_db: bool,

    /// Skip plugins selection
    #[arg(long)]
    skip_plugins: bool,

    /// Database type (sqlite, postgres, mysql)
    #[arg(long)]
    database: Option<String>,
}

const SUPPORTED_DATABASES: &[&str] = &["sqlite", "postgres", "mysql"];

const AVAILABLE_PLUGINS: &[PluginInfo] = &[
    PluginInfo { id: "two-factor", crate_name: "better-auth", feature: Some("two-factor") },
    PluginInfo { id: "admin", crate_name: "better-auth", feature: Some("admin") },
    PluginInfo { id: "organization", crate_name: "better-auth", feature: Some("organization") },
    PluginInfo { id: "jwt", crate_name: "better-auth", feature: Some("jwt") },
    PluginInfo { id: "username", crate_name: "better-auth", feature: Some("username") },
    PluginInfo { id: "anonymous", crate_name: "better-auth", feature: Some("anonymous") },
    PluginInfo { id: "magic-link", crate_name: "better-auth", feature: Some("magic-link") },
    PluginInfo { id: "email-otp", crate_name: "better-auth", feature: Some("email-otp") },
    PluginInfo { id: "phone-number", crate_name: "better-auth", feature: Some("phone-number") },
    PluginInfo { id: "bearer", crate_name: "better-auth", feature: Some("bearer") },
    PluginInfo { id: "one-tap", crate_name: "better-auth", feature: Some("one-tap") },
    PluginInfo { id: "captcha", crate_name: "better-auth", feature: Some("captcha") },
    PluginInfo { id: "siwe", crate_name: "better-auth", feature: Some("siwe") },
    PluginInfo { id: "oauth-proxy", crate_name: "better-auth", feature: Some("oauth-proxy") },
    PluginInfo { id: "generic-oauth", crate_name: "better-auth", feature: Some("generic-oauth") },
    PluginInfo { id: "multi-session", crate_name: "better-auth", feature: Some("multi-session") },
    PluginInfo { id: "oidc-provider", crate_name: "better-auth", feature: Some("oidc-provider") },
    PluginInfo { id: "open-api", crate_name: "better-auth", feature: Some("open-api") },
    PluginInfo { id: "mcp", crate_name: "better-auth", feature: Some("mcp") },
    PluginInfo { id: "passkey", crate_name: "better-auth-passkey", feature: None },
    PluginInfo { id: "sso", crate_name: "better-auth-sso", feature: None },
    PluginInfo { id: "stripe", crate_name: "better-auth-stripe", feature: None },
];

const SUPPORTED_FRAMEWORKS: &[&str] = &["axum", "actix-web", "leptos", "dioxus", "yew"];

const SOCIAL_PROVIDERS: &[&str] = &[
    "google",
    "github",
    "discord",
    "apple",
    "microsoft",
    "facebook",
    "twitter",
    "spotify",
    "twitch",
    "gitlab",
    "linkedin",
];

struct PluginInfo {
    id: &'static str,
    crate_name: &'static str,
    feature: Option<&'static str>,
}

pub fn run(args: InitArgs) -> Result<(), Box<dyn std::error::Error>> {
    let cwd = if args.cwd.is_relative() {
        std::env::current_dir()?.join(&args.cwd)
    } else {
        args.cwd.clone()
    };

    println!();
    println!("{}", "🔐 Better Auth — Project Setup".bold());
    println!("{}", "=".repeat(40).dimmed());
    println!();

    // 1. App name
    let app_name: String = dialoguer::Input::new()
        .with_prompt("App name")
        .default("my-app".to_string())
        .interact_text()?;

    // 2. Framework selection
    let framework_selection = dialoguer::Select::new()
        .with_prompt("Select web framework")
        .items(SUPPORTED_FRAMEWORKS)
        .default(0)
        .interact()?;
    let framework = SUPPORTED_FRAMEWORKS[framework_selection].to_string();

    // 3. Database selection
    let db_type = if args.skip_db {
        "sqlite".to_string()
    } else if let Some(ref db) = args.database {
        db.clone()
    } else {
        let selection = dialoguer::Select::new()
            .with_prompt("Select database")
            .items(SUPPORTED_DATABASES)
            .default(0)
            .interact()?;
        SUPPORTED_DATABASES[selection].to_string()
    };

    // 4. Plugin selection
    let selected_plugins: Vec<usize> = if args.skip_plugins {
        Vec::new()
    } else {
        let plugin_names: Vec<&str> = AVAILABLE_PLUGINS.iter().map(|p| p.id).collect();
        dialoguer::MultiSelect::new()
            .with_prompt("Select plugins (space to toggle, enter to confirm)")
            .items(&plugin_names)
            .interact()?
    };

    // 5. Social provider selection
    let selected_socials: Vec<usize> = {
        let should_setup = dialoguer::Confirm::new()
            .with_prompt("Would you like to configure social login providers?")
            .default(false)
            .interact()?;

        if should_setup {
            dialoguer::MultiSelect::new()
                .with_prompt("Select social providers (space to toggle)")
                .items(SOCIAL_PROVIDERS)
                .interact()?
        } else {
            Vec::new()
        }
    };

    // Generate secret
    let mut buf = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
    let secret = hex::encode(buf);

    // 6. Detect existing Cargo.toml
    let cargo_toml_path = cwd.join("Cargo.toml");
    let cargo_info = detect_cargo_toml(&cargo_toml_path);

    // 7. Generate configuration file
    let plugins: Vec<&str> = selected_plugins
        .iter()
        .map(|&i| AVAILABLE_PLUGINS[i].id)
        .collect();
    let socials: Vec<&str> = selected_socials
        .iter()
        .map(|&i| SOCIAL_PROVIDERS[i])
        .collect();
    let config = generate_config(&app_name, &db_type, &plugins, &socials, &secret, &framework);
    let config_path = cwd.join("better-auth.toml");

    // Check if config already exists
    if config_path.exists() {
        let overwrite = dialoguer::Confirm::new()
            .with_prompt("better-auth.toml already exists. Overwrite?")
            .default(false)
            .interact()?;

        if !overwrite {
            println!("Initialization cancelled.");
            return Ok(());
        }
    }

    std::fs::write(&config_path, &config)?;
    println!();
    println!("{} Config written to {}", "✓".green(), config_path.display());

    // 8. Generate .env file
    let env_path = cwd.join(".env");
    let mut env_content = format!(
        "# Better Auth\nBETTER_AUTH_SECRET={}\nDATABASE_URL={}\n",
        secret,
        default_db_url(&db_type)
    );

    // Add social provider env vars
    for social in &socials {
        let upper = social.to_uppercase();
        env_content.push_str(&format!(
            "\n# {} OAuth\n{}_CLIENT_ID=\n{}_CLIENT_SECRET=\n",
            social, upper, upper
        ));
    }

    if env_path.exists() {
        let append = dialoguer::Confirm::new()
            .with_prompt(".env already exists. Append Better Auth variables?")
            .default(true)
            .interact()?;

        if append {
            let mut existing = std::fs::read_to_string(&env_path)?;
            existing.push('\n');
            existing.push_str(&env_content);
            std::fs::write(&env_path, existing)?;
            println!("{} Variables appended to .env", "✓".green());
        }
    } else {
        std::fs::write(&env_path, &env_content)?;
        println!("{} .env file created", "✓".green());
    }

    // 9. Generate Rust auth config file
    let auth_rs = generate_auth_rs(&app_name, &db_type, &plugins, &framework, &socials);
    let auth_rs_path = cwd.join("src").join("auth.rs");
    if let Some(parent) = auth_rs_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if auth_rs_path.exists() {
        let overwrite = dialoguer::Confirm::new()
            .with_prompt("src/auth.rs already exists. Overwrite?")
            .default(false)
            .interact()?;

        if overwrite {
            std::fs::write(&auth_rs_path, &auth_rs)?;
            println!("{} Auth config written to {}", "✓".green(), auth_rs_path.display());
        }
    } else {
        std::fs::write(&auth_rs_path, &auth_rs)?;
        println!("{} Auth config written to {}", "✓".green(), auth_rs_path.display());
    }

    // 10. Show dependency recommendations
    println!();
    println!("{}", "📦 Dependencies:".bold().cyan());

    if cargo_info.has_better_auth {
        println!("  {} better-auth is already in Cargo.toml", "✓".green());
    } else {
        println!("  {} Add to Cargo.toml:", "→".yellow());
        println!("    {}", format!("better-auth = {{ version = \"*\", features = [\"{}\"{}] }}", 
            db_type,
            if selected_plugins.is_empty() { "" } else { ", ..." }
        ).yellow());
    }

    // Framework integration crate
    let framework_crate = match framework.as_str() {
        "axum" => Some("better-auth-axum"),
        "actix-web" => Some("better-auth-actix"),
        "leptos" => Some("better-auth-leptos"),
        "dioxus" => Some("better-auth-dioxus"),
        "yew" => Some("better-auth-yew"),
        _ => None,
    };
    if let Some(fw_crate) = framework_crate {
        if !cargo_info.has_framework_crate {
            println!("  {} Add framework integration:", "→".yellow());
            println!("    {}", format!("{} = \"*\"", fw_crate).yellow());
        }
    }

    // External plugin crates
    let external_crates: Vec<&str> = selected_plugins
        .iter()
        .filter_map(|&i| {
            let p = &AVAILABLE_PLUGINS[i];
            if p.crate_name != "better-auth" {
                Some(p.crate_name)
            } else {
                None
            }
        })
        .collect();
    if !external_crates.is_empty() {
        println!("  {} External plugin crates:", "→".yellow());
        for c in &external_crates {
            println!("    {}", format!("{} = \"*\"", c).yellow());
        }
    }

    // Feature flags
    let features: Vec<&str> = selected_plugins
        .iter()
        .filter_map(|&i| AVAILABLE_PLUGINS[i].feature)
        .collect();
    if !features.is_empty() {
        println!();
        println!("  {} Required features: {}", "ℹ".blue(), features.join(", ").cyan());
    }

    // Summary
    println!();
    println!("{}", "🥳 All Done, Happy Hacking!".bold().green());
    println!();
    println!("  {} {}", "App:".cyan(), app_name);
    println!("  {} {}", "Framework:".cyan(), framework);
    println!("  {} {}", "Database:".cyan(), db_type);
    if !plugins.is_empty() {
        println!("  {} {}", "Plugins:".cyan(), plugins.join(", "));
    }
    if !socials.is_empty() {
        println!("  {} {}", "Social:".cyan(), socials.join(", "));
    }
    println!("  {} {}", "Config:".cyan(), config_path.display());
    println!("  {} {}", "Auth RS:".cyan(), auth_rs_path.display());
    println!();
    println!("{}", "Next steps:".bold());
    println!("  1. Review your better-auth.toml configuration");
    println!("  2. Add the recommended dependencies to Cargo.toml");
    println!("  3. Run {} to create database tables", "better-auth migrate".yellow());
    println!("  4. Import the auth module in your application");
    println!();

    Ok(())
}

fn generate_config(
    app_name: &str,
    db_type: &str,
    plugins: &[&str],
    socials: &[&str],
    secret: &str,
    framework: &str,
) -> String {
    let mut config = String::new();
    config.push_str(&format!("# Better Auth Configuration — {}\n\n", app_name));

    config.push_str("[app]\n");
    config.push_str(&format!("name = \"{}\"\n", app_name));
    config.push_str(&format!("secret = \"{}\"\n", secret));
    config.push_str(&format!("framework = \"{}\"\n", framework));
    config.push_str("# base_url = \"http://localhost:3000\"\n");
    config.push('\n');

    config.push_str("[database]\n");
    config.push_str(&format!("type = \"{}\"\n", db_type));
    config.push_str(&format!("url = \"{}\"\n", default_db_url(db_type)));
    config.push('\n');

    config.push_str("[session]\n");
    config.push_str("# max_age = 604800  # 7 days in seconds\n");
    config.push_str("# update_age = 86400  # 1 day in seconds\n");
    config.push('\n');

    if !plugins.is_empty() {
        config.push_str("[plugins]\n");
        for plugin in plugins {
            config.push_str(&format!("{} = true\n", plugin));
        }
        config.push('\n');
    }

    config.push_str("[email_and_password]\n");
    config.push_str("enabled = true\n");
    config.push_str("# min_password_length = 8\n");
    config.push_str("# max_password_length = 128\n");
    config.push('\n');

    if !socials.is_empty() {
        config.push_str("[social_providers]\n");
        for social in socials {
            config.push_str(&format!("[social_providers.{}]\n", social));
            let upper = social.to_uppercase();
            config.push_str(&format!("client_id = \"${{{}_CLIENT_ID}}\"\n", upper));
            config.push_str(&format!("client_secret = \"${{{}_CLIENT_SECRET}}\"\n", upper));
            config.push('\n');
        }
    } else {
        config.push_str("# [social_providers]\n");
        config.push_str("# [social_providers.google]\n");
        config.push_str("# client_id = \"\"\n");
        config.push_str("# client_secret = \"\"\n");
    }

    config
}

fn generate_auth_rs(
    _app_name: &str,
    db_type: &str,
    plugins: &[&str],
    framework: &str,
    socials: &[&str],
) -> String {
    let mut code = String::new();
    code.push_str("//! Better Auth configuration (auto-generated)\n");
    code.push_str("//! Customize this file to match your application's needs.\n\n");

    code.push_str("use better_auth::BetterAuthOptions;\n");
    code.push_str("use better_auth_core::db::schema::AuthSchema;\n");

    // Framework-specific import
    match framework {
        "axum" => code.push_str("use better_auth_axum::BetterAuthAxum;\n"),
        "actix-web" => code.push_str("use better_auth_actix::BetterAuthActix;\n"),
        _ => {}
    }
    code.push('\n');

    // Auth setup function
    code.push_str("/// Create and configure the Better Auth instance.\n");
    code.push_str("pub fn create_auth() -> BetterAuthOptions {\n");
    code.push_str("    let mut options = BetterAuthOptions::default();\n");
    code.push('\n');
    code.push_str(&format!(
        "    // Database: {}\n",
        db_type
    ));
    code.push_str(&format!(
        "    options.database_url = std::env::var(\"DATABASE_URL\")\n        .unwrap_or_else(|_| \"{}\".to_string());\n\n",
        default_db_url(db_type)
    ));

    // Secret
    code.push_str("    // Auth secret\n");
    code.push_str("    options.secret = std::env::var(\"BETTER_AUTH_SECRET\")\n");
    code.push_str("        .expect(\"BETTER_AUTH_SECRET must be set\");\n\n");

    // Social providers
    if !socials.is_empty() {
        code.push_str("    // Social providers\n");
        for social in socials {
            let upper = social.to_uppercase();
            code.push_str(&format!(
                "    // options.add_social_provider(\"{}\", \n",
                social
            ));
            code.push_str(&format!(
                "    //     std::env::var(\"{}_CLIENT_ID\").unwrap(),\n",
                upper
            ));
            code.push_str(&format!(
                "    //     std::env::var(\"{}_CLIENT_SECRET\").unwrap(),\n",
                upper
            ));
            code.push_str("    // );\n");
        }
        code.push('\n');
    }

    // Plugins
    if !plugins.is_empty() {
        code.push_str("    // Plugins\n");
        for plugin in plugins {
            code.push_str(&format!("    // options.enable_plugin(\"{}\");\n", plugin));
        }
        code.push('\n');
    }

    code.push_str("    options\n");
    code.push_str("}\n");

    code
}

/// Cargo.toml detection info.
struct CargoInfo {
    has_better_auth: bool,
    has_framework_crate: bool,
}

fn detect_cargo_toml(path: &PathBuf) -> CargoInfo {
    if !path.exists() {
        return CargoInfo {
            has_better_auth: false,
            has_framework_crate: false,
        };
    }

    let content = std::fs::read_to_string(path).unwrap_or_default();

    CargoInfo {
        has_better_auth: content.contains("better-auth"),
        has_framework_crate: content.contains("better-auth-axum")
            || content.contains("better-auth-actix")
            || content.contains("better-auth-leptos")
            || content.contains("better-auth-dioxus")
            || content.contains("better-auth-yew"),
    }
}

fn default_db_url(db_type: &str) -> &str {
    match db_type {
        "sqlite" => "sqlite://better-auth.db",
        "postgres" => "postgres://localhost:5432/better_auth",
        "mysql" => "mysql://localhost:3306/better_auth",
        _ => "sqlite://better-auth.db",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_config_basic() {
        let config = generate_config("test-app", "sqlite", &[], &[], "secret123", "axum");
        assert!(config.contains("name = \"test-app\""));
        assert!(config.contains("type = \"sqlite\""));
        assert!(config.contains("framework = \"axum\""));
        assert!(config.contains("secret = \"secret123\""));
    }

    #[test]
    fn test_generate_config_with_plugins() {
        let config = generate_config("app", "postgres", &["admin", "jwt"], &[], "s", "axum");
        assert!(config.contains("[plugins]"));
        assert!(config.contains("admin = true"));
        assert!(config.contains("jwt = true"));
    }

    #[test]
    fn test_generate_config_with_socials() {
        let config = generate_config("app", "sqlite", &[], &["google", "github"], "s", "axum");
        assert!(config.contains("[social_providers.google]"));
        assert!(config.contains("[social_providers.github]"));
        assert!(config.contains("GOOGLE_CLIENT_ID"));
        assert!(config.contains("GITHUB_CLIENT_SECRET"));
    }

    #[test]
    fn test_generate_auth_rs() {
        let code = generate_auth_rs("app", "postgres", &["admin"], "axum", &["google"]);
        assert!(code.contains("use better_auth::BetterAuthOptions"));
        assert!(code.contains("use better_auth_axum::BetterAuthAxum"));
        assert!(code.contains("DATABASE_URL"));
        assert!(code.contains("BETTER_AUTH_SECRET"));
        assert!(code.contains("google"));
        assert!(code.contains("admin"));
    }

    #[test]
    fn test_detect_cargo_toml_missing() {
        let info = detect_cargo_toml(&PathBuf::from("/nonexistent/Cargo.toml"));
        assert!(!info.has_better_auth);
        assert!(!info.has_framework_crate);
    }

    #[test]
    fn test_default_db_url() {
        assert_eq!(default_db_url("sqlite"), "sqlite://better-auth.db");
        assert_eq!(default_db_url("postgres"), "postgres://localhost:5432/better_auth");
        assert_eq!(default_db_url("mysql"), "mysql://localhost:3306/better_auth");
    }
}
