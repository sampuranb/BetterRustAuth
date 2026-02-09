// `better-auth login` — device authorization flow for CLI authentication.
// Maps to TS `commands/login.ts` (276 lines).

use std::path::PathBuf;

use clap::Args;
use colored::Colorize;

const DEMO_URL: &str = "https://demo.better-auth.com";
const CLIENT_ID: &str = "better-auth-cli";

#[derive(Args)]
pub struct LoginArgs {
    /// The Better Auth server URL
    #[arg(long, default_value = DEMO_URL)]
    server_url: String,

    /// The OAuth client ID
    #[arg(long, default_value = CLIENT_ID)]
    client_id: String,
}

/// Get the config directory for storing tokens.
fn config_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".better-auth")
}

/// Get the token file path.
fn token_file() -> PathBuf {
    config_dir().join("token.json")
}

/// Stored token data.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct StoredToken {
    access_token: String,
    token_type: String,
    scope: Option<String>,
    created_at: String,
}

/// Store a token to disk.
fn store_token(token: &StoredToken) -> Result<(), Box<dyn std::error::Error>> {
    let dir = config_dir();
    std::fs::create_dir_all(&dir)?;
    let data = serde_json::to_string_pretty(token)?;
    std::fs::write(token_file(), data)?;
    Ok(())
}

/// Get a stored token from disk.
fn get_stored_token() -> Option<StoredToken> {
    let path = token_file();
    if !path.exists() {
        return None;
    }
    let data = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&data).ok()
}

/// Device authorization response.
#[derive(serde::Deserialize, Debug)]
struct DeviceAuthResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    #[serde(default = "default_interval")]
    interval: u64,
    expires_in: u64,
}

fn default_interval() -> u64 { 5 }

/// Token response from polling.
#[derive(serde::Deserialize, Debug)]
struct TokenResponse {
    access_token: Option<String>,
    token_type: Option<String>,
    scope: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

pub fn run(args: LoginArgs) -> Result<(), Box<dyn std::error::Error>> {
    println!();
    println!("{}", "🔐 Better Auth CLI Login (Demo)".bold());
    println!();
    println!("{}", "⚠️  This is a demo feature for testing device authorization flow.".yellow());
    println!("{}", "   It connects to the Better Auth demo server for testing purposes.".dimmed());
    println!();

    // Check if already logged in
    if let Some(_existing) = get_stored_token() {
        let reauth = dialoguer::Confirm::new()
            .with_prompt("You're already logged in. Do you want to log in again?")
            .default(false)
            .interact()?;

        if !reauth {
            println!("Login cancelled.");
            return Ok(());
        }
    }

    // Request device code using blocking reqwest
    let spinner = indicatif::ProgressBar::new_spinner();
    spinner.set_message("Requesting device authorization...");
    spinner.enable_steady_tick(std::time::Duration::from_millis(80));

    let client = reqwest::blocking::Client::new();
    let response = client
        .post(format!("{}/api/auth/device-authorization/authorize", args.server_url))
        .form(&[
            ("client_id", args.client_id.as_str()),
            ("scope", "openid profile email"),
        ])
        .send()?;

    spinner.finish_and_clear();

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_default();
        return Err(format!("Device authorization failed ({}): {}", status, body).into());
    }

    let device_auth: DeviceAuthResponse = response.json()?;

    // Display authorization instructions
    println!();
    println!("{}", "📱 Device Authorization Required".cyan());
    println!();
    println!("  Please visit: {}", device_auth.verification_uri.underline().blue());
    println!("  Enter code:   {}", device_auth.user_code.bold().green());
    println!();

    // Ask if user wants to open browser
    let should_open = dialoguer::Confirm::new()
        .with_prompt("Open browser automatically?")
        .default(true)
        .interact()?;

    if should_open {
        let url = device_auth.verification_uri_complete
            .as_deref()
            .unwrap_or(&device_auth.verification_uri);
        let _ = open::that(url);
    }

    // Start polling
    println!(
        "{}",
        format!(
            "Waiting for authorization (expires in {} minutes)...",
            device_auth.expires_in / 60
        ).dimmed()
    );

    let polling_interval = std::time::Duration::from_secs(device_auth.interval);
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_secs(device_auth.expires_in);

    let poll_spinner = indicatif::ProgressBar::new_spinner();
    poll_spinner.enable_steady_tick(std::time::Duration::from_millis(120));

    loop {
        if std::time::Instant::now() > deadline {
            poll_spinner.finish_and_clear();
            return Err("Device code expired. Please try again.".into());
        }

        std::thread::sleep(polling_interval);
        poll_spinner.set_message("Polling for authorization...");

        let poll_result = client
            .post(format!("{}/api/auth/device-authorization/token", args.server_url))
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", &device_auth.device_code),
                ("client_id", &args.client_id),
            ])
            .header("User-Agent", "Better Auth CLI")
            .send();

        match poll_result {
            Ok(resp) => {
                let token_resp: TokenResponse = match resp.json() {
                    Ok(t) => t,
                    Err(_) => continue,
                };

                if let Some(ref access_token) = token_resp.access_token {
                    poll_spinner.finish_and_clear();

                    // Store the token
                    let stored = StoredToken {
                        access_token: access_token.clone(),
                        token_type: token_resp.token_type.unwrap_or_else(|| "Bearer".into()),
                        scope: token_resp.scope,
                        created_at: chrono::Utc::now().to_rfc3339(),
                    };
                    store_token(&stored)?;

                    println!();
                    println!("{}", "✅ Demo login successful!".green().bold());
                    println!();
                    println!("{}", "📝 Note: This was a demo authentication for testing purposes.".dimmed());
                    println!();
                    println!(
                        "{}",
                        "For more info: https://better-auth.com/docs/plugins/device-authorization"
                            .blue()
                    );
                    println!();
                    return Ok(());
                }

                if let Some(ref error) = token_resp.error {
                    match error.as_str() {
                        "authorization_pending" => continue,
                        "slow_down" => {
                            // back off
                            std::thread::sleep(std::time::Duration::from_secs(5));
                            continue;
                        }
                        "access_denied" => {
                            poll_spinner.finish_and_clear();
                            return Err("Access was denied by the user.".into());
                        }
                        "expired_token" => {
                            poll_spinner.finish_and_clear();
                            return Err("The device code has expired. Please try again.".into());
                        }
                        _ => {
                            poll_spinner.finish_and_clear();
                            let desc = token_resp
                                .error_description
                                .unwrap_or_else(|| "Unknown error".into());
                            return Err(format!("Error: {}", desc).into());
                        }
                    }
                }
            }
            Err(e) => {
                poll_spinner.finish_and_clear();
                return Err(format!("Network error: {}", e).into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_dir() {
        let dir = config_dir();
        assert!(dir.to_string_lossy().contains(".better-auth"));
    }

    #[test]
    fn test_store_and_get_token() {
        // Test serialization round-trip
        let token = StoredToken {
            access_token: "test_token_123".into(),
            token_type: "Bearer".into(),
            scope: Some("openid".into()),
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&token).unwrap();
        let parsed: StoredToken = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.access_token, "test_token_123");
        assert_eq!(parsed.token_type, "Bearer");
    }

    #[test]
    fn test_token_file_path() {
        let path = token_file();
        assert!(path.to_string_lossy().ends_with("token.json"));
    }
}
