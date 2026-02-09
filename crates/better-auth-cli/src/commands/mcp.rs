// `better-auth mcp` — install/configure MCP server in various editors.
// Maps to TS `commands/mcp.ts` (249 lines).

use std::path::PathBuf;

use clap::Args;
use colored::Colorize;

const REMOTE_MCP_URL: &str = "https://mcp.inkeep.com/better-auth/mcp";

#[derive(Args)]
pub struct McpArgs {
    /// Automatically open Cursor with the MCP configuration
    #[arg(long)]
    cursor: bool,

    /// Show Claude Code MCP configuration command
    #[arg(long)]
    claude_code: bool,

    /// Show Open Code MCP configuration
    #[arg(long)]
    open_code: bool,

    /// Show manual MCP configuration for mcp.json
    #[arg(long)]
    manual: bool,
}

pub fn run(args: McpArgs) -> Result<(), Box<dyn std::error::Error>> {
    if args.cursor {
        handle_cursor()
    } else if args.claude_code {
        handle_claude_code()
    } else if args.open_code {
        handle_open_code()
    } else if args.manual {
        handle_manual()
    } else {
        show_all_options();
        Ok(())
    }
}

fn handle_cursor() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "🚀 Adding Better Auth MCP to Cursor...".bold().blue());

    let remote_config = serde_json::json!({ "url": REMOTE_MCP_URL });
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        serde_json::to_string(&remote_config)?,
    );
    let deeplink = format!(
        "cursor://anysphere.cursor-deeplink/mcp/install?name={}&config={}",
        urlencoding::encode("better-auth"),
        encoded
    );

    match open::that(&deeplink) {
        Ok(_) => println!("{}", "\n✓ Better Auth MCP server installed!".green()),
        Err(_) => {
            println!(
                "{}",
                "\n⚠ Could not automatically open Cursor for MCP installation.".yellow()
            );
            println!("  Deeplink: {}", deeplink.dimmed());
        }
    }

    print_next_steps("Cursor");
    Ok(())
}

fn handle_claude_code() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "🤖 Adding Better Auth MCP to Claude Code...".bold().blue());

    let command = format!(
        "claude mcp add --transport http better-auth {}",
        REMOTE_MCP_URL
    );

    match std::process::Command::new("sh")
        .args(["-c", &command])
        .status()
    {
        Ok(status) if status.success() => {
            println!("{}", "\n✓ Claude Code MCP configured!".green());
        }
        _ => {
            println!(
                "{}",
                "\n⚠ Could not automatically add to Claude Code. Please run this command manually:"
                    .yellow()
            );
            println!("  {}", command.cyan());
        }
    }

    print_next_steps("Claude Code");
    Ok(())
}

fn handle_open_code() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "🔧 Adding Better Auth MCP to Open Code...".bold().blue());

    let config_path = PathBuf::from("opencode.json");
    let open_code_config = serde_json::json!({
        "$schema": "https://opencode.ai/config.json",
        "mcp": {
            "better-auth": {
                "type": "remote",
                "url": REMOTE_MCP_URL,
                "enabled": true
            }
        }
    });

    // Read existing config and merge
    let merged = if config_path.exists() {
        let existing: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path)?)?;
        merge_json(existing, open_code_config)
    } else {
        open_code_config
    };

    std::fs::write(&config_path, serde_json::to_string_pretty(&merged)?)?;
    println!(
        "{}",
        format!("\n✓ Open Code configuration written to {}", config_path.display()).green()
    );
    println!("{}", "✓ Better Auth MCP server added successfully!".green());

    print_next_steps("Open Code");
    Ok(())
}

fn handle_manual() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "📝 Better Auth MCP Configuration...".bold().blue());

    let manual_config = serde_json::json!({
        "better-auth": {
            "url": REMOTE_MCP_URL
        }
    });

    let config_path = PathBuf::from("mcp.json");

    // Read existing config and merge
    let merged = if config_path.exists() {
        let existing: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path)?)?;
        merge_json(existing, manual_config)
    } else {
        manual_config
    };

    std::fs::write(&config_path, serde_json::to_string_pretty(&merged)?)?;
    println!(
        "{}",
        format!("\n✓ MCP configuration written to {}", config_path.display()).green()
    );
    println!("{}", "✓ Better Auth MCP server added successfully!".green());

    print_next_steps("your MCP client");
    Ok(())
}

fn show_all_options() {
    println!("{}", "🔌 Better Auth MCP Server".bold().blue());
    println!("{}", "Choose your MCP client to get started:".dimmed());
    println!();
    println!("{}", "MCP Clients:".bold().white());
    println!("  {}  {}", "--cursor".cyan(), "Add to Cursor".dimmed());
    println!("  {}  {}", "--claude-code".cyan(), "Add to Claude Code".dimmed());
    println!("  {}  {}", "--open-code".cyan(), "Add to Open Code".dimmed());
    println!("  {}  {}", "--manual".cyan(), "Manual configuration".dimmed());
    println!();
    println!("{}", "Server:".bold().white());
    println!(
        "  {} {} {}",
        "•".dimmed(),
        "better-auth".white(),
        "- Search documentation, code examples, setup assistance".dimmed()
    );
    println!();
}

fn print_next_steps(client: &str) {
    println!();
    println!("{}", "✨ Next Steps:".bold().white());
    println!(
        "{}",
        format!("• The MCP server will be added to your {} configuration", client).dimmed()
    );
    println!(
        "{}",
        format!("• You can now use Better Auth features directly in {}", client).dimmed()
    );
    if client == "Cursor" {
        println!(
            "{}",
            "• Try: \"Set up Better Auth with Google login\" or \"Help me debug my auth\"".dimmed()
        );
    }
    println!();
}

/// Merge two JSON values (shallow merge, second wins).
fn merge_json(base: serde_json::Value, overlay: serde_json::Value) -> serde_json::Value {
    match (base, overlay) {
        (serde_json::Value::Object(mut base_map), serde_json::Value::Object(overlay_map)) => {
            for (k, v) in overlay_map {
                let existing = base_map.remove(&k);
                let merged = match existing {
                    Some(ev) => merge_json(ev, v),
                    None => v,
                };
                base_map.insert(k, merged);
            }
            serde_json::Value::Object(base_map)
        }
        (_, overlay) => overlay,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_show_all_options() {
        // Shouldn't panic
        show_all_options();
    }

    #[test]
    fn test_merge_json() {
        let base = serde_json::json!({"a": 1, "b": {"c": 2}});
        let overlay = serde_json::json!({"b": {"d": 3}, "e": 4});
        let merged = merge_json(base, overlay);
        assert_eq!(merged["a"], 1);
        assert_eq!(merged["b"]["c"], 2);
        assert_eq!(merged["b"]["d"], 3);
        assert_eq!(merged["e"], 4);
    }

    #[test]
    fn test_remote_mcp_url() {
        assert!(REMOTE_MCP_URL.starts_with("https://"));
    }
}
