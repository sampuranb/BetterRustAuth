use clap::{Parser, Subcommand};

mod commands;

/// Better Auth CLI — manage your auth infrastructure
#[derive(Parser)]
#[command(name = "better-auth", version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a random secret for BETTER_AUTH_SECRET
    Secret,

    /// Display system and configuration information
    Info(commands::info::InfoArgs),

    /// Run database schema migrations
    Migrate(commands::migrate::MigrateArgs),

    /// Generate SQL DDL schema from auth configuration
    Generate(commands::generate::GenerateArgs),

    /// Initialize a new Better Auth project
    Init(commands::init::InitArgs),

    /// Add Better Auth MCP server to MCP Clients
    Mcp(commands::mcp::McpArgs),

    /// Demo: Test device authorization flow with Better Auth demo server
    Login(commands::login::LoginArgs),
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Secret => commands::secret::run(),
        Commands::Info(args) => commands::info::run(args),
        Commands::Migrate(args) => commands::migrate::run(args),
        Commands::Generate(args) => commands::generate::run(args),
        Commands::Init(args) => commands::init::run(args),
        Commands::Mcp(args) => commands::mcp::run(args),
        Commands::Login(args) => commands::login::run(args),
    };

    if let Err(e) = result {
        eprintln!("{} {}", colored::Colorize::red("error:"), e);
        std::process::exit(1);
    }
}
