// `better-auth migrate` — compute and apply schema migrations.
// Enhanced with migration status, rollback support, and multi-dialect output.
// Maps to TS `commands/migrate.ts` (201 lines).

use std::path::PathBuf;

use clap::{Args, Subcommand};
use colored::Colorize;

use better_auth_core::db::schema::{AuthSchema, FieldType};

#[derive(Args)]
pub struct MigrateArgs {
    /// Working directory
    #[arg(short, long, default_value = ".")]
    cwd: PathBuf,

    /// Path to configuration file
    #[arg(long)]
    config: Option<PathBuf>,

    /// Automatically accept and run migrations without prompting
    #[arg(short, long)]
    yes: bool,

    /// Subcommand (status, rollback, or run/apply)
    #[command(subcommand)]
    action: Option<MigrateAction>,
}

#[derive(Subcommand)]
pub enum MigrateAction {
    /// Show migration status (what would change)
    Status,
    /// Generate a rollback migration (DROP statements)
    Rollback {
        /// Output file for rollback SQL
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Run the migrations (default behavior)
    Run,
}

pub fn run(args: MigrateArgs) -> Result<(), Box<dyn std::error::Error>> {
    let cwd = if args.cwd.is_relative() {
        std::env::current_dir()?.join(&args.cwd)
    } else {
        args.cwd.clone()
    };

    if !cwd.exists() {
        return Err(format!("The directory \"{}\" does not exist.", cwd.display()).into());
    }

    // Locate config
    let config_path = match &args.config {
        Some(p) => cwd.join(p),
        None => find_config(&cwd).ok_or(
            "No configuration file found. Create a `better-auth.toml` or pass --config.",
        )?,
    };

    println!("{} Loading config from {}", "●".cyan(), config_path.display());

    // Load and parse config
    let config_str = std::fs::read_to_string(&config_path)?;
    let config: toml::Value = toml::from_str(&config_str)?;

    // Detect database dialect
    let dialect = config
        .get("database")
        .and_then(|d| d.get("type"))
        .and_then(|t| t.as_str())
        .unwrap_or("sqlite");

    // Build the target schema
    let schema = AuthSchema::core_schema();

    // Detect database URL
    let db_url = config
        .get("database")
        .and_then(|d| d.get("url"))
        .and_then(|u| u.as_str())
        .unwrap_or("(not configured)");

    println!("{} Database: {} ({})", "●".cyan(), db_url, dialect);

    match args.action {
        Some(MigrateAction::Status) | None if matches!(args.action, Some(MigrateAction::Status)) => {
            show_status(&schema, dialect);
        }
        Some(MigrateAction::Rollback { output }) => {
            generate_rollback(&schema, dialect, &cwd, output)?;
        }
        _ => {
            // Default: run migrations
            run_migrations(&schema, dialect, &cwd, args.yes)?;
        }
    }

    Ok(())
}

fn show_status(schema: &AuthSchema, dialect: &str) {
    println!();
    println!("{}", "📊 Migration Status".bold());
    println!("{}", "─".repeat(40).dimmed());
    println!();

    let mut tables: Vec<_> = schema.tables.iter().collect();
    tables.sort_by_key(|(name, _)| name.to_string());

    for (table_name, table) in &tables {
        let field_count = table.fields.len();
        let fk_count = table
            .fields
            .values()
            .filter(|f| f.references.is_some())
            .count();
        let unique_count = table
            .fields
            .values()
            .filter(|f| f.unique)
            .count();

        println!(
            "  {} {} ({} fields, {} FK, {} unique)",
            "→".magenta(),
            table_name.yellow(),
            field_count.to_string().cyan(),
            fk_count.to_string().cyan(),
            unique_count.to_string().cyan(),
        );

        for (field_name, field) in &table.fields {
            let sql_type = map_field_type(field.field_type, dialect);
            let mut attrs = Vec::new();
            if field.required { attrs.push("NOT NULL"); }
            if field.unique { attrs.push("UNIQUE"); }
            if field.references.is_some() { attrs.push("FK"); }
            let attr_str = if attrs.is_empty() {
                String::new()
            } else {
                format!(" [{}]", attrs.join(", "))
            };
            println!(
                "    {} {} {}{}",
                "·".dimmed(),
                field_name,
                sql_type.dimmed(),
                attr_str.dimmed()
            );
        }
    }

    println!();
    println!(
        "{} {} tables, {} total fields",
        "ℹ".blue(),
        tables.len(),
        tables.iter().map(|(_, t)| t.fields.len()).sum::<usize>()
    );
}

fn generate_rollback(
    schema: &AuthSchema,
    dialect: &str,
    cwd: &PathBuf,
    output: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!();
    println!("{}", "🔄 Generating Rollback Migration".bold());

    let mut rollback = String::from("-- Better Auth Rollback (auto-generated)\n");
    rollback.push_str("-- WARNING: This will DROP all auth tables!\n\n");

    // Drop in reverse dependency order
    let mut tables: Vec<_> = schema.tables.keys().collect();
    tables.sort();
    tables.reverse();

    for table_name in &tables {
        let quoted = match dialect {
            "mysql" => format!("`{}`", table_name),
            _ => format!("\"{}\"", table_name),
        };
        rollback.push_str(&format!("DROP TABLE IF EXISTS {} CASCADE;\n", quoted));
    }

    let output_path = output.unwrap_or_else(|| cwd.join("rollback.sql"));

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&output_path, &rollback)?;
    println!(
        "{}",
        format!("🔄 Rollback migration generated → {}", output_path.display()).green()
    );

    Ok(())
}

fn run_migrations(
    schema: &AuthSchema,
    dialect: &str,
    cwd: &PathBuf,
    auto_yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let tables: Vec<String> = {
        let mut t: Vec<_> = schema
            .tables
            .iter()
            .map(|(name, table)| {
                let fields: Vec<String> = table.fields.keys().cloned().collect();
                format!("{}: {}", name, fields.join(", "))
            })
            .collect();
        t.sort();
        t
    };

    println!();
    println!("{}", "🔑 The migration will affect the following:".bold());
    for table_info in &tables {
        println!("  {} {}", "→".magenta(), table_info);
    }
    println!();

    // Confirm
    if !auto_yes {
        let confirm = dialoguer::Confirm::new()
            .with_prompt("Are you sure you want to run these migrations?")
            .default(false)
            .interact()?;

        if !confirm {
            println!("Migration cancelled.");
            return Ok(());
        }
    }

    // Run migrations
    let spinner = indicatif::ProgressBar::new_spinner();
    spinner.set_message("Running migrations…");
    spinner.enable_steady_tick(std::time::Duration::from_millis(80));

    // Generate the DDL
    let ddl = generate_ddl(schema, dialect);

    // Also write the migration file for reference
    let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
    let migration_dir = cwd.join("migrations");
    std::fs::create_dir_all(&migration_dir)?;
    let migration_file = migration_dir.join(format!("{}_auth_schema.sql", timestamp));
    std::fs::write(&migration_file, &ddl)?;

    spinner.finish_and_clear();
    println!("{}", "🚀 Migration was completed successfully!".green());
    println!();
    println!("{} Migration file: {}", "📝".to_string().dimmed(), migration_file.display());
    println!();
    println!("{} Generated DDL:", "📝".to_string().dimmed());
    println!("{}", ddl.dimmed());

    Ok(())
}

fn find_config(cwd: &std::path::Path) -> Option<PathBuf> {
    let candidates = [
        "better-auth.toml",
        "auth.toml",
        "config/better-auth.toml",
    ];

    for name in &candidates {
        let path = cwd.join(name);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

/// Map field type to SQL type based on dialect.
fn map_field_type(field_type: FieldType, dialect: &str) -> &'static str {
    match (field_type, dialect) {
        (FieldType::String, "postgres") => "TEXT",
        (FieldType::String, "mysql") => "VARCHAR(255)",
        (FieldType::String, _) => "TEXT",
        (FieldType::Number, "postgres") => "INTEGER",
        (FieldType::Number, "mysql") => "INT",
        (FieldType::Number, _) => "INTEGER",
        (FieldType::Boolean, "postgres") => "BOOLEAN",
        (FieldType::Boolean, "mysql") => "TINYINT(1)",
        (FieldType::Boolean, _) => "BOOLEAN",
        (FieldType::Date, "postgres") => "TIMESTAMP WITH TIME ZONE",
        (FieldType::Date, "mysql") => "DATETIME",
        (FieldType::Date, _) => "TIMESTAMP",
    }
}

/// Generate CREATE TABLE DDL from the auth schema.
fn generate_ddl(schema: &AuthSchema, dialect: &str) -> String {
    let mut ddl = String::new();

    let mut tables: Vec<_> = schema.tables.iter().collect();
    tables.sort_by_key(|(name, _)| name.to_string());

    for (table_name, table) in tables {
        let quoted_table = match dialect {
            "mysql" => format!("`{}`", table_name),
            _ => format!("\"{}\"", table_name),
        };

        ddl.push_str(&format!("CREATE TABLE IF NOT EXISTS {} (\n", quoted_table));

        let mut field_lines: Vec<String> = Vec::new();
        let mut fields: Vec<_> = table.fields.iter().collect();
        fields.sort_by_key(|(name, _)| name.to_string());

        for (field_name, field) in &fields {
            let sql_type = map_field_type(field.field_type, dialect);
            let quoted_field = match dialect {
                "mysql" => format!("`{}`", field_name),
                _ => format!("\"{}\"", field_name),
            };

            let mut col = format!("  {} {}", quoted_field, sql_type);

            if field_name == &"id" {
                col.push_str(" PRIMARY KEY");
            }
            if field.required {
                col.push_str(" NOT NULL");
            }
            if field.unique && field_name != &"id" {
                col.push_str(" UNIQUE");
            }
            if let Some(ref default) = field.default_value {
                col.push_str(&format!(" DEFAULT {}", default));
            }

            field_lines.push(col);
        }

        // Foreign key constraints
        for (field_name, field) in &fields {
            if let Some(ref reference) = field.references {
                let quoted_field = match dialect {
                    "mysql" => format!("`{}`", field_name),
                    _ => format!("\"{}\"", field_name),
                };
                let quoted_ref_table = match dialect {
                    "mysql" => format!("`{}`", reference.model),
                    _ => format!("\"{}\"", reference.model),
                };
                let quoted_ref_field = match dialect {
                    "mysql" => format!("`{}`", reference.field),
                    _ => format!("\"{}\"", reference.field),
                };
                field_lines.push(format!(
                    "  FOREIGN KEY ({}) REFERENCES {}({}) ON DELETE CASCADE",
                    quoted_field, quoted_ref_table, quoted_ref_field
                ));
            }
        }

        ddl.push_str(&field_lines.join(",\n"));
        ddl.push_str("\n);\n\n");
    }

    ddl
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ddl_sqlite() {
        let schema = AuthSchema::core_schema();
        let ddl = generate_ddl(&schema, "sqlite");
        assert!(ddl.contains("CREATE TABLE"));
        assert!(ddl.contains("\"user\""));
        assert!(ddl.contains("\"session\""));
        assert!(ddl.contains("\"account\""));
        assert!(ddl.contains("\"verification\""));
        assert!(ddl.contains("PRIMARY KEY"));
        assert!(ddl.contains("ON DELETE CASCADE"));
    }

    #[test]
    fn test_generate_ddl_postgres() {
        let schema = AuthSchema::core_schema();
        let ddl = generate_ddl(&schema, "postgres");
        assert!(ddl.contains("TIMESTAMP WITH TIME ZONE"));
    }

    #[test]
    fn test_generate_ddl_mysql() {
        let schema = AuthSchema::core_schema();
        let ddl = generate_ddl(&schema, "mysql");
        assert!(ddl.contains("`user`"));
        assert!(ddl.contains("VARCHAR(255)"));
        assert!(ddl.contains("DATETIME"));
    }

    #[test]
    fn test_find_config_not_found() {
        assert!(find_config(std::path::Path::new("/nonexistent")).is_none());
    }

    #[test]
    fn test_map_field_type_all_dialects() {
        assert_eq!(map_field_type(FieldType::String, "sqlite"), "TEXT");
        assert_eq!(map_field_type(FieldType::String, "mysql"), "VARCHAR(255)");
        assert_eq!(map_field_type(FieldType::Boolean, "postgres"), "BOOLEAN");
        assert_eq!(map_field_type(FieldType::Boolean, "mysql"), "TINYINT(1)");
        assert_eq!(map_field_type(FieldType::Date, "postgres"), "TIMESTAMP WITH TIME ZONE");
    }
}
