// `better-auth generate` — generate SQL DDL schema from auth configuration.
// Enhanced to support multiple output formats: SQL, Diesel, Sea-ORM.
// Maps to TS `commands/generate.ts` + `generators/`.

use std::path::PathBuf;

use clap::{Args, ValueEnum};
use colored::Colorize;

use better_auth_core::db::schema::{AuthSchema, FieldType};

/// Supported output formats for schema generation.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    /// Raw SQL DDL (CREATE TABLE)
    Sql,
    /// Diesel migration format (up.sql + down.sql)
    Diesel,
    /// Sea-ORM entity files (.rs)
    SeaOrm,
    /// SQLx migration file (.sql)
    Sqlx,
}

#[derive(Args)]
pub struct GenerateArgs {
    /// Working directory
    #[arg(short, long, default_value = ".")]
    cwd: PathBuf,

    /// Path to configuration file
    #[arg(long)]
    config: Option<PathBuf>,

    /// Output file path
    #[arg(long)]
    output: Option<PathBuf>,

    /// Output format
    #[arg(long, value_enum, default_value = "sql")]
    format: OutputFormat,

    /// Database dialect (sqlite, postgres, mysql)
    #[arg(long, default_value = "sqlite")]
    dialect: String,

    /// Automatically answer yes to all prompts
    #[arg(short, long)]
    yes: bool,
}

pub fn run(args: GenerateArgs) -> Result<(), Box<dyn std::error::Error>> {
    let cwd = if args.cwd.is_relative() {
        std::env::current_dir()?.join(&args.cwd)
    } else {
        args.cwd.clone()
    };

    if !cwd.exists() {
        return Err(format!("The directory \"{}\" does not exist.", cwd.display()).into());
    }

    let spinner = indicatif::ProgressBar::new_spinner();
    spinner.set_message("Preparing schema…");
    spinner.enable_steady_tick(std::time::Duration::from_millis(80));

    // Build schema from core tables (plugins will add fields when runtime is wired)
    let schema = AuthSchema::core_schema();

    let (output, default_filename) = match args.format {
        OutputFormat::Sql => (generate_sql_ddl(&schema, &args.dialect), "schema.sql".to_string()),
        OutputFormat::Diesel => (
            generate_diesel_migration(&schema, &args.dialect),
            "migrations".to_string(),
        ),
        OutputFormat::SeaOrm => (generate_sea_orm_entities(&schema), "entity".to_string()),
        OutputFormat::Sqlx => {
            let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
            (
                generate_sql_ddl(&schema, &args.dialect),
                format!("migrations/{}_create_auth_tables.sql", timestamp),
            )
        }
    };

    spinner.finish_and_clear();

    if output.is_empty() {
        println!("Your schema is already up to date.");
        return Ok(());
    }

    match args.format {
        OutputFormat::Diesel => {
            // Diesel creates a directory with up.sql and down.sql
            let base_dir = args.output.unwrap_or_else(|| cwd.join("migrations/00000000000000_create_auth_tables"));
            write_diesel_migration(&base_dir, &schema, &args.dialect, args.yes)?;
        }
        OutputFormat::SeaOrm => {
            // Sea-ORM creates multiple .rs files
            let base_dir = args.output.unwrap_or_else(|| cwd.join("src/entity"));
            write_sea_orm_entities(&base_dir, &schema, args.yes)?;
        }
        _ => {
            let output_file = args.output.unwrap_or_else(|| cwd.join(&default_filename));
            let filename = output_file.display().to_string();

            if !args.yes {
                let confirm = dialoguer::Confirm::new()
                    .with_prompt(format!("Generate schema to {}?", filename.yellow()))
                    .default(true)
                    .interact()?;

                if !confirm {
                    println!("Schema generation aborted.");
                    return Ok(());
                }
            }

            if let Some(parent) = output_file.parent() {
                std::fs::create_dir_all(parent)?;
            }

            std::fs::write(&output_file, &output)?;
            println!(
                "{}",
                format!("🚀 Schema was generated successfully → {filename}").green()
            );
        }
    }

    Ok(())
}

/// Generate SQL DDL for all auth tables with dialect-specific types.
fn generate_sql_ddl(schema: &AuthSchema, dialect: &str) -> String {
    let mut ddl = String::from("-- Better Auth Schema (auto-generated)\n");
    ddl.push_str(&format!(
        "-- Dialect: {}\n-- Run this file against your database to create the auth tables.\n\n",
        dialect
    ));

    let mut tables: Vec<_> = schema.tables.iter().collect();
    tables.sort_by_key(|(name, _)| name.to_string());

    for (table_name, table) in tables {
        ddl.push_str(&format!(
            "CREATE TABLE IF NOT EXISTS {} (\n",
            quote_identifier(table_name, dialect)
        ));

        let mut fields: Vec<_> = table.fields.iter().collect();
        fields.sort_by_key(|(name, _)| name.to_string());

        let mut lines: Vec<String> = Vec::new();
        for (field_name, field) in &fields {
            let sql_type = map_field_type(field.field_type, dialect);
            let mut col = format!(
                "    {} {}",
                quote_identifier(field_name, dialect),
                sql_type
            );
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
            lines.push(col);
        }

        // Foreign key constraints
        for (field_name, field) in &fields {
            if let Some(ref reference) = field.references {
                lines.push(format!(
                    "    FOREIGN KEY ({}) REFERENCES {}({})",
                    quote_identifier(field_name, dialect),
                    quote_identifier(&reference.model, dialect),
                    quote_identifier(&reference.field, dialect)
                ));
            }
        }

        ddl.push_str(&lines.join(",\n"));
        ddl.push_str("\n);\n\n");
    }

    ddl
}

/// Generate Diesel migration (up.sql content).
fn generate_diesel_migration(schema: &AuthSchema, dialect: &str) -> String {
    generate_sql_ddl(schema, dialect)
}

/// Generate Diesel down.sql (DROP TABLE statements).
fn generate_diesel_down(schema: &AuthSchema, dialect: &str) -> String {
    let mut down = String::from("-- Better Auth Schema Rollback (auto-generated)\n\n");

    // Drop in reverse order (children first)
    let mut tables: Vec<_> = schema.tables.keys().collect();
    tables.sort();
    tables.reverse();

    for table_name in tables {
        down.push_str(&format!(
            "DROP TABLE IF EXISTS {};\n",
            quote_identifier(table_name, dialect)
        ));
    }

    down
}

/// Write Diesel migration directory (up.sql + down.sql).
fn write_diesel_migration(
    base_dir: &PathBuf,
    schema: &AuthSchema,
    dialect: &str,
    auto_yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !auto_yes {
        let confirm = dialoguer::Confirm::new()
            .with_prompt(format!(
                "Generate Diesel migration in {}?",
                base_dir.display().to_string().yellow()
            ))
            .default(true)
            .interact()?;
        if !confirm {
            println!("Generation aborted.");
            return Ok(());
        }
    }

    std::fs::create_dir_all(base_dir)?;

    let up_sql = generate_diesel_migration(schema, dialect);
    let down_sql = generate_diesel_down(schema, dialect);

    std::fs::write(base_dir.join("up.sql"), &up_sql)?;
    std::fs::write(base_dir.join("down.sql"), &down_sql)?;

    println!(
        "{}",
        format!(
            "🚀 Diesel migration generated → {}/",
            base_dir.display()
        )
        .green()
    );
    println!("  {} up.sql ({} bytes)", "✓".green(), up_sql.len());
    println!("  {} down.sql ({} bytes)", "✓".green(), down_sql.len());

    Ok(())
}

/// Generate Sea-ORM entity module code.
fn generate_sea_orm_entities(schema: &AuthSchema) -> String {
    let mut tables: Vec<_> = schema.tables.keys().collect();
    tables.sort();

    let mut mod_rs = String::from("//! Better Auth entity module (auto-generated for Sea-ORM)\n\n");
    for table in &tables {
        mod_rs.push_str(&format!("pub mod {};\n", table));
    }
    mod_rs
}

/// Generate a single Sea-ORM entity file for a table.
fn generate_sea_orm_entity(table_name: &str, schema: &AuthSchema) -> String {
    let table = match schema.tables.get(table_name) {
        Some(t) => t,
        None => return String::new(),
    };

    let mut entity = String::new();
    entity.push_str(&format!(
        "//! `{}` entity (auto-generated for Sea-ORM)\n\n",
        table_name
    ));
    entity.push_str("use sea_orm::entity::prelude::*;\n\n");

    // Model struct
    entity.push_str("#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]\n");
    entity.push_str(&format!("#[sea_orm(table_name = \"{}\")]\n", table_name));
    entity.push_str("pub struct Model {\n");

    let mut fields: Vec<_> = table.fields.iter().collect();
    fields.sort_by_key(|(name, _)| name.to_string());

    for (field_name, field) in &fields {
        if field_name == &"id" {
            entity.push_str("    #[sea_orm(primary_key, auto_increment = false)]\n");
        }
        if field.unique && field_name != &"id" {
            entity.push_str("    #[sea_orm(unique)]\n");
        }

        let rust_type = match field.field_type {
            FieldType::String => "String",
            FieldType::Number => "i64",
            FieldType::Boolean => "bool",
            FieldType::Date => "DateTimeUtc",
        };

        let full_type = if field.required || field_name == &"id" {
            rust_type.to_string()
        } else {
            format!("Option<{}>", rust_type)
        };

        entity.push_str(&format!("    pub {}: {},\n", field_name, full_type));
    }
    entity.push_str("}\n\n");

    // Relation enum
    entity.push_str("#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]\n");
    entity.push_str("pub enum Relation {");

    let has_relations = fields
        .iter()
        .any(|(_, f)| f.references.is_some());

    if has_relations {
        entity.push('\n');
        for (field_name, field) in &fields {
            if let Some(ref reference) = field.references {
                let related_entity = to_pascal_case(&reference.model);
                entity.push_str(&format!(
                    "    #[sea_orm(\n        belongs_to = \"super::{}::Entity\",\n        from = \"Column::{}\",\n        to = \"super::{}::Column::{}\"\n    )]\n    {},\n",
                    reference.model,
                    to_pascal_case(field_name),
                    reference.model,
                    to_pascal_case(&reference.field),
                    related_entity,
                ));
            }
        }
    }
    entity.push_str("}\n\n");

    entity.push_str("impl ActiveModelBehavior for ActiveModel {}\n");

    entity
}

/// Write Sea-ORM entity files.
fn write_sea_orm_entities(
    base_dir: &PathBuf,
    schema: &AuthSchema,
    auto_yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !auto_yes {
        let confirm = dialoguer::Confirm::new()
            .with_prompt(format!(
                "Generate Sea-ORM entities in {}?",
                base_dir.display().to_string().yellow()
            ))
            .default(true)
            .interact()?;
        if !confirm {
            println!("Generation aborted.");
            return Ok(());
        }
    }

    std::fs::create_dir_all(base_dir)?;

    // Generate mod.rs
    let mod_content = generate_sea_orm_entities(schema);
    std::fs::write(base_dir.join("mod.rs"), &mod_content)?;

    // Generate individual entity files
    let mut tables: Vec<_> = schema.tables.keys().collect();
    tables.sort();

    for table_name in &tables {
        let entity = generate_sea_orm_entity(table_name, schema);
        std::fs::write(base_dir.join(format!("{}.rs", table_name)), &entity)?;
    }

    println!(
        "{}",
        format!("🚀 Sea-ORM entities generated → {}/", base_dir.display()).green()
    );
    println!("  {} mod.rs", "✓".green());
    for table in &tables {
        println!("  {} {}.rs", "✓".green(), table);
    }

    Ok(())
}

/// Quote an identifier based on SQL dialect.
fn quote_identifier(name: &str, dialect: &str) -> String {
    match dialect {
        "mysql" => format!("`{}`", name),
        "postgres" => format!("\"{}\"", name),
        _ => format!("\"{}\"", name), // sqlite
    }
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

/// Convert snake_case to PascalCase.
fn to_pascal_case(s: &str) -> String {
    s.split('_')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(c) => c.to_uppercase().to_string() + &chars.collect::<String>(),
                None => String::new(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_sql_ddl_sqlite() {
        let schema = AuthSchema::core_schema();
        let ddl = generate_sql_ddl(&schema, "sqlite");
        assert!(ddl.contains("CREATE TABLE"));
        assert!(ddl.contains("\"user\""));
        assert!(ddl.contains("PRIMARY KEY"));
        assert!(ddl.contains("FOREIGN KEY"));
        assert!(ddl.contains("Dialect: sqlite"));
    }

    #[test]
    fn test_generate_sql_ddl_postgres() {
        let schema = AuthSchema::core_schema();
        let ddl = generate_sql_ddl(&schema, "postgres");
        assert!(ddl.contains("TIMESTAMP WITH TIME ZONE"));
        assert!(ddl.contains("Dialect: postgres"));
    }

    #[test]
    fn test_generate_sql_ddl_mysql() {
        let schema = AuthSchema::core_schema();
        let ddl = generate_sql_ddl(&schema, "mysql");
        assert!(ddl.contains("VARCHAR(255)"));
        assert!(ddl.contains("`user`"));
        assert!(ddl.contains("DATETIME"));
    }

    #[test]
    fn test_generate_diesel_down() {
        let schema = AuthSchema::core_schema();
        let down = generate_diesel_down(&schema, "sqlite");
        assert!(down.contains("DROP TABLE IF EXISTS"));
        assert!(down.contains("user"));
    }

    #[test]
    fn test_generate_sea_orm_entities() {
        let schema = AuthSchema::core_schema();
        let mod_rs = generate_sea_orm_entities(&schema);
        assert!(mod_rs.contains("pub mod user;"));
        assert!(mod_rs.contains("pub mod session;"));
    }

    #[test]
    fn test_generate_sea_orm_entity() {
        let schema = AuthSchema::core_schema();
        let entity = generate_sea_orm_entity("user", &schema);
        assert!(entity.contains("DeriveEntityModel"));
        assert!(entity.contains("table_name = \"user\""));
        assert!(entity.contains("pub id: String"));
    }

    #[test]
    fn test_quote_identifier() {
        assert_eq!(quote_identifier("user", "postgres"), "\"user\"");
        assert_eq!(quote_identifier("user", "mysql"), "`user`");
        assert_eq!(quote_identifier("user", "sqlite"), "\"user\"");
    }

    #[test]
    fn test_map_field_type() {
        assert_eq!(map_field_type(FieldType::String, "postgres"), "TEXT");
        assert_eq!(map_field_type(FieldType::String, "mysql"), "VARCHAR(255)");
        assert_eq!(map_field_type(FieldType::Date, "postgres"), "TIMESTAMP WITH TIME ZONE");
        assert_eq!(map_field_type(FieldType::Boolean, "mysql"), "TINYINT(1)");
    }

    #[test]
    fn test_to_pascal_case() {
        assert_eq!(to_pascal_case("user_id"), "UserId");
        assert_eq!(to_pascal_case("user"), "User");
        assert_eq!(to_pascal_case("api_key"), "ApiKey");
    }
}
