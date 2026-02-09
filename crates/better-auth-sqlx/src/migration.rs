// Migration schema generator — maps to packages/better-auth/src/db/get-migration.ts
//
// Introspects the live database to determine which tables/columns exist,
// compares against the target AuthSchema (core + plugins), and produces
// differential migrations: CREATE TABLE for missing tables, ALTER TABLE
// ADD COLUMN for missing fields.
//
// Supports SQLite, PostgreSQL, and MySQL introspection.

use std::collections::HashMap;

use sqlx::{AnyPool, Row};

use better_auth_core::db::schema::{AuthSchema, AuthTable, FieldType, SchemaField};
use better_auth_core::error::BetterAuthError;

use crate::schema::{
    compile_migrations, generate_alter_ddl, generate_ddl_for, generate_index_ddl,
    match_type, DatabaseType, IdStrategy,
};

// ---------------------------------------------------------------------------
// Column metadata from introspection
// ---------------------------------------------------------------------------

/// Metadata about a single column in an existing database table.
#[derive(Debug, Clone)]
pub struct ColumnInfo {
    /// Column name.
    pub name: String,
    /// Database-specific data type (e.g. "text", "varchar(255)", "timestamptz").
    pub data_type: String,
    /// Whether the column is nullable.
    pub is_nullable: bool,
}

/// Metadata about a single table in the database.
#[derive(Debug, Clone)]
pub struct TableInfo {
    /// Table name.
    pub name: String,
    /// Schema name (for PostgreSQL; empty for SQLite/MySQL).
    pub schema: String,
    /// Columns in the table.
    pub columns: Vec<ColumnInfo>,
}

// ---------------------------------------------------------------------------
// Migration diff result
// ---------------------------------------------------------------------------

/// A table (with all its fields) that needs to be created.
#[derive(Debug, Clone)]
pub struct TableToCreate {
    /// The table name.
    pub table: String,
    /// The fields to create (column name → field definition).
    pub fields: HashMap<String, SchemaField>,
    /// Sort order for dependency ordering.
    pub order: i32,
}

/// A set of columns to add to an existing table.
#[derive(Debug, Clone)]
pub struct ColumnsToAdd {
    /// The table name.
    pub table: String,
    /// The fields to add (column name → field definition).
    pub fields: HashMap<String, SchemaField>,
    /// Sort order.
    pub order: i32,
}

/// Type-mismatched column warning.
#[derive(Debug, Clone)]
pub struct TypeMismatch {
    pub table: String,
    pub field: String,
    pub expected: FieldType,
    pub actual: String,
}

/// The result of computing migrations.
#[derive(Debug, Clone)]
pub struct MigrationPlan {
    /// Tables that need to be created (whole table missing from DB).
    pub to_be_created: Vec<TableToCreate>,
    /// Columns that need to be added to existing tables.
    pub to_be_added: Vec<ColumnsToAdd>,
    /// Columns where the type didn't match (warnings, not auto-fixed).
    pub type_mismatches: Vec<TypeMismatch>,
    /// The compiled SQL statements to run.
    pub statements: Vec<String>,
}

impl MigrationPlan {
    /// Compile all migration statements into a single SQL string.
    pub fn compile(&self) -> String {
        if self.statements.is_empty() {
            return ";".to_string();
        }
        compile_migrations(&self.statements)
    }

    /// Check if there are any pending migrations.
    pub fn has_pending(&self) -> bool {
        !self.to_be_created.is_empty() || !self.to_be_added.is_empty()
    }

    /// Run all migration statements against the pool.
    pub async fn run(&self, pool: &AnyPool) -> Result<(), BetterAuthError> {
        for stmt in &self.statements {
            sqlx::query(stmt)
                .execute(pool)
                .await
                .map_err(|e| BetterAuthError::Other(format!("Migration failed: {e}\nSQL: {stmt}")))?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Database type detection
// ---------------------------------------------------------------------------

/// Detect the database type from the pool's connection URL.
pub fn detect_db_type(pool: &AnyPool) -> DatabaseType {
    // sqlx::AnyPool doesn't expose the backend directly, but we can use
    // the pool options or try a backend-specific query. A simpler heuristic:
    // check the pool's connect options string.
    let opts_str = format!("{:?}", pool.connect_options());
    let opts_lower = opts_str.to_lowercase();

    if opts_lower.contains("postgres") || opts_lower.contains("postgresql") {
        DatabaseType::Postgres
    } else if opts_lower.contains("mysql") || opts_lower.contains("mariadb") {
        DatabaseType::Mysql
    } else {
        DatabaseType::Sqlite
    }
}

// ---------------------------------------------------------------------------
// Introspection — query the db for existing tables + columns
// ---------------------------------------------------------------------------

/// Introspect the database to get metadata about all existing tables.
pub async fn introspect_tables(
    pool: &AnyPool,
    db_type: DatabaseType,
) -> Result<Vec<TableInfo>, BetterAuthError> {
    match db_type {
        DatabaseType::Sqlite => introspect_sqlite(pool).await,
        DatabaseType::Postgres => introspect_postgres(pool).await,
        DatabaseType::Mysql => introspect_mysql(pool).await,
        DatabaseType::Mssql => {
            // MSSQL not supported for introspection yet, treat as empty
            Ok(Vec::new())
        }
    }
}

/// Introspect SQLite tables using PRAGMA and sqlite_master.
async fn introspect_sqlite(pool: &AnyPool) -> Result<Vec<TableInfo>, BetterAuthError> {
    // Get all table names
    let table_rows = sqlx::query(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| BetterAuthError::Other(format!("SQLite introspection failed: {e}")))?;

    let mut tables = Vec::new();

    for row in &table_rows {
        let table_name: String = row
            .try_get("name")
            .map_err(|e| BetterAuthError::Other(format!("Failed to read table name: {e}")))?;

        let pragma_sql = format!("PRAGMA table_info(\"{}\")", table_name.replace('"', ""));
        let col_rows = sqlx::query(&pragma_sql)
            .fetch_all(pool)
            .await
            .map_err(|e| {
                BetterAuthError::Other(format!(
                    "PRAGMA table_info failed for {}: {}",
                    table_name, e
                ))
            })?;

        let mut columns = Vec::new();
        for col_row in &col_rows {
            let name: String = col_row
                .try_get("name")
                .map_err(|e| BetterAuthError::Other(format!("Column name read failed: {e}")))?;
            let data_type: String = col_row.try_get("type").unwrap_or_default();
            let notnull: i32 = col_row.try_get("notnull").unwrap_or(0);

            columns.push(ColumnInfo {
                name,
                data_type,
                is_nullable: notnull == 0,
            });
        }

        tables.push(TableInfo {
            name: table_name,
            schema: String::new(),
            columns,
        });
    }

    Ok(tables)
}

/// Introspect PostgreSQL tables using information_schema.
async fn introspect_postgres(pool: &AnyPool) -> Result<Vec<TableInfo>, BetterAuthError> {
    // Detect current search_path schema
    let current_schema = get_postgres_schema(pool).await;

    // Get tables in the current schema
    let table_rows = sqlx::query(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = $1 AND table_type = 'BASE TABLE'",
    )
    .bind(&current_schema)
    .fetch_all(pool)
    .await
    .map_err(|e| BetterAuthError::Other(format!("PostgreSQL table introspection failed: {e}")))?;

    let mut tables = Vec::new();

    for row in &table_rows {
        let table_name: String = row
            .try_get("table_name")
            .map_err(|e| BetterAuthError::Other(format!("Failed to read table_name: {e}")))?;

        // Get columns for this table
        let col_rows = sqlx::query(
            "SELECT column_name, data_type, is_nullable \
             FROM information_schema.columns \
             WHERE table_schema = $1 AND table_name = $2 \
             ORDER BY ordinal_position",
        )
        .bind(&current_schema)
        .bind(&table_name)
        .fetch_all(pool)
        .await
        .map_err(|e| {
            BetterAuthError::Other(format!(
                "PostgreSQL column introspection failed for {}: {}",
                table_name, e
            ))
        })?;

        let mut columns = Vec::new();
        for col_row in &col_rows {
            let name: String = col_row.try_get("column_name").unwrap_or_default();
            let data_type: String = col_row.try_get("data_type").unwrap_or_default();
            let is_nullable_str: String = col_row.try_get("is_nullable").unwrap_or_default();

            columns.push(ColumnInfo {
                name,
                data_type,
                is_nullable: is_nullable_str.to_uppercase() == "YES",
            });
        }

        tables.push(TableInfo {
            name: table_name,
            schema: current_schema.clone(),
            columns,
        });
    }

    Ok(tables)
}

/// Get the current PostgreSQL schema from search_path.
/// Matches TS `getPostgresSchema()`.
async fn get_postgres_schema(pool: &AnyPool) -> String {
    let result = sqlx::query("SHOW search_path")
        .fetch_optional(pool)
        .await;

    match result {
        Ok(Some(row)) => {
            let search_path: String = row.try_get("search_path").unwrap_or_default();
            // Parse comma-separated search_path, skip $user variables
            search_path
                .split(',')
                .map(|s| s.trim().trim_matches('"').trim_matches('\''))
                .find(|s| !s.starts_with('$') && !s.is_empty())
                .unwrap_or("public")
                .to_string()
        }
        _ => "public".to_string(),
    }
}

/// Introspect MySQL tables using information_schema.
async fn introspect_mysql(pool: &AnyPool) -> Result<Vec<TableInfo>, BetterAuthError> {
    // Get the current database name
    let db_row = sqlx::query("SELECT DATABASE() as db_name")
        .fetch_optional(pool)
        .await
        .map_err(|e| BetterAuthError::Other(format!("MySQL database detection failed: {e}")))?;

    let db_name: String = db_row
        .as_ref()
        .and_then(|r| r.try_get::<String, _>("db_name").ok())
        .unwrap_or_default();

    if db_name.is_empty() {
        return Ok(Vec::new());
    }

    // Get tables
    let table_rows = sqlx::query(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = $1 AND table_type = 'BASE TABLE'",
    )
    .bind(&db_name)
    .fetch_all(pool)
    .await
    .map_err(|e| BetterAuthError::Other(format!("MySQL table introspection failed: {e}")))?;

    let mut tables = Vec::new();

    for row in &table_rows {
        let table_name: String = row
            .try_get("table_name")
            .map_err(|e| BetterAuthError::Other(format!("Failed to read table_name: {e}")))?;

        // Get columns
        let col_rows = sqlx::query(
            "SELECT column_name, data_type, is_nullable \
             FROM information_schema.columns \
             WHERE table_schema = $1 AND table_name = $2 \
             ORDER BY ordinal_position",
        )
        .bind(&db_name)
        .bind(&table_name)
        .fetch_all(pool)
        .await
        .map_err(|e| {
            BetterAuthError::Other(format!(
                "MySQL column introspection failed for {}: {}",
                table_name, e
            ))
        })?;

        let mut columns = Vec::new();
        for col_row in &col_rows {
            let name: String = col_row.try_get("column_name").unwrap_or_default();
            let data_type: String = col_row.try_get("data_type").unwrap_or_default();
            let is_nullable_str: String = col_row.try_get("is_nullable").unwrap_or_default();

            columns.push(ColumnInfo {
                name,
                data_type,
                is_nullable: is_nullable_str.to_uppercase() == "YES",
            });
        }

        tables.push(TableInfo {
            name: table_name,
            schema: db_name.clone(),
            columns,
        });
    }

    Ok(tables)
}

// ---------------------------------------------------------------------------
// Migration computation — the core diff logic
// ---------------------------------------------------------------------------

/// Compute migrations by comparing the target schema against the live database.
///
/// This is the Rust equivalent of the TS `getMigrations()` function.
/// It introspects the database, computes the diff, and builds the DDL statements.
pub async fn get_migrations(
    pool: &AnyPool,
    schema: &AuthSchema,
    db_type: DatabaseType,
    id_strategy: IdStrategy,
) -> Result<MigrationPlan, BetterAuthError> {
    // 1. Introspect existing tables
    let existing_tables = introspect_tables(pool, db_type).await?;

    // Build a lookup map: table_name → TableInfo
    let existing_map: HashMap<&str, &TableInfo> = existing_tables
        .iter()
        .map(|t| (t.name.as_str(), t))
        .collect();

    // 2. Compute the diff
    let mut to_be_created: Vec<TableToCreate> = Vec::new();
    let mut to_be_added: Vec<ColumnsToAdd> = Vec::new();
    let mut type_mismatches: Vec<TypeMismatch> = Vec::new();

    // Sort tables by their order field for dependency ordering
    let mut schema_tables: Vec<(&String, &AuthTable)> = schema.tables.iter().collect();
    schema_tables.sort_by_key(|(_, t)| t.order.unwrap_or(i32::MAX));

    for (table_name, table) in &schema_tables {
        let table_name_str = table_name.as_str();

        match existing_map.get(table_name_str) {
            None => {
                // Table doesn't exist — needs to be created
                // Check if we already have this table in to_be_created (from a plugin
                // extending the same table)
                let existing_idx = to_be_created.iter().position(|t| t.table == *table_name_str);
                if let Some(idx) = existing_idx {
                    // Merge fields into existing entry
                    to_be_created[idx]
                        .fields
                        .extend(table.fields.iter().map(|(k, v)| (k.clone(), v.clone())));
                } else {
                    to_be_created.push(TableToCreate {
                        table: table_name_str.to_string(),
                        fields: table.fields.clone(),
                        order: table.order.unwrap_or(i32::MAX),
                    });
                }
            }
            Some(existing_table) => {
                // Table exists — check for missing columns
                let _existing_columns: Vec<&str> =
                    existing_table.columns.iter().map(|c| c.name.as_str()).collect();

                let mut missing_fields: HashMap<String, SchemaField> = HashMap::new();

                for (field_name, field) in &table.fields {
                    if let Some(col) = existing_table
                        .columns
                        .iter()
                        .find(|c| c.name == *field_name)
                    {
                        // Column exists — check type match
                        if !match_type(&col.data_type, &field.field_type, db_type) {
                            type_mismatches.push(TypeMismatch {
                                table: table_name_str.to_string(),
                                field: field_name.clone(),
                                expected: field.field_type,
                                actual: col.data_type.clone(),
                            });
                        }
                    } else {
                        // Column doesn't exist — needs to be added
                        missing_fields.insert(field_name.clone(), field.clone());
                    }
                }

                if !missing_fields.is_empty() {
                    to_be_added.push(ColumnsToAdd {
                        table: table_name_str.to_string(),
                        fields: missing_fields,
                        order: table.order.unwrap_or(i32::MAX),
                    });
                }
            }
        }
    }

    // Sort to_be_created by order for dependency resolution
    to_be_created.sort_by_key(|t| t.order);

    // 3. Generate DDL statements
    let mut statements: Vec<String> = Vec::new();

    // ALTER TABLE ADD COLUMN for existing tables with missing columns
    for entry in &to_be_added {
        for (field_name, field) in &entry.fields {
            let alter = generate_alter_ddl(
                &entry.table,
                field_name,
                field,
                db_type,
                id_strategy,
            );
            statements.push(alter);
        }
    }

    // CREATE TABLE for entirely new tables
    if !to_be_created.is_empty() {
        // Build a temporary AuthSchema with only the tables to create,
        // then generate DDL for them.
        let mut create_schema = AuthSchema::new();
        for entry in &to_be_created {
            let mut auth_table = AuthTable::new(&entry.table);
            auth_table.order = Some(entry.order);
            for (field_name, field) in &entry.fields {
                if field_name != "id" {
                    auth_table = auth_table.field(field_name, field.clone());
                }
            }
            // Ensure id field is included
            if entry.fields.contains_key("id") {
                auth_table = auth_table.field("id", entry.fields["id"].clone());
            }
            create_schema = create_schema.table(auth_table);
        }
        let create_stmts = generate_ddl_for(&create_schema, db_type, id_strategy);
        statements.extend(create_stmts);
    }

    // CREATE INDEX for new tables
    if !to_be_created.is_empty() {
        let mut index_schema = AuthSchema::new();
        for entry in &to_be_created {
            let mut auth_table = AuthTable::new(&entry.table);
            for (field_name, field) in &entry.fields {
                auth_table = auth_table.field(field_name, field.clone());
            }
            index_schema = index_schema.table(auth_table);
        }
        let index_stmts = generate_index_ddl(&index_schema);
        statements.extend(index_stmts);
    }

    Ok(MigrationPlan {
        to_be_created,
        to_be_added,
        type_mismatches,
        statements,
    })
}

// ---------------------------------------------------------------------------
// Convenience — auto-detect DB type and compute migrations
// ---------------------------------------------------------------------------

/// Compute migrations with auto-detected database type.
///
/// This is the simplest entry point, equivalent to `getMigrations(config)` in TS.
pub async fn get_migrations_auto(
    pool: &AnyPool,
    schema: &AuthSchema,
) -> Result<MigrationPlan, BetterAuthError> {
    let db_type = detect_db_type(pool);
    get_migrations(pool, schema, db_type, IdStrategy::NanoId).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::db::schema::AuthSchema;

    #[test]
    fn test_detect_db_type_defaults_sqlite() {
        // We can't easily create a real pool in a sync test, but we test the
        // migration plan compilation and diff logic.
        let plan = MigrationPlan {
            to_be_created: vec![],
            to_be_added: vec![],
            type_mismatches: vec![],
            statements: vec![],
        };
        assert!(!plan.has_pending());
        assert_eq!(plan.compile(), ";");
    }

    #[test]
    fn test_migration_plan_compile_with_statements() {
        let plan = MigrationPlan {
            to_be_created: vec![TableToCreate {
                table: "user".to_string(),
                fields: HashMap::new(),
                order: 0,
            }],
            to_be_added: vec![],
            type_mismatches: vec![],
            statements: vec![
                "CREATE TABLE \"user\" (\"id\" text PRIMARY KEY NOT NULL)".to_string(),
            ],
        };
        assert!(plan.has_pending());
        let compiled = plan.compile();
        assert!(compiled.contains("CREATE TABLE"));
        assert!(compiled.ends_with(';'));
    }

    #[test]
    fn test_migration_plan_compile_multiple() {
        let plan = MigrationPlan {
            to_be_created: vec![],
            to_be_added: vec![ColumnsToAdd {
                table: "user".to_string(),
                fields: HashMap::new(),
                order: 0,
            }],
            type_mismatches: vec![],
            statements: vec![
                "ALTER TABLE \"user\" ADD COLUMN \"role\" text".to_string(),
                "ALTER TABLE \"session\" ADD COLUMN \"impersonatedBy\" text".to_string(),
            ],
        };
        assert!(plan.has_pending());
        let compiled = plan.compile();
        assert!(compiled.contains("ALTER TABLE \"user\""));
        assert!(compiled.contains("ALTER TABLE \"session\""));
    }

    #[tokio::test]
    async fn test_get_migrations_sqlite_empty_db() {
        // Create an in-memory SQLite database
        sqlx::any::install_default_drivers();
        let pool = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("Failed to create SQLite pool");

        let schema = AuthSchema::core_schema();
        let plan = get_migrations(&pool, &schema, DatabaseType::Sqlite, IdStrategy::NanoId)
            .await
            .expect("Migration computation failed");

        // All 4 core tables should need to be created
        assert_eq!(
            plan.to_be_created.len(),
            4,
            "Expected 4 tables to create, got {}",
            plan.to_be_created.len()
        );
        assert!(plan.to_be_added.is_empty());
        assert!(plan.type_mismatches.is_empty());

        let table_names: Vec<&str> = plan.to_be_created.iter().map(|t| t.table.as_str()).collect();
        assert!(table_names.contains(&"user"));
        assert!(table_names.contains(&"session"));
        assert!(table_names.contains(&"account"));
        assert!(table_names.contains(&"verification"));

        // Should have CREATE TABLE statements
        assert!(!plan.statements.is_empty());
        let compiled = plan.compile();
        assert!(compiled.contains("CREATE TABLE"));
    }

    #[tokio::test]
    async fn test_get_migrations_sqlite_partial_schema() {
        // Create SQLite and add only the user table
        sqlx::any::install_default_drivers();
        let pool = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("Failed to create SQLite pool");

        // Create the user table manually
        sqlx::query(
            r#"CREATE TABLE "user" (
                "id" TEXT PRIMARY KEY NOT NULL,
                "name" TEXT NOT NULL,
                "email" TEXT NOT NULL UNIQUE,
                "emailVerified" INTEGER NOT NULL DEFAULT 0,
                "image" TEXT,
                "createdAt" TEXT NOT NULL,
                "updatedAt" TEXT NOT NULL
            )"#,
        )
        .execute(&pool)
        .await
        .expect("Failed to create user table");

        let schema = AuthSchema::core_schema();
        let plan = get_migrations(&pool, &schema, DatabaseType::Sqlite, IdStrategy::NanoId)
            .await
            .expect("Migration computation failed");

        // user table exists, so we should only create the other 3
        assert_eq!(
            plan.to_be_created.len(),
            3,
            "Expected 3 tables to create, got {}",
            plan.to_be_created.len()
        );
        assert!(
            plan.to_be_added.is_empty(),
            "Expected no columns to add, got {:?}",
            plan.to_be_added
        );

        let created_names: Vec<&str> =
            plan.to_be_created.iter().map(|t| t.table.as_str()).collect();
        assert!(!created_names.contains(&"user"), "user table should NOT be in to_be_created");
        assert!(created_names.contains(&"session"));
        assert!(created_names.contains(&"account"));
        assert!(created_names.contains(&"verification"));
    }

    #[tokio::test]
    async fn test_get_migrations_sqlite_missing_columns() {
        // Create SQLite with a user table missing the 'image' column
        sqlx::any::install_default_drivers();
        let pool = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("Failed to create SQLite pool");

        // Create user table WITHOUT the 'image' column
        sqlx::query(
            r#"CREATE TABLE "user" (
                "id" TEXT PRIMARY KEY NOT NULL,
                "name" TEXT NOT NULL,
                "email" TEXT NOT NULL UNIQUE,
                "emailVerified" INTEGER NOT NULL DEFAULT 0,
                "createdAt" TEXT NOT NULL,
                "updatedAt" TEXT NOT NULL
            )"#,
        )
        .execute(&pool)
        .await
        .expect("Failed to create user table");

        let schema = AuthSchema::core_schema();
        let plan = get_migrations(&pool, &schema, DatabaseType::Sqlite, IdStrategy::NanoId)
            .await
            .expect("Migration computation failed");

        // user table exists but is missing 'image'
        assert_eq!(plan.to_be_created.len(), 3); // session, account, verification
        assert_eq!(plan.to_be_added.len(), 1); // user.image
        assert_eq!(plan.to_be_added[0].table, "user");
        assert!(plan.to_be_added[0].fields.contains_key("image"));
    }

    #[tokio::test]
    async fn test_run_migrations_then_recheck() {
        // Full round-trip: compute, run, then re-check should show no pending
        sqlx::any::install_default_drivers();
        let pool = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("Failed to create SQLite pool");

        let schema = AuthSchema::core_schema();

        // First pass: everything needs to be created
        let plan = get_migrations(&pool, &schema, DatabaseType::Sqlite, IdStrategy::NanoId)
            .await
            .expect("Migration computation failed");
        assert!(plan.has_pending());

        // Run the migrations
        plan.run(&pool).await.expect("Migration run failed");

        // Second pass: nothing should be pending
        let plan2 = get_migrations(&pool, &schema, DatabaseType::Sqlite, IdStrategy::NanoId)
            .await
            .expect("Second migration computation failed");
        assert!(
            !plan2.has_pending(),
            "Expected no pending migrations after running, but got: {:?} to_create, {:?} to_add",
            plan2.to_be_created.len(),
            plan2.to_be_added.len()
        );
        assert_eq!(plan2.compile(), ";");
    }

    #[tokio::test]
    async fn test_run_migrations_then_add_plugin_columns() {
        // Simulates the TS test: run base migrations, then add plugin fields
        sqlx::any::install_default_drivers();
        let pool = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("Failed to create SQLite pool");

        // 1. Run core schema
        let core_schema = AuthSchema::core_schema();
        let plan = get_migrations(&pool, &core_schema, DatabaseType::Sqlite, IdStrategy::NanoId)
            .await
            .unwrap();
        plan.run(&pool).await.unwrap();

        // 2. Add plugin fields to the schema
        let mut extended_schema = AuthSchema::core_schema();
        // Add "role" to user table (like the admin plugin)
        if let Some(user_table) = extended_schema.tables.get_mut("user") {
            user_table
                .fields
                .insert("role".to_string(), SchemaField::optional_string());
        }
        // Add "impersonatedBy" to session table
        if let Some(session_table) = extended_schema.tables.get_mut("session") {
            session_table
                .fields
                .insert("impersonatedBy".to_string(), SchemaField::optional_string());
        }

        // 3. Compute differential migrations
        let plan2 =
            get_migrations(&pool, &extended_schema, DatabaseType::Sqlite, IdStrategy::NanoId)
                .await
                .unwrap();

        // Should have 0 tables to create, 2 tables with columns to add
        assert_eq!(plan2.to_be_created.len(), 0);
        assert_eq!(plan2.to_be_added.len(), 2);

        let user_adds = plan2
            .to_be_added
            .iter()
            .find(|a| a.table == "user")
            .expect("Expected user table in to_be_added");
        assert!(user_adds.fields.contains_key("role"));

        let session_adds = plan2
            .to_be_added
            .iter()
            .find(|a| a.table == "session")
            .expect("Expected session table in to_be_added");
        assert!(session_adds.fields.contains_key("impersonatedBy"));

        // 4. Run the differential migrations
        plan2.run(&pool).await.unwrap();

        // 5. Re-check: nothing pending
        let plan3 =
            get_migrations(&pool, &extended_schema, DatabaseType::Sqlite, IdStrategy::NanoId)
                .await
                .unwrap();
        assert!(!plan3.has_pending());
    }
}
