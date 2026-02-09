// Integration tests for the SqlxAdapter using SQLite in-memory.
//
// Tests the full CRUD lifecycle, transactions, and schema migration.

use better_auth_core::db::adapter::{
    Adapter, FindManyQuery, SchemaOptions, SortBy, SortDirection, WhereClause,
};
use better_auth_core::db::schema::AuthSchema;
use better_auth_sqlx::SqlxAdapter;

/// Helper: create a fresh SQLite in-memory adapter with the core schema.
async fn setup_adapter() -> SqlxAdapter {
    let adapter = SqlxAdapter::connect("sqlite::memory:")
        .await
        .expect("Failed to connect to SQLite in-memory");

    let schema = AuthSchema::core_schema();
    adapter
        .create_schema(&schema, &SchemaOptions { auto_migrate: true })
        .await
        .expect("Failed to create schema");

    adapter
}

// ─── CRUD Lifecycle ──────────────────────────────────────────────

#[tokio::test]
async fn test_create_and_find_user() {
    let adapter = setup_adapter().await;

    // Create
    let user = adapter
        .create(
            "user",
            serde_json::json!({
                "id": "user-1",
                "name": "Alice",
                "email": "alice@example.com",
                "emailVerified": "false",
                "createdAt": "2025-01-01T00:00:00Z",
                "updatedAt": "2025-01-01T00:00:00Z"
            }),
            None,
        )
        .await
        .expect("Create user failed");

    assert_eq!(user["id"], "user-1");
    assert_eq!(user["name"], "Alice");
    assert_eq!(user["email"], "alice@example.com");

    // FindOne by ID
    let found = adapter
        .find_one("user", &[WhereClause::eq("id", "user-1")])
        .await
        .expect("FindOne failed");

    assert!(found.is_some());
    assert_eq!(found.unwrap()["email"], "alice@example.com");
}

#[tokio::test]
async fn test_find_one_not_found() {
    let adapter = setup_adapter().await;

    let result = adapter
        .find_one("user", &[WhereClause::eq("id", "nonexistent")])
        .await
        .expect("FindOne should not error");

    assert!(result.is_none());
}

#[tokio::test]
async fn test_update_user() {
    let adapter = setup_adapter().await;

    // Create
    adapter
        .create(
            "user",
            serde_json::json!({
                "id": "user-2",
                "name": "Bob",
                "email": "bob@example.com",
                "emailVerified": "false",
                "createdAt": "2025-01-01T00:00:00Z",
                "updatedAt": "2025-01-01T00:00:00Z"
            }),
            None,
        )
        .await
        .unwrap();

    // Update
    let updated = adapter
        .update(
            "user",
            &[WhereClause::eq("id", "user-2")],
            serde_json::json!({ "name": "Robert" }),
        )
        .await
        .expect("Update failed");

    assert!(updated.is_some());
    let updated = updated.unwrap();
    assert_eq!(updated["name"], "Robert");
    assert_eq!(updated["email"], "bob@example.com");
}

#[tokio::test]
async fn test_delete_user() {
    let adapter = setup_adapter().await;

    // Create
    adapter
        .create(
            "user",
            serde_json::json!({
                "id": "user-3",
                "name": "Charlie",
                "email": "charlie@example.com",
                "emailVerified": "false",
                "createdAt": "2025-01-01T00:00:00Z",
                "updatedAt": "2025-01-01T00:00:00Z"
            }),
            None,
        )
        .await
        .unwrap();

    // Delete
    adapter
        .delete("user", &[WhereClause::eq("id", "user-3")])
        .await
        .expect("Delete failed");

    // Verify gone
    let found = adapter
        .find_one("user", &[WhereClause::eq("id", "user-3")])
        .await
        .unwrap();

    assert!(found.is_none());
}

// ─── FindMany + Sorting + Pagination ─────────────────────────────

#[tokio::test]
async fn test_find_many_with_sort_and_limit() {
    let adapter = setup_adapter().await;

    // Create 3 users
    for (id, name) in [("a", "Alice"), ("b", "Bob"), ("c", "Charlie")] {
        adapter
            .create(
                "user",
                serde_json::json!({
                    "id": id,
                    "name": name,
                    "email": format!("{}@example.com", name.to_lowercase()),
                    "emailVerified": "false",
                    "createdAt": "2025-01-01T00:00:00Z",
                    "updatedAt": "2025-01-01T00:00:00Z"
                }),
                None,
            )
            .await
            .unwrap();
    }

    // FindMany with sort DESC and limit 2
    let results = adapter
        .find_many(
            "user",
            FindManyQuery {
                sort_by: Some(SortBy {
                    field: "name".into(),
                    direction: SortDirection::Desc,
                }),
                limit: Some(2),
                ..Default::default()
            },
        )
        .await
        .expect("FindMany failed");

    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["name"], "Charlie");
    assert_eq!(results[1]["name"], "Bob");
}

#[tokio::test]
async fn test_find_many_with_offset() {
    let adapter = setup_adapter().await;

    // Create 3 users
    for (id, name) in [("a", "Alice"), ("b", "Bob"), ("c", "Charlie")] {
        adapter
            .create(
                "user",
                serde_json::json!({
                    "id": id,
                    "name": name,
                    "email": format!("{}@example.com", name.to_lowercase()),
                    "emailVerified": "false",
                    "createdAt": "2025-01-01T00:00:00Z",
                    "updatedAt": "2025-01-01T00:00:00Z"
                }),
                None,
            )
            .await
            .unwrap();
    }

    // FindMany with offset=1, sorted ASC
    let results = adapter
        .find_many(
            "user",
            FindManyQuery {
                sort_by: Some(SortBy {
                    field: "name".into(),
                    direction: SortDirection::Asc,
                }),
                offset: Some(1),
                ..Default::default()
            },
        )
        .await
        .expect("FindMany failed");

    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["name"], "Bob");
}

// ─── Count ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_count() {
    let adapter = setup_adapter().await;

    // Empty table
    let count = adapter.count("user", &[]).await.expect("Count failed");
    assert_eq!(count, 0);

    // Create 2 users
    for id in ["u1", "u2"] {
        adapter
            .create(
                "user",
                serde_json::json!({
                    "id": id,
                    "name": "Test",
                    "email": format!("{}@example.com", id),
                    "emailVerified": "false",
                    "createdAt": "2025-01-01T00:00:00Z",
                    "updatedAt": "2025-01-01T00:00:00Z"
                }),
                None,
            )
            .await
            .unwrap();
    }

    let count = adapter.count("user", &[]).await.expect("Count failed");
    assert_eq!(count, 2);

    // Count with filter
    let count = adapter
        .count("user", &[WhereClause::eq("id", "u1")])
        .await
        .expect("Count failed");
    assert_eq!(count, 1);
}

// ─── UpdateMany + DeleteMany ────────────────────────────────────

#[tokio::test]
async fn test_update_many() {
    let adapter = setup_adapter().await;

    // Create 2 users with same name
    for id in ["m1", "m2"] {
        adapter
            .create(
                "user",
                serde_json::json!({
                    "id": id,
                    "name": "Test",
                    "email": format!("{}@example.com", id),
                    "emailVerified": "false",
                    "createdAt": "2025-01-01T00:00:00Z",
                    "updatedAt": "2025-01-01T00:00:00Z"
                }),
                None,
            )
            .await
            .unwrap();
    }

    // Update both
    let affected = adapter
        .update_many(
            "user",
            &[WhereClause::eq("name", "Test")],
            serde_json::json!({ "name": "Updated" }),
        )
        .await
        .expect("UpdateMany failed");

    assert_eq!(affected, 2);

    // Verify both updated
    let results = adapter
        .find_many("user", FindManyQuery::default())
        .await
        .unwrap();
    assert!(results.iter().all(|u| u["name"] == "Updated"));
}

#[tokio::test]
async fn test_delete_many() {
    let adapter = setup_adapter().await;

    for id in ["d1", "d2", "d3"] {
        adapter
            .create(
                "user",
                serde_json::json!({
                    "id": id,
                    "name": "Delete",
                    "email": format!("{}@example.com", id),
                    "emailVerified": "false",
                    "createdAt": "2025-01-01T00:00:00Z",
                    "updatedAt": "2025-01-01T00:00:00Z"
                }),
                None,
            )
            .await
            .unwrap();
    }

    let deleted = adapter
        .delete_many("user", &[WhereClause::eq("name", "Delete")])
        .await
        .expect("DeleteMany failed");

    assert_eq!(deleted, 3);

    let count = adapter.count("user", &[]).await.unwrap();
    assert_eq!(count, 0);
}

// ─── Sessions + Accounts ────────────────────────────────────────

#[tokio::test]
async fn test_session_crud() {
    let adapter = setup_adapter().await;

    // Create user first
    adapter
        .create(
            "user",
            serde_json::json!({
                "id": "u1",
                "name": "Alice",
                "email": "alice@example.com",
                "emailVerified": "false",
                "createdAt": "2025-01-01T00:00:00Z",
                "updatedAt": "2025-01-01T00:00:00Z"
            }),
            None,
        )
        .await
        .unwrap();

    // Create session
    let session = adapter
        .create(
            "session",
            serde_json::json!({
                "id": "s1",
                "token": "tok-abc",
                "userId": "u1",
                "expiresAt": "2025-12-31T23:59:59Z",
                "createdAt": "2025-01-01T00:00:00Z",
                "updatedAt": "2025-01-01T00:00:00Z"
            }),
            None,
        )
        .await
        .expect("Create session failed");

    assert_eq!(session["token"], "tok-abc");

    // Find by token
    let found = adapter
        .find_one("session", &[WhereClause::eq("token", "tok-abc")])
        .await
        .unwrap();

    assert!(found.is_some());
    assert_eq!(found.unwrap()["userId"], "u1");

    // Delete session
    adapter
        .delete("session", &[WhereClause::eq("token", "tok-abc")])
        .await
        .unwrap();

    let found = adapter
        .find_one("session", &[WhereClause::eq("token", "tok-abc")])
        .await
        .unwrap();

    assert!(found.is_none());
}

// ─── Transactions ───────────────────────────────────────────────

#[tokio::test]
async fn test_transaction_commit() {
    let adapter = setup_adapter().await;

    // Begin transaction
    let tx = adapter
        .begin_transaction()
        .await
        .expect("Begin transaction failed");

    // Create inside transaction
    tx.create(
        "user",
        serde_json::json!({
            "id": "tx-u1",
            "name": "TxUser",
            "email": "tx@example.com",
            "emailVerified": "false",
            "createdAt": "2025-01-01T00:00:00Z",
            "updatedAt": "2025-01-01T00:00:00Z"
        }),
        None,
    )
    .await
    .expect("Create in transaction failed");

    // Commit
    tx.commit().await.expect("Commit failed");

    // Verify the user exists outside the transaction
    let found = adapter
        .find_one("user", &[WhereClause::eq("id", "tx-u1")])
        .await
        .unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap()["name"], "TxUser");
}

#[tokio::test]
async fn test_transaction_rollback() {
    let adapter = setup_adapter().await;

    // Begin transaction
    let tx = adapter
        .begin_transaction()
        .await
        .expect("Begin transaction failed");

    // Create inside transaction
    tx.create(
        "user",
        serde_json::json!({
            "id": "tx-u2",
            "name": "RollbackUser",
            "email": "rollback@example.com",
            "emailVerified": "false",
            "createdAt": "2025-01-01T00:00:00Z",
            "updatedAt": "2025-01-01T00:00:00Z"
        }),
        None,
    )
    .await
    .expect("Create in transaction failed");

    // Rollback
    tx.rollback().await.expect("Rollback failed");

    // Verify the user does NOT exist
    let found = adapter
        .find_one("user", &[WhereClause::eq("id", "tx-u2")])
        .await
        .unwrap();
    assert!(found.is_none());
}

// ─── Schema Migration ───────────────────────────────────────────

#[tokio::test]
async fn test_schema_creation() {
    let adapter = SqlxAdapter::connect("sqlite::memory:")
        .await
        .expect("Failed to connect");

    let schema = AuthSchema::core_schema();
    let status = adapter
        .create_schema(&schema, &SchemaOptions { auto_migrate: true })
        .await
        .expect("Schema creation failed");

    // Should have generated DDL statements
    match status {
        better_auth_core::db::adapter::SchemaStatus::NeedsMigration { statements } => {
            assert!(
                statements.len() >= 4,
                "Expected at least 4 CREATE TABLE statements, got {}",
                statements.len()
            );
        }
        _ => {} // UpToDate is fine too if tables already existed
    }

    // Verify tables exist by inserting data
    let result = adapter
        .create(
            "user",
            serde_json::json!({
                "id": "schema-test",
                "name": "SchemaTest",
                "email": "schema@test.com",
                "emailVerified": "false",
                "createdAt": "2025-01-01T00:00:00Z",
                "updatedAt": "2025-01-01T00:00:00Z"
            }),
            None,
        )
        .await;

    assert!(result.is_ok(), "Insert after schema creation should work");
}

// ─── Idempotent Schema ──────────────────────────────────────────

#[tokio::test]
async fn test_schema_idempotent() {
    let adapter = SqlxAdapter::connect("sqlite::memory:")
        .await
        .expect("Failed to connect");

    let schema = AuthSchema::core_schema();

    // Run twice — should not error
    adapter
        .create_schema(&schema, &SchemaOptions { auto_migrate: true })
        .await
        .expect("First schema creation failed");

    adapter
        .create_schema(&schema, &SchemaOptions { auto_migrate: true })
        .await
        .expect("Second schema creation should be idempotent");
}
