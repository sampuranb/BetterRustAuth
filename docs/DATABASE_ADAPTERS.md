# Database Adapters

This document describes how to configure and use the database adapters available in BetterRustAuth.

## Overview

All database operations in BetterRustAuth go through the `InternalAdapter` trait. This provides complete database agnosticism — you can swap databases by changing a single dependency.

```rust
#[async_trait]
pub trait InternalAdapter: Send + Sync {
    // User operations
    async fn create_user(&self, user: Value) -> Result<Value, AdapterError>;
    async fn find_user_by_email(&self, email: &str) -> Result<Option<Value>, AdapterError>;
    async fn find_user_by_id(&self, id: &str) -> Result<Option<Value>, AdapterError>;
    async fn update_user(&self, id: &str, data: Value) -> Result<Value, AdapterError>;
    async fn delete_user(&self, id: &str) -> Result<(), AdapterError>;

    // Session operations
    async fn create_session(&self, session: Value) -> Result<Value, AdapterError>;
    async fn find_session_and_user(&self, token: &str) -> Result<Option<SessionAndUser>, AdapterError>;
    async fn update_session(&self, token: &str, data: Value) -> Result<Value, AdapterError>;
    async fn delete_session(&self, token: &str) -> Result<(), AdapterError>;
    async fn list_sessions_for_user(&self, user_id: &str) -> Result<Vec<Value>, AdapterError>;
    async fn delete_sessions_for_user(&self, user_id: &str) -> Result<(), AdapterError>;

    // Account operations (OAuth)
    async fn create_account(&self, account: Value) -> Result<Value, AdapterError>;
    async fn find_accounts(&self, user_id: &str) -> Result<Vec<Value>, AdapterError>;
    async fn find_account_by_provider(&self, provider: &str, account_id: &str) -> Result<Option<Value>, AdapterError>;
    async fn delete_account(&self, provider: &str, account_id: &str) -> Result<(), AdapterError>;

    // Verification operations
    async fn create_verification(&self, verification: Value) -> Result<Value, AdapterError>;
    async fn find_verification(&self, identifier: &str) -> Result<Option<Value>, AdapterError>;
    async fn delete_verification(&self, identifier: &str) -> Result<(), AdapterError>;

    // ... and more (40+ methods total)
}
```

## SQLx Adapter

**Crate:** `better-auth-sqlx`

The recommended adapter for SQL databases. Supports SQLite, PostgreSQL, and MySQL.

### SQLite

```toml
[dependencies]
better-auth-sqlx = { version = "0.1", features = ["sqlite"] }
```

```rust
use better_auth_sqlx::SqlxAdapter;

let pool = sqlx::SqlitePool::connect("sqlite:./auth.db").await?;
let adapter = Arc::new(SqlxAdapter::new(pool));
```

### PostgreSQL

```toml
[dependencies]
better-auth-sqlx = { version = "0.1", features = ["postgres"] }
```

```rust
let pool = sqlx::PgPool::connect("postgres://user:pass@localhost/auth").await?;
let adapter = Arc::new(SqlxAdapter::new(pool));
```

### MySQL

```toml
[dependencies]
better-auth-sqlx = { version = "0.1", features = ["mysql"] }
```

```rust
let pool = sqlx::MySqlPool::connect("mysql://user:pass@localhost/auth").await?;
let adapter = Arc::new(SqlxAdapter::new(pool));
```

### Schema

The SQLx adapter expects the following tables:

```sql
CREATE TABLE "user" (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    "emailVerified" BOOLEAN NOT NULL DEFAULT FALSE,
    image TEXT,
    "createdAt" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE "session" (
    id TEXT PRIMARY KEY,
    "userId" TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    "expiresAt" TIMESTAMP NOT NULL,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "createdAt" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE "account" (
    id TEXT PRIMARY KEY,
    "userId" TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    "accountId" TEXT NOT NULL,
    "providerId" TEXT NOT NULL,
    "accessToken" TEXT,
    "refreshToken" TEXT,
    "accessTokenExpiresAt" TIMESTAMP,
    "refreshTokenExpiresAt" TIMESTAMP,
    scope TEXT,
    "idToken" TEXT,
    password TEXT,
    "createdAt" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE("providerId", "accountId")
);

CREATE TABLE "verification" (
    id TEXT PRIMARY KEY,
    identifier TEXT NOT NULL,
    value TEXT NOT NULL,
    "expiresAt" TIMESTAMP NOT NULL,
    "createdAt" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

## Diesel Adapter

**Crate:** `better-auth-diesel`

For projects already using Diesel ORM.

```toml
[dependencies]
better-auth-diesel = { version = "0.1", features = ["sqlite"] }
```

## SeaORM Adapter

**Crate:** `better-auth-sea-orm`

For projects using SeaORM.

```toml
[dependencies]
better-auth-sea-orm = "0.1"
```

## MongoDB Adapter

**Crate:** `better-auth-mongodb`

Document-based storage with MongoDB.

```toml
[dependencies]
better-auth-mongodb = "0.1"
```

```rust
use better_auth_mongodb::MongoAdapter;

let client = mongodb::Client::with_uri_str("mongodb://localhost:27017").await?;
let db = client.database("auth");
let adapter = Arc::new(MongoAdapter::new(db));
```

## In-Memory Adapter

**Crate:** `better-auth-memory`

For development and testing. Data is lost on restart.

```toml
[dependencies]
better-auth-memory = "0.1"
```

```rust
use better_auth_memory::MemoryAdapter;

let adapter = Arc::new(MemoryAdapter::new());
```

## Implementing a Custom Adapter

To create your own adapter, implement the `InternalAdapter` trait:

```rust
use async_trait::async_trait;
use better_auth::internal_adapter::{InternalAdapter, AdapterError, SessionAndUser};
use serde_json::Value;

pub struct MyAdapter { /* ... */ }

#[async_trait]
impl InternalAdapter for MyAdapter {
    async fn create_user(&self, user: Value) -> Result<Value, AdapterError> {
        // Your implementation
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<Value>, AdapterError> {
        // Your implementation
    }

    // ... implement all required methods
}
```
