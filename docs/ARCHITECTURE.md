# Architecture

This document describes the internal architecture of BetterRustAuth, how the crates relate to each other, and the key design decisions.

## Layered Architecture

BetterRustAuth follows a strict layered architecture:

```
┌──────────────────────────────────────────────────────────┐
│                   Framework Adapters                      │
│  better-auth-axum, better-auth-actix, better-auth-leptos │
├──────────────────────────────────────────────────────────┤
│                   Core Library                            │
│  better-auth (routes, plugins, handler, middleware)       │
├──────────────────────────────────────────────────────────┤
│                   Core Types                              │
│  better-auth-core (options, hooks, logger)                │
├──────────────────────────────────────────────────────────┤
│                   OAuth2 Client                           │
│  better-auth-oauth2 (providers, token exchange, PKCE)     │
├──────────────────────────────────────────────────────────┤
│                   Database Adapters                        │
│  better-auth-sqlx, diesel, sea-orm, mongodb, memory       │
└──────────────────────────────────────────────────────────┘
```

Each layer only depends on layers below it. The core library has no knowledge of which framework or database is used at runtime.

## Key Abstractions

### `AuthContext` (context.rs)

The central struct that holds all resolved configuration and shared state:

```rust
pub struct AuthContext {
    pub options: BetterAuthOptions,      // Original config
    pub secret: String,                  // Signing key
    pub base_url: Option<String>,        // Server base URL
    pub base_path: String,               // Auth route prefix
    pub auth_cookies: BetterAuthCookies, // Pre-computed cookie names
    pub trusted_origins: Vec<String>,    // Allowed origins
    pub session_config: SessionConfig,   // Session TTL/refresh
    pub adapter: Arc<dyn InternalAdapter>, // Database layer
    pub rate_limiter: Arc<RateLimiter>,  // Per-IP rate limiting
    pub plugin_registry: PluginRegistry, // Enabled plugins
    pub logger: AuthLogger,             // Structured logger
    // ...
}
```

Created once at startup and shared as `Arc<AuthContext>` across all request handlers.

### `InternalAdapter` (internal_adapter.rs)

The database abstraction trait with 40+ methods:

```rust
pub trait InternalAdapter: Send + Sync {
    async fn create_user(&self, user: Value) -> Result<Value, AdapterError>;
    async fn find_user_by_email(&self, email: &str) -> Result<Option<Value>, AdapterError>;
    async fn find_user_by_id(&self, id: &str) -> Result<Option<Value>, AdapterError>;
    async fn create_session(&self, session: Value) -> Result<Value, AdapterError>;
    async fn find_session_and_user(&self, token: &str) -> Result<Option<SessionAndUser>, AdapterError>;
    async fn update_session(&self, token: &str, data: Value) -> Result<Value, AdapterError>;
    // ... 35+ more methods
}
```

### `GenericRequest` / `GenericResponse` (api/)

Framework-agnostic request/response types that decouple auth logic from HTTP frameworks:

```rust
pub struct GenericRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, Vec<String>>,
    pub body: Option<String>,
    pub query_string: Option<String>,
}

pub struct GenericResponse {
    pub status: u16,
    pub headers: HashMap<String, Vec<String>>,
    pub body: Option<String>,
}
```

### Plugin System

Plugins implement the `BetterAuthPlugin` trait:

```rust
pub trait BetterAuthPlugin: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn endpoints(&self) -> Vec<PluginEndpoint>;
    fn schema(&self) -> Vec<AuthTable> { vec![] }
    fn rate_limit_paths(&self) -> Vec<(String, RateLimitRule)> { vec![] }
}
```

Plugins are feature-gated to keep binary size small:
```toml
[features]
plugin-two-factor = []
plugin-admin = []
plugin-email-otp = []
```

## Request Processing Pipeline

1. **Framework adapter** converts the raw HTTP request into a `GenericRequest`
2. **`handle_auth_request`** strips the base path and runs middleware:
   - Origin/CSRF validation
   - Rate limiting
   - Disabled paths check
3. **`route_request`** dispatches to the correct handler based on method + path
4. **Route handler** processes business logic, interacting with `InternalAdapter`
5. **Response** flows back as `GenericResponse`, converted by the framework adapter

## Security Model

### Password Hashing
- **scrypt** with configurable parameters (log_n=15, r=8, p=1 by default)
- Constant-time comparison for hash verification

### Token Security
- Session tokens: 32 random bytes, base64-encoded
- Verification tokens: ChaCha20-Poly1305 encrypted JWTs
- OAuth state: HMAC-SHA256 signed with PKCE challenge

### Cookie Security
- `HttpOnly` flag on session cookies
- `Secure` flag auto-detected from base URL protocol
- `SameSite=Lax` default
- Configurable `__Secure-` cookie prefix for HTTPS

### CSRF Protection
- Origin header validation against trusted origins
- Configurable bypass for specific paths (e.g., OAuth callbacks)
