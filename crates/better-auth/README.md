# better-auth

Core Rust implementation of [Better Auth](https://www.better-auth.com/) --
a comprehensive, framework-agnostic authentication and authorization library.

This crate contains the authentication engine: request routing, session
management, password hashing, cookie handling, OAuth flows, email
verification, and the plugin runtime. It is framework-agnostic; pair it
with `better-auth-axum` or `better-auth-actix` for HTTP integration.

## Usage

```rust,ignore
use std::sync::Arc;
use better_auth::context::AuthContext;
use better_auth::internal_adapter::InternalAdapter;
use better_auth_core::options::BetterAuthOptions;

// 1. Configure options
let options = BetterAuthOptions::new("my-secret-key-at-least-32-chars!")
    .with_base_url("https://example.com");

// 2. Provide a database adapter (implements InternalAdapter)
let adapter: Arc<dyn InternalAdapter> = /* your adapter */;

// 3. Build the auth context
let ctx = AuthContext::new(options, adapter);

// 4. Pass `Arc<AuthContext>` to your HTTP integration crate
```

## Features

- **Email / password** authentication with configurable password policies
- **OAuth2 / social login** via 33 built-in providers (see `better-auth-oauth2`)
- **Session management** -- creation, refresh, revocation, multi-device listing
- **Cookie handling** with secure defaults, CSRF protection, and configurable prefixes
- **Email verification** flow with token generation and validation
- **Password reset** -- forgot-password, reset-password, change-password endpoints
- **Account linking** -- link/unlink social accounts, access-token retrieval
- **Plugin system** -- extend the auth engine with custom endpoints and hooks
- **Rate limiting** and origin/CSRF middleware built in
- **Structured logging** via `better-auth-core` logger

## Crate layout

| Module              | Purpose                                      |
|---------------------|----------------------------------------------|
| `api`               | High-level API surface                       |
| `context`           | `AuthContext` -- the shared request state     |
| `cookies`           | Cookie builder and response helpers           |
| `crypto`            | Password hashing (argon2/bcrypt) and tokens   |
| `db`                | Database hook registry                        |
| `internal_adapter`  | `InternalAdapter` trait for storage backends  |
| `middleware`        | Origin check, rate limiting                   |
| `oauth`             | OAuth flow orchestration                      |
| `plugins`           | Built-in plugin implementations               |
| `plugin_runtime`    | Plugin endpoint router and lifecycle          |
| `routes`            | All auth route handlers                       |
| `verification`      | Email / token verification helpers            |

## Related crates

| Crate                  | Role                          |
|------------------------|-------------------------------|
| `better-auth-core`     | Shared types, options, traits |
| `better-auth-oauth2`   | OAuth2 protocol layer         |
| `better-auth-axum`     | Axum HTTP integration         |
| `better-auth-actix`    | Actix-web HTTP integration    |

## License

See the repository root for license information.
