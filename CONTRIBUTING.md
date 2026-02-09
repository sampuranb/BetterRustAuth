# Contributing to BetterRustAuth

Thank you for your interest in contributing to BetterRustAuth! This document provides guidelines and information to help you get started.

## Development Setup

### Prerequisites

- **Rust 1.85+** (install via [rustup](https://rustup.rs/))
- **Git**
- **SQLite** (for running tests with the default adapter)

### Getting Started

```bash
# Clone the repository
git clone https://github.com/sampuranb/BetterRustAuth.git
cd BetterRustAuth

# Build the workspace
cargo build

# Run tests
cargo test -p better-auth -p better-auth-axum

# Run tests with specific plugins enabled
cargo test -p better-auth --features plugin-two-factor,plugin-admin
```

## Project Structure

The project is organized as a Cargo workspace with 22 crates:

### Core Crates
- `better-auth-core` — Shared types, options, hooks, and logger
- `better-auth` — Main library with routes, plugins, middleware, and request handler
- `better-auth-oauth2` — OAuth2 client implementation with 33 provider configs

### Framework Integration Crates
- `better-auth-axum` — Axum adapter
- `better-auth-actix` — Actix-web adapter
- `better-auth-leptos` — Leptos adapter
- `better-auth-dioxus` — Dioxus adapter
- `better-auth-yew` — Yew adapter

### Database Adapter Crates
- `better-auth-sqlx` — SQLx (SQLite, PostgreSQL, MySQL)
- `better-auth-diesel` — Diesel ORM
- `better-auth-sea-orm` — SeaORM
- `better-auth-mongodb` — MongoDB
- `better-auth-memory` — In-memory (dev/testing)
- `better-auth-redis` — Redis secondary storage

### Extension Crates
- `better-auth-client` — Rust client SDK
- `better-auth-cli` — CLI tool
- `better-auth-passkey` — WebAuthn/Passkey
- `better-auth-sso` — SAML SSO
- `better-auth-stripe` — Stripe billing
- `better-auth-scim` — SCIM 2.0
- `better-auth-i18n` — Internationalization
- `better-auth-oauth-provider` — OAuth provider mode

## Code Guidelines

### Style
- Follow standard Rust formatting (`cargo fmt`)
- Use `cargo clippy` for lint checks
- Prefer `Result<T, E>` over panics in library code
- Use `Arc<dyn Trait>` for runtime polymorphism (adapters, callbacks)
- Feature-gate plugins with `#[cfg(feature = "plugin-name")]`

### Naming Conventions
- **Files**: `snake_case.rs`
- **Structs/Enums**: `PascalCase` 
- **Functions**: `snake_case`
- **Constants**: `SCREAMING_SNAKE_CASE`
- **Feature flags**: `plugin-kebab-case`

### Error Handling
- Define specific error enums per module (e.g., `UpdateUserError`, `SignUpHandlerError`)
- Use `AdapterError` for database operation errors
- Map errors to HTTP responses at the handler layer, not in business logic

### Testing
- Add `#[cfg(test)]` modules in the same file for unit tests
- Use `MockInternalAdapter` for tests that don't need a real database
- Name tests descriptively: `test_sign_up_validates_password_length`

## Adding a New Plugin

1. Add the feature flag to `crates/better-auth/Cargo.toml`:
   ```toml
   [features]
   plugin-my-plugin = []
   ```

2. Create the plugin file at `crates/better-auth/src/plugins/my_plugin.rs`

3. Register it in `crates/better-auth/src/plugins/mod.rs`:
   ```rust
   #[cfg(feature = "plugin-my-plugin")]
   pub mod my_plugin;
   ```

4. Implement the `BetterAuthPlugin` trait:
   ```rust
   impl BetterAuthPlugin for MyPlugin {
       fn id(&self) -> &str { "my-plugin" }
       fn name(&self) -> &str { "My Plugin" }
       fn endpoints(&self) -> Vec<PluginEndpoint> { /* ... */ }
   }
   ```

5. Add tests and update `completion.md` if relevant.

## Commit Messages

Use clear, descriptive commit messages:

```
feat(plugin-siwe): implement secp256k1 signature verification
fix(handler): wire missing /set-password route
docs: add comprehensive README
refactor(session): extract cookie management into module
test(email-otp): add send callback integration test
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Make your changes with tests
4. Run `cargo build` and `cargo test` to verify
5. Submit a pull request with a clear description

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
