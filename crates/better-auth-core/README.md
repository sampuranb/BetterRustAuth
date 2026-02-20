# better-auth-core

Core types, configuration options, traits, and error types for the
[Better Auth](https://www.better-auth.com/) Rust port.

This crate is the foundation that every other `better-auth-*` crate depends
on. It defines `BetterAuthOptions`, database model types, the `Adapter` and
`BetterAuthPlugin` traits, error types, hooks, and the structured logger.

## Usage

```rust,ignore
use better_auth_core::options::BetterAuthOptions;

let options = BetterAuthOptions::new("my-secret-key-at-least-32-chars!")
    .with_base_url("https://example.com")
    .with_app_name("My App");

// Configure email + password settings
// options.email_and_password.enabled = true;
// options.email_and_password.min_password_length = 10;

// Configure session settings
// options.session.expiration_seconds = 7 * 24 * 3600; // 7 days

// Add trusted origins
// options.trusted_origins = vec!["https://app.example.com".into()];
```

## Key types

| Type / Trait          | Description                                       |
|-----------------------|---------------------------------------------------|
| `BetterAuthOptions`   | Top-level configuration struct                    |
| `Adapter`             | Generic database adapter trait                    |
| `BetterAuthPlugin`    | Plugin trait for extending auth behaviour         |
| `BetterAuthError`     | Crate-wide error enum                             |
| `ApiError`            | Structured API error with status code             |
| `ErrorCode`           | Machine-readable error code constants             |
| `User`                | Core user model                                   |
| `Session`             | Session model                                     |
| `Account`             | Linked account model (credential or social)       |
| `Verification`        | Email / token verification record                 |
| `AsyncHookRegistry`   | Registry for before/after hooks                   |
| `AuthLogger`          | Structured logger with configurable levels        |
| `SecondaryStorage`    | Trait for rate-limit and cache storage backends   |

## Modules

- `db` -- database adapter trait, model structs, secondary storage
- `env` -- environment variable helpers
- `error` -- `BetterAuthError`, `ApiError`, `ErrorCode`
- `hooks` -- async hook registry for lifecycle events
- `logger` -- structured logging
- `options` -- `BetterAuthOptions` and all sub-option structs
- `plugin` -- `BetterAuthPlugin` trait and plugin endpoint types
- `utils` -- shared utility functions

## Related crates

| Crate                | Role                               |
|----------------------|------------------------------------|
| `better-auth`        | Core auth engine                   |
| `better-auth-oauth2` | OAuth2 protocol layer              |
| `better-auth-axum`   | Axum HTTP integration              |
| `better-auth-actix`  | Actix-web HTTP integration         |

## License

See the repository root for license information.
