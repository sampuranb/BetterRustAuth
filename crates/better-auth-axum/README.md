# better-auth-axum

[Axum](https://github.com/tokio-rs/axum) HTTP integration for
[Better Auth](https://www.better-auth.com/).

This crate provides a ready-to-use `axum::Router` with all Better Auth
endpoints pre-wired. It handles request parsing, cookie management,
error conversion, CSRF validation, rate limiting, and plugin dispatch
so you can add authentication to an Axum app in a few lines.

## Usage

```rust,ignore
use std::sync::Arc;
use better_auth_axum::BetterAuth;
use better_auth_core::options::BetterAuthOptions;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let options = BetterAuthOptions::new("my-secret-key-at-least-32-chars!");
    let adapter = /* your InternalAdapter implementation */;

    let auth = BetterAuth::new(options, Arc::new(adapter));

    let app = axum::Router::new()
        .merge(auth.router());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

## Endpoints

All routes are nested under the configurable `base_path` (default
`/api/auth`). Core endpoints include:

- `POST /sign-up/email` -- register with email + password
- `POST /sign-in/email` -- sign in with email + password
- `POST /sign-in/social` -- initiate OAuth flow
- `GET  /callback/{provider}` -- OAuth callback
- `GET  /session` -- get current session
- `POST /sign-out` -- sign out (deletes session cookies)
- `POST /change-password`, `/forgot-password`, `/reset-password`
- `GET  /list-accounts`, `POST /unlink-account`, `POST /link-social`
- `GET  /verify-email`, `POST /send-verification-email`
- Plugin endpoints are dispatched automatically via the fallback handler

## Features

- `router()` -- returns a `Router` nested under the base path
- `router_with_cors()` -- same, with a permissive CORS layer
- `from_context()` -- create from an existing `Arc<AuthContext>`
- Built-in origin/CSRF middleware and per-endpoint rate limiting
- Plugin dispatch fallback for custom plugin endpoints

## Related crates

| Crate                | Role                          |
|----------------------|-------------------------------|
| `better-auth`        | Core auth engine              |
| `better-auth-core`   | Shared types, options, traits |
| `better-auth-oauth2` | OAuth2 protocol layer         |
| `better-auth-actix`  | Actix-web HTTP integration    |

## License

See the repository root for license information.
