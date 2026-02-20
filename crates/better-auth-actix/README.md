# better-auth-actix

[Actix-web](https://actix.rs/) HTTP integration for
[Better Auth](https://www.better-auth.com/).

This crate provides a service configuration function that registers all
Better Auth endpoints on an Actix-web `App`. It handles request parsing,
cookie management, error conversion, and plugin dispatch so you can add
authentication to an Actix-web app in a few lines.

## Usage

```rust,ignore
use std::sync::Arc;
use actix_web::{App, HttpServer};
use better_auth_actix::BetterAuth;
use better_auth_core::options::BetterAuthOptions;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let options = BetterAuthOptions::new("my-secret-key-at-least-32-chars!");
    let adapter = /* your InternalAdapter implementation */;

    let auth = BetterAuth::new(options, Arc::new(adapter));

    HttpServer::new(move || {
        App::new().configure(auth.configure())
    })
    .bind("0.0.0.0:3000")?
    .run()
    .await
}
```

## Endpoints

All routes are registered under the configurable `base_path` (default
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
- Plugin endpoints are dispatched via the default service handler

## Features

- `configure()` -- returns a closure for `App::new().configure(...)`
- `generic_handler()` -- alternative catch-all handler for all auth routes
- `from_context()` -- create from an existing `Arc<AuthContext>`
- Plugin dispatch default service for custom plugin endpoints

## Related crates

| Crate                | Role                          |
|----------------------|-------------------------------|
| `better-auth`        | Core auth engine              |
| `better-auth-core`   | Shared types, options, traits |
| `better-auth-oauth2` | OAuth2 protocol layer         |
| `better-auth-axum`   | Axum HTTP integration         |

## License

See the repository root for license information.
