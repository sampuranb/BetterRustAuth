# better-auth-oauth2

OAuth2 protocol layer for [Better Auth](https://www.better-auth.com/)
with **33 built-in social providers**.

This crate implements the OAuth2 authorization-code flow, PKCE, token
exchange, token refresh, and a data-driven provider registry. Each
provider is described by a static `ProviderConfig`; a single
`GenericOAuthProvider` struct implements the `OAuthProvider` trait for
all of them.

## Supported providers

| | | | |
|---|---|---|---|
| Google | GitHub | Apple | Discord |
| Twitter | Microsoft | Facebook | Spotify |
| Twitch | LinkedIn | GitLab | TikTok |
| Reddit | Slack | Dropbox | Notion |
| Zoom | Roblox | Cognito | Figma |
| Salesforce | VK | Hugging Face | Atlassian |
| Kakao | Naver | LINE | Linear |
| Kick | PayPal | Paybin | Polar |
| Vercel | | | |

## Usage

```rust,ignore
use better_auth_oauth2::providers::{GenericOAuthProvider, get_provider_config};
use better_auth_oauth2::provider::ProviderOptions;

// Look up the static config for a provider
let config = get_provider_config("github").expect("unknown provider");

// Create a provider instance with your OAuth credentials
let provider = GenericOAuthProvider::new(
    config,
    ProviderOptions::new("your-client-id")
        .with_secret("your-client-secret")
        .with_redirect_url("https://example.com/api/auth/callback/github"),
);

// Generate an authorization URL with PKCE
let (url, state, code_verifier) = provider
    .create_authorization_url("https://example.com/api/auth/callback/github", None)
    .await?;
```

## Modules

- `authorization_url` -- build OAuth2 authorize URLs with state + PKCE
- `code_exchange` -- exchange an authorization code for tokens
- `refresh` -- refresh an access token
- `pkce` -- PKCE code-challenge generation
- `tokens` -- `OAuth2Tokens` and `OAuth2UserInfo` types
- `provider` -- `OAuthProvider` trait and `ProviderOptions`
- `providers` -- static registry of all 33 provider configs
- `client_credentials` -- client-credentials grant helpers

## Related crates

| Crate              | Role                          |
|--------------------|-------------------------------|
| `better-auth`      | Core auth engine              |
| `better-auth-core` | Shared types, options, traits |
| `better-auth-axum` | Axum HTTP integration         |
| `better-auth-actix`| Actix-web HTTP integration    |

## License

See the repository root for license information.
