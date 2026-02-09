//! OAuth Provider DB schema.

pub const OAUTH_PROVIDER_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS oauth_client (
    id TEXT PRIMARY KEY NOT NULL,
    client_id TEXT NOT NULL UNIQUE,
    client_secret_hash TEXT,
    name TEXT NOT NULL,
    redirect_uris TEXT NOT NULL DEFAULT '[]',
    grant_types TEXT NOT NULL DEFAULT '["authorization_code"]',
    response_types TEXT NOT NULL DEFAULT '["code"]',
    scopes TEXT NOT NULL DEFAULT '[]',
    client_type TEXT NOT NULL DEFAULT 'confidential',
    logo_uri TEXT,
    policy_uri TEXT,
    tos_uri TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_oauth_client_client_id ON oauth_client(client_id);

CREATE TABLE IF NOT EXISTS authorization_code (
    code TEXT PRIMARY KEY NOT NULL,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT '',
    code_challenge TEXT,
    code_challenge_method TEXT,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS oauth_access_token (
    token TEXT PRIMARY KEY NOT NULL,
    client_id TEXT NOT NULL,
    user_id TEXT,
    scope TEXT NOT NULL DEFAULT '',
    token_type TEXT NOT NULL DEFAULT 'Bearer',
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_oauth_access_token_client ON oauth_access_token(client_id);

CREATE TABLE IF NOT EXISTS oauth_refresh_token (
    token TEXT PRIMARY KEY NOT NULL,
    access_token TEXT NOT NULL,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS oauth_consent (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_oauth_consent_user_client ON oauth_consent(user_id, client_id);
"#;
