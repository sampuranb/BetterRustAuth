//! Passkey DB schema.
//! Maps to TS `schema.ts`.

/// SQL schema for the passkey table.
pub const PASSKEY_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS passkey (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT,
    public_key TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    device_type TEXT NOT NULL,
    backed_up BOOLEAN NOT NULL DEFAULT FALSE,
    transports TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    aaguid TEXT
);

CREATE INDEX IF NOT EXISTS idx_passkey_user_id ON passkey(user_id);
CREATE INDEX IF NOT EXISTS idx_passkey_credential_id ON passkey(credential_id);
"#;

/// Field definitions for the passkey model.
/// Maps to TS `schema.passkey.fields`.
pub const PASSKEY_FIELDS: &[(&str, &str, bool)] = &[
    ("name", "string", false),
    ("public_key", "string", true),
    ("user_id", "string", true),
    ("credential_id", "string", true),
    ("counter", "number", true),
    ("device_type", "string", true),
    ("backed_up", "boolean", true),
    ("transports", "string", false),
    ("created_at", "date", false),
    ("aaguid", "string", false),
];
