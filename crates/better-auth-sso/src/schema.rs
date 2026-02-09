//! SSO DB schema.

/// SQL schema for SSO connection table.
pub const SSO_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS sso_connection (
    id TEXT PRIMARY KEY NOT NULL,
    organization_id TEXT,
    provider TEXT NOT NULL DEFAULT 'saml',
    domain TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    idp_metadata_url TEXT,
    idp_entity_id TEXT,
    idp_sso_url TEXT,
    idp_certificate TEXT,
    sp_entity_id TEXT NOT NULL,
    sp_acs_url TEXT NOT NULL,
    attribute_mapping TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sso_connection_domain ON sso_connection(domain);
CREATE INDEX IF NOT EXISTS idx_sso_connection_org ON sso_connection(organization_id);
"#;
