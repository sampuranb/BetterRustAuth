//! Passkey route handlers.
//! Maps to TS `routes.ts`.
//!
//! These are handler function signatures that mirror the 7 endpoints
//! from the TS passkey plugin. Each generates/verifies WebAuthn challenges
//! and manages stored credentials.


use crate::types::*;
use crate::PasskeyOptions;
use crate::get_rp_id;
use chrono::Utc;
use serde_json::json;

/// Generate registration options for a new passkey.
/// Maps to TS `generatePasskeyRegistrationOptions`.
///
/// GET /passkey/generate-register-options
pub fn generate_registration_options(
    opts: &PasskeyOptions,
    base_url: &str,
    _user_id: &str,
    user_name: &str,
    user_display_name: &str,
    existing_passkeys: &[Passkey],
) -> RegistrationOptions {
    let rp_id = get_rp_id(opts, base_url);
    let rp_name = opts.rp_name.clone().unwrap_or_else(|| "Better Auth".to_string());

    // Generate a random challenge
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(uuid::Uuid::new_v4().as_bytes());

    // Build exclude credentials from existing passkeys
    let exclude_credentials: Vec<CredentialDescriptor> = existing_passkeys
        .iter()
        .map(|pk| CredentialDescriptor {
            id: pk.credential_id.clone(),
            cred_type: "public-key".to_string(),
            transports: pk.transports.as_ref().map(|t| {
                t.split(',').map(|s| s.trim().to_string()).collect()
            }),
        })
        .collect();

    let authenticator_selection = opts.authenticator_selection.as_ref().map(|sel| {
        serde_json::to_value(sel).unwrap_or_default()
    }).unwrap_or_else(|| json!({
        "residentKey": "preferred",
        "userVerification": "preferred",
    }));

    // Generate random user ID for WebAuthn (not the auth user ID)
    let webauthn_user_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(uuid::Uuid::new_v4().as_bytes());

    RegistrationOptions {
        challenge,
        rp: RelyingParty { name: rp_name, id: rp_id },
        user: PublicKeyUser {
            id: webauthn_user_id,
            name: user_name.to_string(),
            display_name: user_display_name.to_string(),
        },
        timeout: Some(60000),
        attestation: Some("none".to_string()),
        exclude_credentials: if exclude_credentials.is_empty() { None } else { Some(exclude_credentials) },
        authenticator_selection: Some(authenticator_selection),
        pub_key_cred_params: Some(vec![
            PubKeyCredParam { cred_type: "public-key".to_string(), alg: -7 },   // ES256
            PubKeyCredParam { cred_type: "public-key".to_string(), alg: -257 }, // RS256
        ]),
    }
}

/// Generate authentication options for signing in with a passkey.
/// Maps to TS `generatePasskeyAuthenticationOptions`.
///
/// GET /passkey/generate-authenticate-options
pub fn generate_authentication_options(
    opts: &PasskeyOptions,
    base_url: &str,
    user_passkeys: &[Passkey],
) -> AuthenticationOptions {
    let rp_id = get_rp_id(opts, base_url);

    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(uuid::Uuid::new_v4().as_bytes());

    let allow_credentials: Vec<CredentialDescriptor> = user_passkeys
        .iter()
        .map(|pk| CredentialDescriptor {
            id: pk.credential_id.clone(),
            cred_type: "public-key".to_string(),
            transports: pk.transports.as_ref().map(|t| {
                t.split(',').map(|s| s.trim().to_string()).collect()
            }),
        })
        .collect();

    AuthenticationOptions {
        challenge,
        timeout: Some(60000),
        rp_id,
        allow_credentials: if allow_credentials.is_empty() { None } else { Some(allow_credentials) },
        user_verification: Some("preferred".to_string()),
    }
}

/// Create a challenge value for storage.
pub fn create_challenge_value(challenge: &str, user_id: &str) -> WebAuthnChallengeValue {
    WebAuthnChallengeValue {
        expected_challenge: challenge.to_string(),
        user_data: ChallengeUserData { id: user_id.to_string() },
    }
}

/// Build a new passkey record from registration data.
pub fn build_passkey_record(
    user_id: &str,
    credential_id: &str,
    public_key: &str,
    counter: i64,
    device_type: &str,
    backed_up: bool,
    transports: Option<&str>,
    name: Option<&str>,
    aaguid: Option<&str>,
) -> Passkey {
    Passkey {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.map(String::from),
        public_key: public_key.to_string(),
        user_id: user_id.to_string(),
        credential_id: credential_id.to_string(),
        counter,
        device_type: device_type.to_string(),
        backed_up,
        transports: transports.map(String::from),
        created_at: Utc::now(),
        aaguid: aaguid.map(String::from),
    }
}

use base64::Engine;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_registration_options() {
        let opts = PasskeyOptions::default();
        let options = generate_registration_options(
            &opts, "https://example.com", "user1", "user@example.com", "User", &[],
        );
        assert_eq!(options.rp.id, "example.com");
        assert_eq!(options.rp.name, "Better Auth");
        assert!(!options.challenge.is_empty());
        assert!(options.exclude_credentials.is_none());
        assert_eq!(options.pub_key_cred_params.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_generate_authentication_options() {
        let opts = PasskeyOptions::default();
        let options = generate_authentication_options(&opts, "https://example.com", &[]);
        assert_eq!(options.rp_id, "example.com");
        assert!(!options.challenge.is_empty());
        assert!(options.allow_credentials.is_none());
    }

    #[test]
    fn test_generate_registration_with_existing() {
        let opts = PasskeyOptions::default();
        let existing = vec![Passkey {
            id: "pk1".into(), name: Some("My Key".into()), public_key: "pk".into(),
            user_id: "u1".into(), credential_id: "cred1".into(), counter: 0,
            device_type: "singleDevice".into(), backed_up: false,
            transports: Some("internal,hybrid".into()), created_at: Utc::now(), aaguid: None,
        }];
        let options = generate_registration_options(
            &opts, "https://example.com", "u1", "user@example.com", "User", &existing,
        );
        let excluded = options.exclude_credentials.unwrap();
        assert_eq!(excluded.len(), 1);
        assert_eq!(excluded[0].id, "cred1");
        assert_eq!(excluded[0].transports.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_build_passkey_record() {
        let pk = build_passkey_record(
            "u1", "cred1", "pubkey_data", 0, "singleDevice", false,
            Some("internal"), Some("My Passkey"), Some("aaguid123"),
        );
        assert_eq!(pk.user_id, "u1");
        assert_eq!(pk.credential_id, "cred1");
        assert_eq!(pk.name, Some("My Passkey".into()));
        assert_eq!(pk.counter, 0);
        assert!(!pk.id.is_empty());
    }

    #[test]
    fn test_create_challenge_value() {
        let cv = create_challenge_value("challenge123", "user456");
        assert_eq!(cv.expected_challenge, "challenge123");
        assert_eq!(cv.user_data.id, "user456");
    }
}
