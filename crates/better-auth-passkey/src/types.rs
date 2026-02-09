//! Passkey types.
//! Maps to TS `types.ts`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Stored passkey credential.
/// Maps to TS `Passkey` type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Passkey {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub public_key: String,
    pub user_id: String,
    pub credential_id: String,
    pub counter: i64,
    pub device_type: String,
    pub backed_up: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<String>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aaguid: Option<String>,
}

/// WebAuthn challenge value stored for verification.
/// Maps to TS `WebAuthnChallengeValue`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnChallengeValue {
    pub expected_challenge: String,
    pub user_data: ChallengeUserData,
}

/// User data embedded in the challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeUserData {
    pub id: String,
}

/// Registration options returned to the client.
/// Subset of WebAuthn PublicKeyCredentialCreationOptions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationOptions {
    pub challenge: String,
    pub rp: RelyingParty,
    pub user: PublicKeyUser,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_credentials: Option<Vec<CredentialDescriptor>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pub_key_cred_params: Option<Vec<PubKeyCredParam>>,
}

/// Authentication options returned to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationOptions {
    pub challenge: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    pub rp_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_credentials: Option<Vec<CredentialDescriptor>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
}

/// Relying Party identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelyingParty {
    pub name: String,
    pub id: String,
}

/// Public key user identity for registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyUser {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

/// Credential descriptor for exclude/allow lists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDescriptor {
    pub id: String,
    #[serde(rename = "type")]
    pub cred_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

/// Public key credential algorithm parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubKeyCredParam {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i64,
}

/// Registration response from the WebAuthn client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResponse {
    pub id: String,
    pub raw_id: String,
    pub response: RegistrationResponseData,
    #[serde(rename = "type")]
    pub cred_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResponseData {
    pub attestation_object: String,
    pub client_data_json: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

/// Authentication response from the WebAuthn client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationResponse {
    pub id: String,
    pub raw_id: String,
    pub response: AuthenticationResponseData,
    #[serde(rename = "type")]
    pub cred_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationResponseData {
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
}
