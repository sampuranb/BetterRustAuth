// Provider-specific overrides — custom getUserInfo / verifyIdToken logic
// for providers that can't use the generic flow.
//
// Maps to the per-provider custom logic in:
//   packages/core/src/social-providers/{discord,github,google,apple,microsoft,facebook}.ts
//
// These functions are intended to be called from specialized provider
// implementations that wrap the GenericOAuthProvider.

use serde::Deserialize;

use crate::tokens::{OAuth2Tokens, OAuth2UserInfo};
use crate::provider::UserInfoResult;
use better_auth_core::error::BetterAuthError;

// ─── Discord ────────────────────────────────────────────────────────────

/// Discord avatar hash → CDN URL conversion.
///
/// Matches TS `discord.getUserInfo`:
/// - If avatar is null, compute default avatar from user ID/discriminator
/// - If avatar starts with "a_", use .gif; otherwise .png
pub fn discord_avatar_url(
    user_id: &str,
    avatar: Option<&str>,
    discriminator: Option<&str>,
) -> String {
    match avatar {
        Some(hash) if !hash.is_empty() => {
            let format = if hash.starts_with("a_") { "gif" } else { "png" };
            format!("https://cdn.discordapp.com/avatars/{user_id}/{hash}.{format}")
        }
        _ => {
            // Default avatar: for new username system (discriminator == "0"),
            // use (user_id >> 22) % 6; otherwise discriminator % 5
            let disc = discriminator.unwrap_or("0");
            let default_num = if disc == "0" {
                // Parse user_id as u64 for bitshift
                user_id.parse::<u64>().unwrap_or(0) >> 22 % 6
            } else {
                disc.parse::<u64>().unwrap_or(0) % 5
            };
            format!("https://cdn.discordapp.com/embed/avatars/{default_num}.png")
        }
    }
}

/// Post-process Discord user info to fix the avatar URL.
///
/// The generic provider stores the raw `avatar` hash, but Discord needs
/// it converted to a full CDN URL.
pub fn fixup_discord_user_info(result: &mut UserInfoResult) {
    let avatar_raw = result.data.get("avatar").and_then(|v| v.as_str()).map(String::from);
    let discriminator = result.data.get("discriminator").and_then(|v| v.as_str()).map(String::from);
    let id = &result.user.id;

    let image_url = discord_avatar_url(id, avatar_raw.as_deref(), discriminator.as_deref());
    result.user.image = Some(image_url);

    // Also prefer global_name over username for display name
    if let Some(global_name) = result.data.get("global_name").and_then(|v| v.as_str()) {
        if !global_name.is_empty() {
            result.user.name = Some(global_name.to_string());
        }
    }
}

// ─── GitHub ─────────────────────────────────────────────────────────────

/// GitHub email entry from the /user/emails API.
#[derive(Debug, Deserialize)]
pub struct GithubEmail {
    pub email: String,
    pub primary: bool,
    pub verified: bool,
    pub visibility: Option<String>,
}

/// Fetch the user's primary email from the GitHub /user/emails API.
///
/// Matches TS `github.getUserInfo`:
/// - If the user profile has no email, fetch /user/emails
/// - Use the primary email, or fall back to the first email
pub async fn github_fetch_primary_email(
    access_token: &str,
) -> Result<Option<(String, bool)>, BetterAuthError> {
    let client = reqwest::Client::new();
    let response = client
        .get("https://api.github.com/user/emails")
        .header("Authorization", format!("Bearer {access_token}"))
        .header("User-Agent", "better-auth")
        .send()
        .await
        .map_err(|e| BetterAuthError::Other(format!("GitHub email fetch failed: {e}")))?;

    if !response.status().is_success() {
        return Ok(None);
    }

    let emails: Vec<GithubEmail> = response.json().await.map_err(|e| {
        BetterAuthError::Other(format!("Failed to parse GitHub emails: {e}"))
    })?;

    // Find primary email, or fall back to first
    let primary = emails.iter().find(|e| e.primary).or(emails.first());
    Ok(primary.map(|e| (e.email.clone(), e.verified)))
}

/// Post-process GitHub user info to fetch email if missing.
///
/// The generic provider may not get the email from /user if the user's
/// email is set to private. This function calls /user/emails as a fallback.
pub async fn fixup_github_user_info(
    result: &mut UserInfoResult,
    access_token: &str,
) -> Result<(), BetterAuthError> {
    if result.user.email.is_none() || result.user.email.as_deref() == Some("") {
        if let Some((email, verified)) = github_fetch_primary_email(access_token).await? {
            result.user.email_verified = verified;
            result.user.email = Some(email);
        }
    } else {
        // Check if the email is verified via the emails API
        let client = reqwest::Client::new();
        let response = client
            .get("https://api.github.com/user/emails")
            .header("Authorization", format!("Bearer {access_token}"))
            .header("User-Agent", "better-auth")
            .send()
            .await
            .ok();

        if let Some(resp) = response {
            if resp.status().is_success() {
                if let Ok(emails) = resp.json::<Vec<GithubEmail>>().await {
                    let user_email = result.user.email.as_deref().unwrap_or("");
                    if let Some(matching) = emails.iter().find(|e| e.email == user_email) {
                        result.user.email_verified = matching.verified;
                    }
                }
            }
        }
    }

    // Prefer login as name fallback if name is missing
    if result.user.name.is_none() || result.user.name.as_deref() == Some("") {
        if let Some(login) = result.data.get("login").and_then(|v| v.as_str()) {
            result.user.name = Some(login.to_string());
        }
    }

    Ok(())
}

// ─── Google / Apple JWKS Verification ─────────────────────────────────

/// JWKS key entry from a provider's public key endpoint.
#[derive(Debug, Deserialize)]
pub struct JwksKey {
    pub kid: String,
    pub alg: String,
    pub kty: String,
    #[serde(rename = "use")]
    pub use_: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
}

/// JWKS key set response.
#[derive(Debug, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<JwksKey>,
}

/// Fetch a public key from a JWKS endpoint by key ID.
///
/// Used by Google and Apple to verify ID token signatures.
/// Matches TS `getGooglePublicKey()` and `getApplePublicKey()`.
pub async fn fetch_jwks_key(
    jwks_url: &str,
    kid: &str,
) -> Result<JwksKey, BetterAuthError> {
    let client = reqwest::Client::new();
    let response = client
        .get(jwks_url)
        .send()
        .await
        .map_err(|e| BetterAuthError::Other(format!("JWKS fetch failed: {e}")))?;

    let jwks: JwksResponse = response.json().await.map_err(|e| {
        BetterAuthError::Other(format!("Failed to parse JWKS: {e}"))
    })?;

    jwks.keys
        .into_iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| BetterAuthError::Other(format!("JWK with kid '{kid}' not found")))
}

/// Google JWKS endpoint.
pub const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// Apple JWKS endpoint.
pub const APPLE_JWKS_URL: &str = "https://appleid.apple.com/auth/keys";

/// Decode a JWT payload without verifying the signature.
///
/// Matches TS `decodeJwt()` — used by Apple and Google getUserInfo
/// to extract user info from the ID token.
///
/// Note: For production use, prefer full JWT verification via JWKS.
/// This function is a convenience for extracting claims.
pub fn decode_jwt_payload(token: &str) -> Result<serde_json::Value, BetterAuthError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(BetterAuthError::Other("Invalid JWT format".to_string()));
    }

    // JWT payload is the second part, base64url-encoded
    use base64::Engine;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| BetterAuthError::Other(format!("JWT base64 decode failed: {e}")))?;

    serde_json::from_slice(&payload_bytes)
        .map_err(|e| BetterAuthError::Other(format!("JWT payload parse failed: {e}")))
}

/// Decode the JWT protected header to extract kid and alg.
///
/// Matches TS `decodeProtectedHeader()`.
pub fn decode_jwt_header(token: &str) -> Result<(Option<String>, Option<String>), BetterAuthError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(BetterAuthError::Other("Invalid JWT format".to_string()));
    }

    use base64::Engine;
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| BetterAuthError::Other(format!("JWT header base64 decode failed: {e}")))?;

    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| BetterAuthError::Other(format!("JWT header parse failed: {e}")))?;

    let kid = header.get("kid").and_then(|v| v.as_str()).map(String::from);
    let alg = header.get("alg").and_then(|v| v.as_str()).map(String::from);

    Ok((kid, alg))
}

// ─── Google ID Token ────────────────────────────────────────────────────

/// Extract user info from a Google ID token.
///
/// Matches TS `google.getUserInfo` — decodes the ID token JWT
/// to get user info instead of calling the userinfo endpoint.
pub fn google_user_from_id_token(
    tokens: &OAuth2Tokens,
) -> Result<Option<UserInfoResult>, BetterAuthError> {
    let id_token = match &tokens.id_token {
        Some(t) => t,
        None => return Ok(None),
    };

    let claims = decode_jwt_payload(id_token)?;

    let id = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if id.is_empty() {
        return Ok(None);
    }

    let user = OAuth2UserInfo {
        id,
        name: claims.get("name").and_then(|v| v.as_str()).map(String::from),
        email: claims.get("email").and_then(|v| v.as_str()).map(String::from),
        image: claims.get("picture").and_then(|v| v.as_str()).map(String::from),
        email_verified: claims.get("email_verified").and_then(|v| v.as_bool()).unwrap_or(false),
    };

    Ok(Some(UserInfoResult { user, data: claims }))
}

// ─── Apple ID Token ─────────────────────────────────────────────────────

/// Extract user info from an Apple ID token.
///
/// Matches TS `apple.getUserInfo` — Apple doesn't have a userinfo endpoint;
/// all user data comes from the ID token JWT.
///
/// The `user_payload` is the optional JSON body Apple sends on first consent,
/// containing the user's name.
pub fn apple_user_from_id_token(
    tokens: &OAuth2Tokens,
    user_payload: Option<&serde_json::Value>,
) -> Result<Option<UserInfoResult>, BetterAuthError> {
    let id_token = match &tokens.id_token {
        Some(t) => t,
        None => return Ok(None),
    };

    let claims = decode_jwt_payload(id_token)?;

    let id = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if id.is_empty() {
        return Ok(None);
    }

    // Name handling: Apple only sends the name on first consent
    let name = if let Some(user) = user_payload {
        let first = user.pointer("/name/firstName").and_then(|v| v.as_str()).unwrap_or("");
        let last = user.pointer("/name/lastName").and_then(|v| v.as_str()).unwrap_or("");
        let full = format!("{first} {last}").trim().to_string();
        if full.is_empty() { Some(" ".to_string()) } else { Some(full) }
    } else {
        claims.get("name").and_then(|v| v.as_str()).map(|n| {
            if n.is_empty() { " ".to_string() } else { n.to_string() }
        }).or(Some(" ".to_string()))
    };

    // email_verified: Apple sends it as boolean or string "true"/"false"
    let email_verified = match claims.get("email_verified") {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::String(s)) => s == "true",
        _ => false,
    };

    let user = OAuth2UserInfo {
        id,
        name,
        email: claims.get("email").and_then(|v| v.as_str()).map(String::from),
        image: None, // Apple doesn't provide a profile picture
        email_verified,
    };

    Ok(Some(UserInfoResult { user, data: claims }))
}

// ─── Microsoft Entra ID ─────────────────────────────────────────────────

/// Microsoft JWKS endpoint for common tenant.
pub const MICROSOFT_JWKS_URL: &str = 
    "https://login.microsoftonline.com/common/discovery/v2.0/keys";

/// Extract user info from a Microsoft ID token.
///
/// Matches TS `microsoft.getUserInfo` — Microsoft uses the ID token
/// for user info when no separate userinfo endpoint is called.
pub fn microsoft_user_from_id_token(
    tokens: &OAuth2Tokens,
) -> Result<Option<UserInfoResult>, BetterAuthError> {
    let id_token = match &tokens.id_token {
        Some(t) => t,
        None => return Ok(None),
    };

    let claims = decode_jwt_payload(id_token)?;

    // Microsoft uses different claim names: "oid" or "sub" for ID
    let id = claims.get("oid")
        .or_else(|| claims.get("sub"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if id.is_empty() {
        return Ok(None);
    }

    let user = OAuth2UserInfo {
        id,
        name: claims.get("name").and_then(|v| v.as_str()).map(String::from),
        email: claims.get("email")
            .or_else(|| claims.get("preferred_username"))
            .and_then(|v| v.as_str())
            .map(String::from),
        image: None, // Microsoft doesn't include image in the ID token
        email_verified: claims.get("email_verified").and_then(|v| v.as_bool()).unwrap_or(false),
    };

    Ok(Some(UserInfoResult { user, data: claims }))
}

// ─── Facebook ───────────────────────────────────────────────────────────

/// Post-process Facebook user info to extract nested picture URL.
///
/// Facebook returns profile picture as `picture.data.url`, which the
/// generic profile mapping can't handle directly.
pub fn fixup_facebook_user_info(result: &mut UserInfoResult) {
    // Extract picture.data.url from the raw response
    if let Some(url) = result.data.pointer("/picture/data/url").and_then(|v| v.as_str()) {
        result.user.image = Some(url.to_string());
    }
}

// ─── Twitch ─────────────────────────────────────────────────────────────

/// Twitch uses an ID token for user info. Extract from the claims.
///
/// Matches TS `twitch.getUserInfo` — when Twitch returns an ID token,
/// user info can be extracted from JWT claims.
pub fn twitch_user_from_id_token(
    tokens: &OAuth2Tokens,
) -> Result<Option<UserInfoResult>, BetterAuthError> {
    let id_token = match &tokens.id_token {
        Some(t) => t,
        None => return Ok(None),
    };

    let claims = decode_jwt_payload(id_token)?;

    let id = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if id.is_empty() {
        return Ok(None);
    }

    let user = OAuth2UserInfo {
        id,
        name: claims.get("preferred_username").and_then(|v| v.as_str()).map(String::from),
        email: claims.get("email").and_then(|v| v.as_str()).map(String::from),
        image: claims.get("picture").and_then(|v| v.as_str()).map(String::from),
        email_verified: claims.get("email_verified").and_then(|v| v.as_bool()).unwrap_or(false),
    };

    Ok(Some(UserInfoResult { user, data: claims }))
}

// ─── Provider Override Dispatcher ───────────────────────────────────────

/// Provider IDs that need custom getUserInfo logic.
pub const PROVIDERS_WITH_OVERRIDES: &[&str] = &[
    "discord", "github", "google", "apple", "microsoft", "facebook", "twitch",
];

/// Check if a provider needs post-processing of user info.
pub fn needs_userinfo_postprocess(provider_id: &str) -> bool {
    matches!(provider_id, "discord" | "github" | "facebook")
}

/// Check if a provider uses ID token for user info instead of the API.
pub fn uses_id_token_for_userinfo(provider_id: &str) -> bool {
    matches!(provider_id, "google" | "apple" | "microsoft" | "twitch")
}

/// Get user info from an ID token for providers that use it.
///
/// Returns `None` if the provider doesn't use ID tokens or if no ID token
/// is present in the tokens.
pub fn get_user_from_id_token(
    provider_id: &str,
    tokens: &OAuth2Tokens,
    user_payload: Option<&serde_json::Value>,
) -> Result<Option<UserInfoResult>, BetterAuthError> {
    match provider_id {
        "google" => google_user_from_id_token(tokens),
        "apple" => apple_user_from_id_token(tokens, user_payload),
        "microsoft" => microsoft_user_from_id_token(tokens),
        "twitch" => twitch_user_from_id_token(tokens),
        _ => Ok(None),
    }
}

/// Apply provider-specific post-processing to user info.
///
/// Call this after getting user info from the generic flow.
pub async fn postprocess_user_info(
    provider_id: &str,
    result: &mut UserInfoResult,
    access_token: &str,
) -> Result<(), BetterAuthError> {
    match provider_id {
        "discord" => {
            fixup_discord_user_info(result);
            Ok(())
        }
        "github" => fixup_github_user_info(result, access_token).await,
        "facebook" => {
            fixup_facebook_user_info(result);
            Ok(())
        }
        _ => Ok(()),
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discord_avatar_with_hash() {
        let url = discord_avatar_url("123456", Some("abc123"), Some("1234"));
        assert_eq!(url, "https://cdn.discordapp.com/avatars/123456/abc123.png");
    }

    #[test]
    fn test_discord_avatar_animated() {
        let url = discord_avatar_url("123456", Some("a_abc123"), Some("1234"));
        assert_eq!(url, "https://cdn.discordapp.com/avatars/123456/a_abc123.gif");
    }

    #[test]
    fn test_discord_avatar_default() {
        let url = discord_avatar_url("123456", None, Some("1234"));
        assert!(url.starts_with("https://cdn.discordapp.com/embed/avatars/"));
    }

    #[test]
    fn test_decode_jwt_payload() {
        // Create a simple JWT with known payload
        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"sub":"12345","name":"Test User","email":"test@example.com"}"#);
        let signature = "fake_signature";

        let token = format!("{header}.{payload}.{signature}");
        let claims = decode_jwt_payload(&token).unwrap();

        assert_eq!(claims["sub"].as_str(), Some("12345"));
        assert_eq!(claims["name"].as_str(), Some("Test User"));
        assert_eq!(claims["email"].as_str(), Some("test@example.com"));
    }

    #[test]
    fn test_decode_jwt_header() {
        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"RS256","typ":"JWT","kid":"key123"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"sub":"12345"}"#);

        let token = format!("{header}.{payload}.fake_sig");
        let (kid, alg) = decode_jwt_header(&token).unwrap();

        assert_eq!(kid.as_deref(), Some("key123"));
        assert_eq!(alg.as_deref(), Some("RS256"));
    }

    #[test]
    fn test_google_user_from_id_token() {
        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"RS256"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"sub":"goog123","name":"Google User","email":"user@gmail.com","picture":"https://lh3.googleusercontent.com/a/photo","email_verified":true}"#);

        let tokens = OAuth2Tokens {
            id_token: Some(format!("{header}.{payload}.fake")),
            ..Default::default()
        };

        let result = google_user_from_id_token(&tokens).unwrap().unwrap();
        assert_eq!(result.user.id, "goog123");
        assert_eq!(result.user.name.as_deref(), Some("Google User"));
        assert_eq!(result.user.email.as_deref(), Some("user@gmail.com"));
        assert!(result.user.email_verified);
    }

    #[test]
    fn test_apple_user_from_id_token() {
        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"RS256"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"sub":"apple123","email":"user@privaterelay.appleid.com","email_verified":"true"}"#);

        let tokens = OAuth2Tokens {
            id_token: Some(format!("{header}.{payload}.fake")),
            ..Default::default()
        };

        let user_payload = serde_json::json!({
            "name": {
                "firstName": "John",
                "lastName": "Doe"
            }
        });

        let result = apple_user_from_id_token(&tokens, Some(&user_payload)).unwrap().unwrap();
        assert_eq!(result.user.id, "apple123");
        assert_eq!(result.user.name.as_deref(), Some("John Doe"));
        assert_eq!(result.user.email.as_deref(), Some("user@privaterelay.appleid.com"));
        assert!(result.user.email_verified);
        assert!(result.user.image.is_none()); // Apple doesn't provide images
    }

    #[test]
    fn test_microsoft_user_from_id_token() {
        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"RS256"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"oid":"ms-oid-123","name":"MS User","preferred_username":"user@outlook.com","email_verified":true}"#);

        let tokens = OAuth2Tokens {
            id_token: Some(format!("{header}.{payload}.fake")),
            ..Default::default()
        };

        let result = microsoft_user_from_id_token(&tokens).unwrap().unwrap();
        assert_eq!(result.user.id, "ms-oid-123");
        assert_eq!(result.user.name.as_deref(), Some("MS User"));
        assert_eq!(result.user.email.as_deref(), Some("user@outlook.com"));
        assert!(result.user.email_verified);
    }

    #[test]
    fn test_facebook_fixup() {
        let data = serde_json::json!({
            "id": "fb123",
            "name": "FB User",
            "email": "user@fb.com",
            "picture": {
                "data": {
                    "url": "https://graph.facebook.com/fb123/picture"
                }
            }
        });

        let mut result = UserInfoResult {
            user: OAuth2UserInfo {
                id: "fb123".to_string(),
                name: Some("FB User".to_string()),
                email: Some("user@fb.com".to_string()),
                image: None,
                email_verified: false,
            },
            data,
        };

        fixup_facebook_user_info(&mut result);
        assert_eq!(
            result.user.image.as_deref(),
            Some("https://graph.facebook.com/fb123/picture")
        );
    }

    #[test]
    fn test_uses_id_token_for_userinfo() {
        assert!(uses_id_token_for_userinfo("google"));
        assert!(uses_id_token_for_userinfo("apple"));
        assert!(uses_id_token_for_userinfo("microsoft"));
        assert!(uses_id_token_for_userinfo("twitch"));
        assert!(!uses_id_token_for_userinfo("github"));
        assert!(!uses_id_token_for_userinfo("discord"));
    }

    #[test]
    fn test_needs_userinfo_postprocess() {
        assert!(needs_userinfo_postprocess("discord"));
        assert!(needs_userinfo_postprocess("github"));
        assert!(needs_userinfo_postprocess("facebook"));
        assert!(!needs_userinfo_postprocess("google"));
        assert!(!needs_userinfo_postprocess("apple"));
    }
}
