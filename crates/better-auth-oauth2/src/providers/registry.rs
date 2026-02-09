// Provider registry — all 33 social providers defined as ProviderConfig constants.
//
// Maps to packages/core/src/social-providers/ (all 33 files).

use std::collections::HashMap;

use async_trait::async_trait;

use crate::authorization_url::{AuthorizationUrlParams, create_authorization_url};
use crate::code_exchange::{CodeExchangeParams, validate_authorization_code};
use crate::provider::{
    AuthenticationMethod, AuthorizationUrlData, CodeValidationData, OAuthProvider, ProviderOptions,
    UserInfoResult,
};
use crate::refresh::{RefreshTokenParams, refresh_access_token};
use crate::tokens::{OAuth2Tokens, OAuth2UserInfo};

/// Profile field mapping — tells GenericOAuthProvider how to extract
/// user fields from the provider's JSON response.
#[derive(Debug, Clone, Copy)]
pub struct ProfileMapping {
    /// JSON path to user ID (e.g., "id", "sub", "data.user.open_id").
    pub id: &'static str,
    /// JSON path to name.
    pub name: &'static str,
    /// JSON path to email.
    pub email: &'static str,
    /// JSON path to avatar/image.
    pub image: &'static str,
    /// JSON path to email_verified.
    pub email_verified: &'static str,
    /// Default email_verified when field is missing.
    pub email_verified_default: bool,
}

/// Static configuration for a social provider.
#[derive(Debug, Clone, Copy)]
pub struct ProviderConfig {
    pub id: &'static str,
    pub name: &'static str,
    pub authorization_endpoint: &'static str,
    pub token_endpoint: &'static str,
    pub userinfo_endpoint: &'static str,
    pub default_scopes: &'static [&'static str],
    pub scope_joiner: &'static str,
    pub auth_method: AuthenticationMethod,
    pub profile_mapping: ProfileMapping,
    /// Additional headers to send with the userinfo request.
    pub extra_userinfo_headers: &'static [(&'static str, &'static str)],
    /// HTTP method for the userinfo request (true = POST, false = GET).
    pub userinfo_is_post: bool,
}

/// A generic OAuth provider implementation backed by `ProviderConfig`.
/// This single struct handles all 33 providers using their static config.
#[derive(Debug, Clone)]
pub struct GenericOAuthProvider {
    pub config: &'static ProviderConfig,
    pub options: ProviderOptions,
}

impl GenericOAuthProvider {
    pub fn new(config: &'static ProviderConfig, options: ProviderOptions) -> Self {
        Self { config, options }
    }

    /// Extracts a string from a nested JSON path like "data.user.id".
    fn extract_field(data: &serde_json::Value, path: &str) -> Option<String> {
        let mut current = data;
        for part in path.split('.') {
            current = current.get(part)?;
        }
        match current {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            serde_json::Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }

    fn extract_bool(data: &serde_json::Value, path: &str, default: bool) -> bool {
        let mut current = data;
        for part in path.split('.') {
            match current.get(part) {
                Some(v) => current = v,
                None => return default,
            }
        }
        match current {
            serde_json::Value::Bool(b) => *b,
            serde_json::Value::String(s) => s == "true",
            serde_json::Value::Number(n) => n.as_i64().unwrap_or(0) != 0,
            _ => default,
        }
    }
}

#[async_trait]
impl OAuthProvider for GenericOAuthProvider {
    fn id(&self) -> &str {
        self.config.id
    }

    fn name(&self) -> &str {
        self.config.name
    }

    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn authorization_endpoint(&self) -> &str {
        self.config.authorization_endpoint
    }

    fn token_endpoint(&self) -> &str {
        self.config.token_endpoint
    }

    fn authentication_method(&self) -> AuthenticationMethod {
        self.config.auth_method
    }

    fn default_scopes(&self) -> Vec<String> {
        self.config
            .default_scopes
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn scope_joiner(&self) -> &str {
        self.config.scope_joiner
    }

    async fn create_authorization_url(
        &self,
        data: &AuthorizationUrlData,
    ) -> Result<url::Url, better_auth_core::error::BetterAuthError> {
        let mut scopes = if self.options.disable_default_scope {
            Vec::new()
        } else {
            self.default_scopes()
        };
        scopes.extend(self.options.scope.iter().cloned());
        if let Some(extra) = &data.scopes {
            scopes.extend(extra.iter().cloned());
        }

        let url = create_authorization_url(AuthorizationUrlParams {
            id: self.config.id.to_string(),
            authorization_endpoint: self.config.authorization_endpoint.to_string(),
            redirect_uri: data.redirect_uri.clone(),
            client_id: self.options.client_id.clone(),
            state: data.state.clone(),
            code_verifier: Some(data.code_verifier.clone()),
            scopes: if scopes.is_empty() {
                None
            } else {
                Some(scopes)
            },
            claims: None,
            duration: None,
            prompt: self.options.prompt.clone(),
            access_type: None,
            response_type: None,
            display: data.display.clone(),
            login_hint: data.login_hint.clone(),
            hd: None,
            response_mode: self.options.response_mode.clone(),
            additional_params: self.additional_auth_params(),
            scope_joiner: Some(self.config.scope_joiner.to_string()),
            override_redirect_uri: self.options.redirect_uri.clone(),
            override_authorization_endpoint: self.options.authorization_endpoint.clone(),
        })
        .map_err(|e| {
            better_auth_core::error::BetterAuthError::Other(format!(
                "Failed to build authorization URL: {e}"
            ))
        })?;

        Ok(url)
    }

    async fn validate_authorization_code(
        &self,
        data: &CodeValidationData,
    ) -> Result<Option<OAuth2Tokens>, better_auth_core::error::BetterAuthError> {
        let tokens = validate_authorization_code(CodeExchangeParams {
            code: data.code.clone(),
            redirect_uri: self
                .options
                .redirect_uri
                .clone()
                .unwrap_or(data.redirect_uri.clone()),
            token_endpoint: self.config.token_endpoint.to_string(),
            client_id: self.options.client_id.clone(),
            client_secret: self.options.client_secret.clone(),
            code_verifier: data.code_verifier.clone(),
            device_id: data.device_id.clone(),
            client_key: self.options.client_key.clone(),
            authentication: self.config.auth_method,
            headers: HashMap::new(),
            additional_params: HashMap::new(),
        })
        .await?;

        Ok(Some(tokens))
    }

    async fn get_user_info(
        &self,
        tokens: &OAuth2Tokens,
    ) -> Result<Option<UserInfoResult>, better_auth_core::error::BetterAuthError> {
        let access_token = match &tokens.access_token {
            Some(t) => t,
            None => return Ok(None),
        };

        let client = reqwest::Client::new();

        let mut req = if self.config.userinfo_is_post {
            client.post(self.config.userinfo_endpoint)
        } else {
            client.get(self.config.userinfo_endpoint)
        };

        req = req.header("Authorization", format!("Bearer {access_token}"));

        for (key, value) in self.config.extra_userinfo_headers {
            req = req.header(*key, *value);
        }

        let response = req.send().await.map_err(|e| {
            better_auth_core::error::BetterAuthError::Other(format!(
                "User info request failed: {e}"
            ))
        })?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let data: serde_json::Value = response.json().await.map_err(|e| {
            better_auth_core::error::BetterAuthError::Other(format!(
                "Failed to parse user info: {e}"
            ))
        })?;

        let mapping = &self.config.profile_mapping;

        let id = match Self::extract_field(&data, mapping.id) {
            Some(id) => id,
            None => return Ok(None),
        };

        let user = OAuth2UserInfo {
            id,
            name: Self::extract_field(&data, mapping.name),
            email: Self::extract_field(&data, mapping.email),
            image: Self::extract_field(&data, mapping.image),
            email_verified: Self::extract_bool(
                &data,
                mapping.email_verified,
                mapping.email_verified_default,
            ),
        };

        Ok(Some(UserInfoResult {
            user,
            data,
        }))
    }

    async fn refresh_access_token(
        &self,
        refresh_token: &str,
    ) -> Result<OAuth2Tokens, better_auth_core::error::BetterAuthError> {
        refresh_access_token(RefreshTokenParams {
            refresh_token: refresh_token.to_string(),
            token_endpoint: self.config.token_endpoint.to_string(),
            client_id: self.options.client_id.clone(),
            client_secret: self.options.client_secret.clone(),
            authentication: self.config.auth_method,
            extra_params: HashMap::new(),
        })
        .await
    }
}

// =============================================================================
// Provider configs — all 33
// =============================================================================

static DEFAULT_MAPPING: ProfileMapping = ProfileMapping {
    id: "id",
    name: "name",
    email: "email",
    image: "picture",
    email_verified: "email_verified",
    email_verified_default: false,
};

static SUB_MAPPING: ProfileMapping = ProfileMapping {
    id: "sub",
    name: "name",
    email: "email",
    image: "picture",
    email_verified: "email_verified",
    email_verified_default: false,
};

// --- Google ---
pub static GOOGLE: ProviderConfig = ProviderConfig {
    id: "google",
    name: "Google",
    authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    token_endpoint: "https://oauth2.googleapis.com/token",
    userinfo_endpoint: "https://www.googleapis.com/oauth2/v3/userinfo",
    default_scopes: &["openid", "email", "profile"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: SUB_MAPPING,
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- GitHub ---
pub static GITHUB: ProviderConfig = ProviderConfig {
    id: "github",
    name: "GitHub",
    authorization_endpoint: "https://github.com/login/oauth/authorize",
    token_endpoint: "https://github.com/login/oauth/access_token",
    userinfo_endpoint: "https://api.github.com/user",
    default_scopes: &["read:user", "user:email"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: ProfileMapping {
        id: "id",
        name: "name",
        email: "email",
        image: "avatar_url",
        email_verified: "email_verified",
        email_verified_default: false,
    },
    extra_userinfo_headers: &[("User-Agent", "better-auth")],
    userinfo_is_post: false,
};

// --- Apple ---
pub static APPLE: ProviderConfig = ProviderConfig {
    id: "apple",
    name: "Apple",
    authorization_endpoint: "https://appleid.apple.com/auth/authorize",
    token_endpoint: "https://appleid.apple.com/auth/token",
    userinfo_endpoint: "", // Apple uses ID token, not a userinfo endpoint
    default_scopes: &["email", "name"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: SUB_MAPPING,
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- Discord ---
pub static DISCORD: ProviderConfig = ProviderConfig {
    id: "discord",
    name: "Discord",
    authorization_endpoint: "https://discord.com/api/oauth2/authorize",
    token_endpoint: "https://discord.com/api/oauth2/token",
    userinfo_endpoint: "https://discord.com/api/users/@me",
    default_scopes: &["identify", "email"],
    scope_joiner: "+",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: ProfileMapping {
        id: "id",
        name: "global_name",
        email: "email",
        image: "avatar",
        email_verified: "verified",
        email_verified_default: false,
    },
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- Twitter / X ---
pub static TWITTER: ProviderConfig = ProviderConfig {
    id: "twitter",
    name: "Twitter",
    authorization_endpoint: "https://x.com/i/oauth2/authorize",
    token_endpoint: "https://api.x.com/2/oauth2/token",
    userinfo_endpoint: "https://api.x.com/2/users/me?user.fields=profile_image_url",
    default_scopes: &["users.read", "tweet.read", "offline.access", "users.email"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Basic,
    profile_mapping: ProfileMapping {
        id: "data.id",
        name: "data.name",
        email: "data.email",
        image: "data.profile_image_url",
        email_verified: "email_verified",
        email_verified_default: false,
    },
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- Microsoft Entra ID ---
pub static MICROSOFT: ProviderConfig = ProviderConfig {
    id: "microsoft",
    name: "Microsoft EntraID",
    authorization_endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    token_endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    userinfo_endpoint: "", // Microsoft uses ID token
    default_scopes: &["openid", "profile", "email", "User.Read", "offline_access"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: SUB_MAPPING,
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- Facebook ---
pub static FACEBOOK: ProviderConfig = ProviderConfig {
    id: "facebook",
    name: "Facebook",
    authorization_endpoint: "https://www.facebook.com/v24.0/dialog/oauth",
    token_endpoint: "https://graph.facebook.com/v24.0/oauth/access_token",
    userinfo_endpoint: "https://graph.facebook.com/me?fields=id,name,email,picture",
    default_scopes: &["email", "public_profile"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: DEFAULT_MAPPING,
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- Spotify ---
pub static SPOTIFY: ProviderConfig = ProviderConfig {
    id: "spotify",
    name: "Spotify",
    authorization_endpoint: "https://accounts.spotify.com/authorize",
    token_endpoint: "https://accounts.spotify.com/api/token",
    userinfo_endpoint: "https://api.spotify.com/v1/me",
    default_scopes: &["user-read-email"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: ProfileMapping {
        id: "id",
        name: "display_name",
        email: "email",
        image: "images.0.url",
        email_verified: "email_verified",
        email_verified_default: false,
    },
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- Twitch ---
pub static TWITCH: ProviderConfig = ProviderConfig {
    id: "twitch",
    name: "Twitch",
    authorization_endpoint: "https://id.twitch.tv/oauth2/authorize",
    token_endpoint: "https://id.twitch.tv/oauth2/token",
    userinfo_endpoint: "", // Twitch uses ID token
    default_scopes: &["user:read:email", "openid"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: SUB_MAPPING,
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- LinkedIn ---
pub static LINKEDIN: ProviderConfig = ProviderConfig {
    id: "linkedin",
    name: "Linkedin",
    authorization_endpoint: "https://www.linkedin.com/oauth/v2/authorization",
    token_endpoint: "https://www.linkedin.com/oauth/v2/accessToken",
    userinfo_endpoint: "https://api.linkedin.com/v2/userinfo",
    default_scopes: &["profile", "email", "openid"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: SUB_MAPPING,
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- GitLab ---
pub static GITLAB: ProviderConfig = ProviderConfig {
    id: "gitlab",
    name: "Gitlab",
    authorization_endpoint: "https://gitlab.com/oauth/authorize",
    token_endpoint: "https://gitlab.com/oauth/token",
    userinfo_endpoint: "https://gitlab.com/api/v4/user",
    default_scopes: &["read_user"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: ProfileMapping {
        id: "id",
        name: "name",
        email: "email",
        image: "avatar_url",
        email_verified: "email_verified",
        email_verified_default: false,
    },
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- TikTok ---
pub static TIKTOK: ProviderConfig = ProviderConfig {
    id: "tiktok",
    name: "TikTok",
    authorization_endpoint: "https://www.tiktok.com/v2/auth/authorize",
    token_endpoint: "https://open.tiktokapis.com/v2/oauth/token/",
    userinfo_endpoint: "https://open.tiktokapis.com/v2/user/info/?fields=open_id,avatar_large_url,display_name,username",
    default_scopes: &["user.info.profile"],
    scope_joiner: ",",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: ProfileMapping {
        id: "data.user.open_id",
        name: "data.user.display_name",
        email: "data.user.username",
        image: "data.user.avatar_large_url",
        email_verified: "email_verified",
        email_verified_default: false,
    },
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- Reddit ---
pub static REDDIT: ProviderConfig = ProviderConfig {
    id: "reddit",
    name: "Reddit",
    authorization_endpoint: "https://www.reddit.com/api/v1/authorize",
    token_endpoint: "https://www.reddit.com/api/v1/access_token",
    userinfo_endpoint: "https://oauth.reddit.com/api/v1/me",
    default_scopes: &["identity"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Basic,
    profile_mapping: ProfileMapping {
        id: "id",
        name: "name",
        email: "oauth_client_id",
        image: "icon_img",
        email_verified: "has_verified_email",
        email_verified_default: false,
    },
    extra_userinfo_headers: &[("User-Agent", "better-auth")],
    userinfo_is_post: false,
};

// --- Slack ---
pub static SLACK: ProviderConfig = ProviderConfig {
    id: "slack",
    name: "Slack",
    authorization_endpoint: "https://slack.com/openid/connect/authorize",
    token_endpoint: "https://slack.com/api/openid.connect.token",
    userinfo_endpoint: "https://slack.com/api/openid.connect.userInfo",
    default_scopes: &["openid", "profile", "email"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: SUB_MAPPING,
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- Dropbox ---
pub static DROPBOX: ProviderConfig = ProviderConfig {
    id: "dropbox",
    name: "Dropbox",
    authorization_endpoint: "https://www.dropbox.com/oauth2/authorize",
    token_endpoint: "https://api.dropboxapi.com/oauth2/token",
    userinfo_endpoint: "https://api.dropboxapi.com/2/users/get_current_account",
    default_scopes: &["account_info.read"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: ProfileMapping {
        id: "account_id",
        name: "name.display_name",
        email: "email",
        image: "profile_photo_url",
        email_verified: "email_verified",
        email_verified_default: false,
    },
    extra_userinfo_headers: &[],
    userinfo_is_post: true,
};

// --- Notion ---
pub static NOTION: ProviderConfig = ProviderConfig {
    id: "notion",
    name: "Notion",
    authorization_endpoint: "https://api.notion.com/v1/oauth/authorize",
    token_endpoint: "https://api.notion.com/v1/oauth/token",
    userinfo_endpoint: "https://api.notion.com/v1/users/me",
    default_scopes: &[],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Basic,
    profile_mapping: ProfileMapping {
        id: "bot.owner.user.id",
        name: "bot.owner.user.name",
        email: "bot.owner.user.person.email",
        image: "bot.owner.user.avatar_url",
        email_verified: "email_verified",
        email_verified_default: false,
    },
    extra_userinfo_headers: &[("Notion-Version", "2022-06-28")],
    userinfo_is_post: false,
};

// --- Zoom ---
pub static ZOOM: ProviderConfig = ProviderConfig {
    id: "zoom",
    name: "Zoom",
    authorization_endpoint: "https://zoom.us/oauth/authorize",
    token_endpoint: "https://zoom.us/oauth/token",
    userinfo_endpoint: "https://api.zoom.us/v2/users/me",
    default_scopes: &[],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: ProfileMapping {
        id: "id",
        name: "display_name",
        email: "email",
        image: "pic_url",
        email_verified: "verified",
        email_verified_default: false,
    },
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- Roblox ---
pub static ROBLOX: ProviderConfig = ProviderConfig {
    id: "roblox",
    name: "Roblox",
    authorization_endpoint: "https://apis.roblox.com/oauth/v1/authorize",
    token_endpoint: "https://apis.roblox.com/oauth/v1/token",
    userinfo_endpoint: "https://apis.roblox.com/oauth/v1/userinfo",
    default_scopes: &["openid", "profile"],
    scope_joiner: "+",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: ProfileMapping {
        id: "sub",
        name: "nickname",
        email: "preferred_username",
        image: "picture",
        email_verified: "email_verified",
        email_verified_default: false,
    },
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- Cognito ---
pub static COGNITO: ProviderConfig = ProviderConfig {
    id: "cognito",
    name: "Cognito",
    authorization_endpoint: "", // Dynamic — set by domain option
    token_endpoint: "",         // Dynamic — set by domain option
    userinfo_endpoint: "",      // Dynamic — set by domain option
    default_scopes: &["openid", "profile", "email"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: SUB_MAPPING,
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- Figma ---
pub static FIGMA: ProviderConfig = ProviderConfig {
    id: "figma",
    name: "Figma",
    authorization_endpoint: "https://www.figma.com/oauth",
    token_endpoint: "https://api.figma.com/v1/oauth/token",
    userinfo_endpoint: "https://api.figma.com/v1/me",
    default_scopes: &["current_user:read"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Basic,
    profile_mapping: ProfileMapping {
        id: "id",
        name: "handle",
        email: "email",
        image: "img_url",
        email_verified: "email_verified",
        email_verified_default: false,
    },
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- Salesforce ---
pub static SALESFORCE: ProviderConfig = ProviderConfig {
    id: "salesforce",
    name: "Salesforce",
    authorization_endpoint: "https://login.salesforce.com/services/oauth2/authorize",
    token_endpoint: "https://login.salesforce.com/services/oauth2/token",
    userinfo_endpoint: "https://login.salesforce.com/services/oauth2/userinfo",
    default_scopes: &["openid", "email", "profile"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: ProfileMapping {
        id: "user_id",
        name: "name",
        email: "email",
        image: "photos.picture",
        email_verified: "email_verified",
        email_verified_default: false,
    },
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- VK ---
pub static VK: ProviderConfig = ProviderConfig {
    id: "vk",
    name: "VK",
    authorization_endpoint: "https://id.vk.com/authorize",
    token_endpoint: "https://id.vk.com/oauth2/auth",
    userinfo_endpoint: "https://id.vk.com/oauth2/user_info",
    default_scopes: &["email", "phone"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: ProfileMapping {
        id: "user.user_id",
        name: "user.first_name",
        email: "user.email",
        image: "user.avatar",
        email_verified: "email_verified",
        email_verified_default: false,
    },
    extra_userinfo_headers: &[],
    userinfo_is_post: true,
};

// --- Hugging Face ---
pub static HUGGINGFACE: ProviderConfig = ProviderConfig {
    id: "huggingface",
    name: "Hugging Face",
    authorization_endpoint: "https://huggingface.co/oauth/authorize",
    token_endpoint: "https://huggingface.co/oauth/token",
    userinfo_endpoint: "https://huggingface.co/oauth/userinfo",
    default_scopes: &["openid", "profile", "email"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: SUB_MAPPING,
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- Atlassian ---
pub static ATLASSIAN: ProviderConfig = ProviderConfig {
    id: "atlassian",
    name: "Atlassian",
    authorization_endpoint: "https://auth.atlassian.com/authorize",
    token_endpoint: "https://auth.atlassian.com/oauth/token",
    userinfo_endpoint: "https://api.atlassian.com/me",
    default_scopes: &["read:me"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: ProfileMapping {
        id: "account_id",
        name: "name",
        email: "email",
        image: "picture",
        email_verified: "email_verified",
        email_verified_default: false,
    },
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- Kakao ---
pub static KAKAO: ProviderConfig = ProviderConfig {
    id: "kakao",
    name: "Kakao",
    authorization_endpoint: "https://kauth.kakao.com/oauth/authorize",
    token_endpoint: "https://kauth.kakao.com/oauth/token",
    userinfo_endpoint: "https://kapi.kakao.com/v2/user/me",
    default_scopes: &["account_email", "profile_nickname", "profile_image"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: ProfileMapping {
        id: "id",
        name: "kakao_account.profile.nickname",
        email: "kakao_account.email",
        image: "kakao_account.profile.profile_image_url",
        email_verified: "kakao_account.is_email_verified",
        email_verified_default: false,
    },
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- Naver ---
pub static NAVER: ProviderConfig = ProviderConfig {
    id: "naver",
    name: "Naver",
    authorization_endpoint: "https://nid.naver.com/oauth2.0/authorize",
    token_endpoint: "https://nid.naver.com/oauth2.0/token",
    userinfo_endpoint: "https://openapi.naver.com/v1/nid/me",
    default_scopes: &[],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: ProfileMapping {
        id: "response.id",
        name: "response.name",
        email: "response.email",
        image: "response.profile_image",
        email_verified: "email_verified",
        email_verified_default: false,
    },
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- LINE ---
pub static LINE: ProviderConfig = ProviderConfig {
    id: "line",
    name: "LINE",
    authorization_endpoint: "https://access.line.me/oauth2/v2.1/authorize",
    token_endpoint: "https://api.line.me/oauth2/v2.1/token",
    userinfo_endpoint: "https://api.line.me/v2/profile",
    default_scopes: &["openid", "profile", "email"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: ProfileMapping {
        id: "userId",
        name: "displayName",
        email: "email",
        image: "pictureUrl",
        email_verified: "email_verified",
        email_verified_default: false,
    },
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- Linear ---
pub static LINEAR: ProviderConfig = ProviderConfig {
    id: "linear",
    name: "Linear",
    authorization_endpoint: "https://linear.app/oauth/authorize",
    token_endpoint: "https://api.linear.app/oauth/token",
    userinfo_endpoint: "https://api.linear.app/graphql",
    default_scopes: &["read"],
    scope_joiner: ",",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: ProfileMapping {
        id: "data.viewer.id",
        name: "data.viewer.name",
        email: "data.viewer.email",
        image: "data.viewer.avatarUrl",
        email_verified: "email_verified",
        email_verified_default: false,
    },
    extra_userinfo_headers: &[],
    userinfo_is_post: true,
};

// --- Kick ---
pub static KICK: ProviderConfig = ProviderConfig {
    id: "kick",
    name: "Kick",
    authorization_endpoint: "https://id.kick.com/oauth/authorize",
    token_endpoint: "https://id.kick.com/oauth/token",
    userinfo_endpoint: "https://id.kick.com/api/v1/user",
    default_scopes: &["user:read", "user:read:email"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: ProfileMapping {
        id: "user_id",
        name: "name",
        email: "email",
        image: "profile_picture",
        email_verified: "email_verified",
        email_verified_default: false,
    },
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- PayPal ---
pub static PAYPAL: ProviderConfig = ProviderConfig {
    id: "paypal",
    name: "PayPal",
    authorization_endpoint: "https://www.paypal.com/signin/authorize",
    token_endpoint: "https://api-m.paypal.com/v1/oauth2/token",
    userinfo_endpoint: "https://api-m.paypal.com/v1/identity/openidconnect/userinfo?schema=openid",
    default_scopes: &["openid", "email", "profile"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Basic,
    profile_mapping: ProfileMapping {
        id: "user_id",
        name: "name",
        email: "email",
        image: "picture",
        email_verified: "email_verified",
        email_verified_default: false,
    },
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- Paybin ---
pub static PAYBIN: ProviderConfig = ProviderConfig {
    id: "paybin",
    name: "Paybin",
    authorization_endpoint: "https://paybin.app/api/oauth/authorize",
    token_endpoint: "https://paybin.app/api/oauth/token",
    userinfo_endpoint: "https://paybin.app/api/oauth/userinfo",
    default_scopes: &["user:read"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: DEFAULT_MAPPING,
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- Polar ---
pub static POLAR: ProviderConfig = ProviderConfig {
    id: "polar",
    name: "Polar",
    authorization_endpoint: "https://polar.sh/oauth2/authorize",
    token_endpoint: "https://api.polar.sh/v1/oauth2/token",
    userinfo_endpoint: "https://api.polar.sh/v1/oauth2/userinfo",
    default_scopes: &["openid", "profile", "email"],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: SUB_MAPPING,
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

// --- Vercel ---
pub static VERCEL: ProviderConfig = ProviderConfig {
    id: "vercel",
    name: "Vercel",
    authorization_endpoint: "https://vercel.com/integrations/oauth-playground/authorize",
    token_endpoint: "https://api.vercel.com/v1/integrations/oauth/token",
    userinfo_endpoint: "https://api.vercel.com/v2/user",
    default_scopes: &[],
    scope_joiner: " ",
    auth_method: AuthenticationMethod::Post,
    profile_mapping: ProfileMapping {
        id: "user.id",
        name: "user.name",
        email: "user.email",
        image: "user.avatar",
        email_verified: "email_verified",
        email_verified_default: false,
    },
    extra_userinfo_headers: &[],
    userinfo_is_post: false,
};

/// Lookup a provider config by its ID string.
pub fn get_provider_config(id: &str) -> Option<&'static ProviderConfig> {
    match id {
        "google" => Some(&GOOGLE),
        "github" => Some(&GITHUB),
        "apple" => Some(&APPLE),
        "discord" => Some(&DISCORD),
        "twitter" => Some(&TWITTER),
        "microsoft" | "microsoft-entra-id" => Some(&MICROSOFT),
        "facebook" => Some(&FACEBOOK),
        "spotify" => Some(&SPOTIFY),
        "twitch" => Some(&TWITCH),
        "linkedin" => Some(&LINKEDIN),
        "gitlab" => Some(&GITLAB),
        "tiktok" => Some(&TIKTOK),
        "reddit" => Some(&REDDIT),
        "slack" => Some(&SLACK),
        "dropbox" => Some(&DROPBOX),
        "notion" => Some(&NOTION),
        "zoom" => Some(&ZOOM),
        "roblox" => Some(&ROBLOX),
        "cognito" => Some(&COGNITO),
        "figma" => Some(&FIGMA),
        "salesforce" => Some(&SALESFORCE),
        "vk" => Some(&VK),
        "huggingface" => Some(&HUGGINGFACE),
        "atlassian" => Some(&ATLASSIAN),
        "kakao" => Some(&KAKAO),
        "naver" => Some(&NAVER),
        "line" => Some(&LINE),
        "linear" => Some(&LINEAR),
        "kick" => Some(&KICK),
        "paypal" => Some(&PAYPAL),
        "paybin" => Some(&PAYBIN),
        "polar" => Some(&POLAR),
        "vercel" => Some(&VERCEL),
        _ => None,
    }
}

/// All provider IDs.
pub const PROVIDER_IDS: &[&str] = &[
    "google", "github", "apple", "discord", "twitter", "microsoft", "facebook",
    "spotify", "twitch", "linkedin", "gitlab", "tiktok", "reddit", "slack",
    "dropbox", "notion", "zoom", "roblox", "cognito", "figma", "salesforce",
    "vk", "huggingface", "atlassian", "kakao", "naver", "line", "linear",
    "kick", "paypal", "paybin", "polar", "vercel",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_providers_registered() {
        assert_eq!(PROVIDER_IDS.len(), 33);
        for id in PROVIDER_IDS {
            assert!(
                get_provider_config(id).is_some(),
                "Provider '{id}' not registered"
            );
        }
    }

    #[test]
    fn test_provider_lookup() {
        let google = get_provider_config("google").unwrap();
        assert_eq!(google.id, "google");
        assert_eq!(google.name, "Google");
        assert_eq!(
            google.authorization_endpoint,
            "https://accounts.google.com/o/oauth2/v2/auth"
        );
    }

    #[test]
    fn test_extract_nested_field() {
        let data = serde_json::json!({
            "data": {
                "user": {
                    "open_id": "12345"
                }
            }
        });
        assert_eq!(
            GenericOAuthProvider::extract_field(&data, "data.user.open_id"),
            Some("12345".to_string())
        );
    }

    #[test]
    fn test_generic_provider_creation() {
        let options = ProviderOptions::new("client123").with_secret("secret456");
        let provider = GenericOAuthProvider::new(&GITHUB, options);
        assert_eq!(provider.id(), "github");
        assert_eq!(provider.name(), "GitHub");
        assert_eq!(provider.default_scopes(), vec!["read:user", "user:email"]);
    }

    #[test]
    fn test_twitter_uses_basic_auth() {
        let config = get_provider_config("twitter").unwrap();
        assert_eq!(config.auth_method, AuthenticationMethod::Basic);
    }
}
