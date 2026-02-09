//! # better-auth-i18n
//!
//! i18n plugin for Better Auth.
//! Maps to TS `packages/i18n/` (316 lines, 3 files).
//!
//! Translates error messages based on detected locale using configurable
//! detection strategies (header, cookie, session, callback).
//!
//! ## Usage
//! ```rust,ignore
//! use better_auth_i18n::*;
//! use std::collections::HashMap;
//!
//! let mut translations = HashMap::new();
//! translations.insert("en".to_string(), {
//!     let mut m = HashMap::new();
//!     m.insert("USER_NOT_FOUND".to_string(), "User not found".to_string());
//!     m
//! });
//! translations.insert("fr".to_string(), {
//!     let mut m = HashMap::new();
//!     m.insert("USER_NOT_FOUND".to_string(), "Utilisateur non trouvé".to_string());
//!     m
//! });
//!
//! let options = I18nOptions {
//!     translations,
//!     detection: vec![LocaleDetectionStrategy::Header, LocaleDetectionStrategy::Cookie],
//!     ..Default::default()
//! };
//!
//! // Detect locale from request
//! let locale = detect_locale_from_headers("en-US,fr;q=0.9", &options);
//! assert_eq!(locale, "en");
//!
//! // Translate error
//! let msg = translate(&options, &locale, "USER_NOT_FOUND");
//! assert_eq!(msg, Some("User not found"));
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Translation dictionary: error_code -> translated message.
pub type TranslationDictionary = HashMap<String, String>;

/// Locale detection strategies.
/// Maps to TS `LocaleDetectionStrategy`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LocaleDetectionStrategy {
    /// Detect from Accept-Language header.
    Header,
    /// Detect from cookie.
    Cookie,
    /// Detect from user session field.
    Session,
    /// Detect using a custom callback.
    Callback,
}

/// i18n plugin options.
/// Maps to TS `I18nOptions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct I18nOptions {
    /// Translations keyed by locale code.
    pub translations: HashMap<String, TranslationDictionary>,
    /// Default locale (falls back to "en" or first available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_locale: Option<String>,
    /// Detection strategies in priority order.
    #[serde(default = "default_detection")]
    pub detection: Vec<LocaleDetectionStrategy>,
    /// Cookie name for locale (used with Cookie strategy).
    #[serde(default = "default_cookie_name")]
    pub locale_cookie: String,
    /// User field name for locale (used with Session strategy).
    #[serde(default = "default_user_field")]
    pub user_locale_field: String,
}

fn default_detection() -> Vec<LocaleDetectionStrategy> {
    vec![LocaleDetectionStrategy::Header]
}
fn default_cookie_name() -> String { "locale".to_string() }
fn default_user_field() -> String { "locale".to_string() }

impl Default for I18nOptions {
    fn default() -> Self {
        Self {
            translations: HashMap::new(),
            default_locale: None,
            detection: default_detection(),
            locale_cookie: default_cookie_name(),
            user_locale_field: default_user_field(),
        }
    }
}

impl I18nOptions {
    /// Get the resolved default locale.
    pub fn resolved_default_locale(&self) -> &str {
        if let Some(ref locale) = self.default_locale {
            if self.translations.contains_key(locale) {
                return locale;
            }
        }
        if self.translations.contains_key("en") {
            return "en";
        }
        self.translations.keys().next().map(|s| s.as_str()).unwrap_or("en")
    }

    /// Get available locales.
    pub fn available_locales(&self) -> Vec<&str> {
        self.translations.keys().map(|s| s.as_str()).collect()
    }
}

/// Parse Accept-Language header and return locales sorted by quality.
/// Maps to TS `parseAcceptLanguage`.
///
/// Example: "en-US,fr;q=0.9,de;q=0.8" → ["en", "fr", "de"]
pub fn parse_accept_language(header: &str) -> Vec<String> {
    let mut entries: Vec<(String, f32)> = header
        .split(',')
        .filter_map(|part| {
            let parts: Vec<&str> = part.trim().split(';').collect();
            let locale_str = parts.first()?.trim();
            // Get base locale (e.g., "en" from "en-US")
            let locale = locale_str.split('-').next()?.to_string();
            if locale.is_empty() { return None; }

            let quality = parts.get(1)
                .and_then(|q| q.trim().strip_prefix("q="))
                .and_then(|q| q.parse::<f32>().ok())
                .unwrap_or(1.0);

            Some((locale, quality))
        })
        .collect();

    entries.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    entries.into_iter().map(|(l, _)| l).collect()
}

/// Detect the locale from an Accept-Language header string.
pub fn detect_locale_from_headers(accept_language: &str, options: &I18nOptions) -> String {
    let preferred = parse_accept_language(accept_language);
    let available: Vec<&str> = options.available_locales();

    for locale in &preferred {
        if available.contains(&locale.as_str()) {
            return locale.clone();
        }
    }

    options.resolved_default_locale().to_string()
}

/// Translate an error code to the localized message.
pub fn translate<'a>(options: &'a I18nOptions, locale: &str, error_code: &str) -> Option<&'a str> {
    options.translations
        .get(locale)
        .and_then(|dict| dict.get(error_code))
        .map(|s| s.as_str())
}

/// Translate with fallback to default locale.
pub fn translate_with_fallback<'a>(
    options: &'a I18nOptions,
    locale: &str,
    error_code: &str,
) -> Option<&'a str> {
    // Try the requested locale first
    if let Some(msg) = translate(options, locale, error_code) {
        return Some(msg);
    }
    // Fall back to default locale
    let default = options.resolved_default_locale();
    if default != locale {
        translate(options, default, error_code)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_options() -> I18nOptions {
        let mut translations = HashMap::new();
        translations.insert("en".to_string(), {
            let mut m = HashMap::new();
            m.insert("USER_NOT_FOUND".to_string(), "User not found".to_string());
            m.insert("INVALID_PASSWORD".to_string(), "Invalid password".to_string());
            m
        });
        translations.insert("fr".to_string(), {
            let mut m = HashMap::new();
            m.insert("USER_NOT_FOUND".to_string(), "Utilisateur non trouvé".to_string());
            m
        });
        translations.insert("es".to_string(), {
            let mut m = HashMap::new();
            m.insert("USER_NOT_FOUND".to_string(), "Usuario no encontrado".to_string());
            m
        });
        I18nOptions {
            translations,
            default_locale: Some("en".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn test_parse_accept_language() {
        let locales = parse_accept_language("en-US,fr;q=0.9,de;q=0.8");
        assert_eq!(locales, vec!["en", "fr", "de"]);
    }

    #[test]
    fn test_parse_accept_language_single() {
        let locales = parse_accept_language("fr");
        assert_eq!(locales, vec!["fr"]);
    }

    #[test]
    fn test_parse_accept_language_empty() {
        let locales = parse_accept_language("");
        assert!(locales.is_empty());
    }

    #[test]
    fn test_detect_locale_from_headers() {
        let opts = test_options();
        assert_eq!(detect_locale_from_headers("fr-FR,en;q=0.9", &opts), "fr");
        assert_eq!(detect_locale_from_headers("de-DE,en;q=0.9", &opts), "en");
        assert_eq!(detect_locale_from_headers("ja", &opts), "en"); // fallback
    }

    #[test]
    fn test_translate() {
        let opts = test_options();
        assert_eq!(translate(&opts, "en", "USER_NOT_FOUND"), Some("User not found"));
        assert_eq!(translate(&opts, "fr", "USER_NOT_FOUND"), Some("Utilisateur non trouvé"));
        assert_eq!(translate(&opts, "es", "USER_NOT_FOUND"), Some("Usuario no encontrado"));
        assert_eq!(translate(&opts, "de", "USER_NOT_FOUND"), None);
    }

    #[test]
    fn test_translate_with_fallback() {
        let opts = test_options();
        // fr has USER_NOT_FOUND
        assert_eq!(translate_with_fallback(&opts, "fr", "USER_NOT_FOUND"), Some("Utilisateur non trouvé"));
        // fr doesn't have INVALID_PASSWORD, falls back to en
        assert_eq!(translate_with_fallback(&opts, "fr", "INVALID_PASSWORD"), Some("Invalid password"));
        // Unknown code
        assert_eq!(translate_with_fallback(&opts, "en", "UNKNOWN"), None);
    }

    #[test]
    fn test_resolved_default_locale() {
        let opts = test_options();
        assert_eq!(opts.resolved_default_locale(), "en");

        let opts2 = I18nOptions {
            translations: {
                let mut m = HashMap::new();
                m.insert("ja".to_string(), HashMap::new());
                m
            },
            default_locale: None,
            ..Default::default()
        };
        assert_eq!(opts2.resolved_default_locale(), "ja");
    }

    #[test]
    fn test_available_locales() {
        let opts = test_options();
        let mut locales = opts.available_locales();
        locales.sort();
        assert_eq!(locales, vec!["en", "es", "fr"]);
    }
}
