//! User consent management.

use crate::types::Consent;
use chrono::Utc;

/// Check if user has previously granted consent for the requested scopes.
pub fn has_consent(
    existing_consents: &[Consent],
    client_id: &str,
    requested_scopes: &[&str],
) -> bool {
    existing_consents.iter().any(|c| {
        c.client_id == client_id
            && requested_scopes.iter().all(|s| c.scopes.contains(&s.to_string()))
    })
}

/// Build a new consent record.
pub fn build_consent(user_id: &str, client_id: &str, scopes: &[&str]) -> Consent {
    let now = Utc::now();
    Consent {
        id: uuid::Uuid::new_v4().to_string(),
        user_id: user_id.to_string(),
        client_id: client_id.to_string(),
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        created_at: now,
        updated_at: now,
    }
}

/// Merge new scopes into an existing consent.
pub fn merge_scopes(existing: &mut Consent, new_scopes: &[&str]) {
    for scope in new_scopes {
        let s = scope.to_string();
        if !existing.scopes.contains(&s) {
            existing.scopes.push(s);
        }
    }
    existing.updated_at = Utc::now();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_consent() {
        let consent = build_consent("u1", "c1", &["openid", "profile"]);
        assert!(has_consent(&[consent.clone()], "c1", &["openid"]));
        assert!(has_consent(&[consent.clone()], "c1", &["openid", "profile"]));
        assert!(!has_consent(&[consent], "c1", &["openid", "email"]));
    }

    #[test]
    fn test_no_consent() {
        assert!(!has_consent(&[], "c1", &["openid"]));
    }

    #[test]
    fn test_merge_scopes() {
        let mut consent = build_consent("u1", "c1", &["openid"]);
        merge_scopes(&mut consent, &["profile", "email"]);
        assert_eq!(consent.scopes.len(), 3);
        // Merge again shouldn't duplicate
        merge_scopes(&mut consent, &["openid", "profile"]);
        assert_eq!(consent.scopes.len(), 3);
    }
}
