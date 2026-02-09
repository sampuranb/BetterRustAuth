// Project ID generation — mirrors packages/telemetry/src/project-id.ts
//
// Generates a stable, anonymous project identifier by hashing the
// project name + base URL, or falling back to a random ID.

use base64::Engine;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

static PROJECT_ID: OnceLock<String> = OnceLock::new();

/// Hash data to base64.
///
/// Maps to TS `hashToBase64(data)`.
fn hash_to_base64(data: &str) -> String {
    let hash = Sha256::digest(data.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hash)
}

/// Generate a random alphanumeric ID of given length.
fn generate_id(len: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect()
}

/// Try to read the project name from `Cargo.toml` in the current directory.
///
/// Maps to TS `getNameFromLocalPackageJson()`.
fn get_project_name() -> Option<String> {
    let cargo_toml = std::fs::read_to_string("Cargo.toml").ok()?;
    // Simple TOML parsing — look for `name = "..."` under [package]
    let mut in_package = false;
    for line in cargo_toml.lines() {
        let trimmed = line.trim();
        if trimmed == "[package]" {
            in_package = true;
            continue;
        }
        if trimmed.starts_with('[') {
            in_package = false;
            continue;
        }
        if in_package && trimmed.starts_with("name") {
            if let Some(val) = trimmed.split('=').nth(1) {
                let name = val.trim().trim_matches('"').trim_matches('\'');
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

/// Get a stable project ID.
///
/// Maps to TS `getProjectId(baseUrl)`.
pub async fn get_project_id(base_url: Option<&str>) -> String {
    if let Some(cached) = PROJECT_ID.get() {
        return cached.clone();
    }

    let id = compute_project_id(base_url);
    PROJECT_ID.get_or_init(|| id).clone()
}

fn compute_project_id(base_url: Option<&str>) -> String {
    // Try project name from Cargo.toml
    if let Some(project_name) = get_project_name() {
        let input = match base_url {
            Some(url) => format!("{}{}", url, project_name),
            None => project_name,
        };
        return hash_to_base64(&input);
    }

    // Fallback: hash the base URL if present
    if let Some(url) = base_url {
        return hash_to_base64(url);
    }

    // Final fallback: random ID
    generate_id(32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_to_base64_deterministic() {
        let a = hash_to_base64("hello");
        let b = hash_to_base64("hello");
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn test_hash_to_base64_different_inputs() {
        let a = hash_to_base64("hello");
        let b = hash_to_base64("world");
        assert_ne!(a, b);
    }

    #[test]
    fn test_generate_id() {
        let id = generate_id(32);
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[tokio::test]
    async fn test_compute_project_id_with_url() {
        let id = compute_project_id(Some("https://example.com"));
        assert!(!id.is_empty());
    }

    #[tokio::test]
    async fn test_compute_project_id_without_url() {
        let id = compute_project_id(None);
        assert!(!id.is_empty());
    }
}
