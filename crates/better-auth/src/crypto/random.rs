// Random string generation — maps to packages/better-auth/src/crypto/random.ts
//
// Generates a random string of the given length using alphanumeric + "-_" characters.

use rand::Rng;

/// Character set: a-z, A-Z, 0-9, -, _
const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";

/// Generate a random string of the specified length.
///
/// Uses the character set: `[a-zA-Z0-9\-_]` (64 characters).
/// Maps to TypeScript `generateRandomString`.
pub fn generate_random_string(length: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correct_length() {
        assert_eq!(generate_random_string(0).len(), 0);
        assert_eq!(generate_random_string(1).len(), 1);
        assert_eq!(generate_random_string(32).len(), 32);
        assert_eq!(generate_random_string(128).len(), 128);
    }

    #[test]
    fn test_valid_characters() {
        let s = generate_random_string(1000);
        for c in s.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_',
                "Invalid character: {c}"
            );
        }
    }

    #[test]
    fn test_uniqueness() {
        let a = generate_random_string(32);
        let b = generate_random_string(32);
        assert_ne!(a, b);
    }
}
