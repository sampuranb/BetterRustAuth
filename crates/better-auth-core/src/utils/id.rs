// ID generation utility — maps to packages/core/src/utils/id.ts
//
// Generates nanoid-based unique identifiers.

/// Generate a unique ID using nanoid.
/// Default length matches the TypeScript version (21 characters).
pub fn generate_id() -> String {
    nanoid::nanoid!()
}

/// Generate an ID with a custom length.
pub fn generate_id_with_length(len: usize) -> String {
    nanoid::nanoid!(len)
}

/// Generate an ID with a custom alphabet and length.
pub fn generate_id_custom(len: usize, alphabet: &[char]) -> String {
    nanoid::nanoid!(len, alphabet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_id_length() {
        let id = generate_id();
        assert_eq!(id.len(), 21);
    }

    #[test]
    fn test_generate_id_custom_length() {
        let id = generate_id_with_length(32);
        assert_eq!(id.len(), 32);
    }

    #[test]
    fn test_ids_are_unique() {
        let id1 = generate_id();
        let id2 = generate_id();
        assert_ne!(id1, id2);
    }
}
