// Wildcard matching — maps to packages/better-auth/src/utils/wildcard.ts
//
// Glob-style pattern matching used for origin patterns, path matching, etc.
// Supports `*` (single segment) and `**` (multi-segment) wildcards.

/// Check if a sample string matches a wildcard pattern.
///
/// Supports:
/// - `*` — matches any characters except `/`
/// - `**` — matches any characters including `/`
/// - `?` — matches a single character
///
/// Matches TS `wildcardMatch`.
pub fn wildcard_match(pattern: &str, sample: &str) -> bool {
    let regex_pattern = transform_pattern(pattern);
    let full_pattern = format!("^{}$", regex_pattern);
    match regex::Regex::new(&full_pattern) {
        Ok(re) => re.is_match(sample),
        Err(_) => false,
    }
}

/// Check if a sample matches any of the given patterns.
pub fn wildcard_match_any(patterns: &[&str], sample: &str) -> bool {
    patterns.iter().any(|p| wildcard_match(p, sample))
}

/// Transform a glob pattern into a regex pattern string.
fn transform_pattern(pattern: &str) -> String {
    let mut result = String::new();
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        match c {
            '*' => {
                // Check for **
                if i + 1 < chars.len() && chars[i + 1] == '*' {
                    // ** matches everything including /
                    result.push_str(".*?");
                    i += 2;
                    // Skip trailing separator
                    if i < chars.len() && chars[i] == '/' {
                        result.push_str("(?:/)?");
                        i += 1;
                    }
                } else {
                    // * matches everything except /
                    result.push_str("[^/]*?");
                    i += 1;
                }
            }
            '?' => {
                result.push_str("[^/]");
                i += 1;
            }
            '\\' => {
                // Escape next character
                i += 1;
                if i < chars.len() {
                    result.push_str(&regex::escape(&chars[i].to_string()));
                    i += 1;
                }
            }
            _ => {
                result.push_str(&regex::escape(&c.to_string()));
                i += 1;
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        assert!(wildcard_match("hello", "hello"));
        assert!(!wildcard_match("hello", "world"));
    }

    #[test]
    fn test_star_wildcard() {
        assert!(wildcard_match("src/*.js", "src/index.js"));
        assert!(wildcard_match("*.txt", "readme.txt"));
        assert!(!wildcard_match("src/*.js", "src/nested/deep.js"));
    }

    #[test]
    fn test_double_star() {
        assert!(wildcard_match("src/**/*.js", "src/nested/deep.js"));
        assert!(wildcard_match("**/*.js", "any/path/file.js"));
    }

    #[test]
    fn test_question_mark() {
        assert!(wildcard_match("file?.txt", "file1.txt"));
        assert!(!wildcard_match("file?.txt", "file12.txt"));
    }

    #[test]
    fn test_origin_patterns() {
        assert!(wildcard_match("https://*.example.com", "https://app.example.com"));
        assert!(!wildcard_match("https://*.example.com", "https://other.domain.com"));
    }

    #[test]
    fn test_match_any() {
        let patterns = &["*.js", "*.ts"];
        assert!(wildcard_match_any(patterns, "file.js"));
        assert!(wildcard_match_any(patterns, "file.ts"));
        assert!(!wildcard_match_any(patterns, "file.rs"));
    }
}
