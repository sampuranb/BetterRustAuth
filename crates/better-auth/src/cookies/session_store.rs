// Session store — maps to packages/better-auth/src/cookies/session-store.ts
//
// Handles chunking large cookie data (>4093 bytes) across multiple cookies.
// Each chunk is named `{base_name}.{index}`.

/// Maximum cookie value size before chunking is needed.
pub const MAX_COOKIE_SIZE: usize = 4093;

/// A cookie chunk ready to be set.
#[derive(Debug, Clone)]
pub struct CookieChunk {
    pub name: String,
    pub value: String,
}

/// Split a large cookie value into chunks of `MAX_COOKIE_SIZE` bytes.
///
/// Returns a list of `CookieChunk` with names like `name.0`, `name.1`, etc.
pub fn chunk_cookie_value(name: &str, data: &str) -> Vec<CookieChunk> {
    if data.len() <= MAX_COOKIE_SIZE {
        return vec![CookieChunk {
            name: name.to_string(),
            value: data.to_string(),
        }];
    }

    let mut chunks = Vec::new();
    let bytes = data.as_bytes();
    let mut offset = 0;
    let mut index = 0;

    while offset < bytes.len() {
        let end = (offset + MAX_COOKIE_SIZE).min(bytes.len());
        let chunk_value = &data[offset..end];
        chunks.push(CookieChunk {
            name: format!("{}.{}", name, index),
            value: chunk_value.to_string(),
        });
        offset = end;
        index += 1;
    }

    chunks
}

/// Generate "clean" cookies that expire all chunk cookies.
/// Used when transitioning from chunked to non-chunked storage.
///
/// Returns cookies with empty values (caller should set max_age=0).
pub fn clean_chunk_cookies(name: &str, max_chunks: usize) -> Vec<CookieChunk> {
    (0..max_chunks)
        .map(|i| CookieChunk {
            name: format!("{}.{}", name, i),
            value: String::new(),
        })
        .collect()
}

/// Reassemble chunked cookies from a cookie map.
///
/// Looks for cookies named `{name}.0`, `{name}.1`, etc. and joins them.
pub fn get_chunked_cookie(
    cookies: &std::collections::HashMap<String, String>,
    name: &str,
) -> Option<String> {
    // First check if there's a non-chunked version
    if let Some(value) = cookies.get(name) {
        return Some(value.clone());
    }

    // Try to reconstruct from chunks
    let mut chunks: Vec<(usize, String)> = Vec::new();
    for (cookie_name, value) in cookies {
        if let Some(suffix) = cookie_name.strip_prefix(&format!("{}.", name)) {
            if let Ok(index) = suffix.parse::<usize>() {
                chunks.push((index, value.clone()));
            }
        }
    }

    if chunks.is_empty() {
        return None;
    }

    chunks.sort_by_key(|(idx, _)| *idx);
    Some(chunks.into_iter().map(|(_, v)| v).collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_chunking_needed() {
        let data = "short-value";
        let chunks = chunk_cookie_value("session", data);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].name, "session");
        assert_eq!(chunks[0].value, "short-value");
    }

    #[test]
    fn test_chunking() {
        // Create data larger than MAX_COOKIE_SIZE
        let data = "x".repeat(MAX_COOKIE_SIZE * 2 + 100);
        let chunks = chunk_cookie_value("session_data", &data);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].name, "session_data.0");
        assert_eq!(chunks[1].name, "session_data.1");
        assert_eq!(chunks[2].name, "session_data.2");

        // Verify all data is preserved
        let reassembled: String = chunks.iter().map(|c| c.value.as_str()).collect();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_get_chunked_cookie() {
        let mut cookies = std::collections::HashMap::new();
        cookies.insert("data.0".into(), "chunk0".into());
        cookies.insert("data.1".into(), "chunk1".into());
        cookies.insert("data.2".into(), "chunk2".into());

        let result = get_chunked_cookie(&cookies, "data");
        assert_eq!(result.unwrap(), "chunk0chunk1chunk2");
    }

    #[test]
    fn test_get_non_chunked_cookie() {
        let mut cookies = std::collections::HashMap::new();
        cookies.insert("session".into(), "value123".into());

        let result = get_chunked_cookie(&cookies, "session");
        assert_eq!(result.unwrap(), "value123");
    }

    #[test]
    fn test_get_missing_cookie() {
        let cookies = std::collections::HashMap::new();
        assert!(get_chunked_cookie(&cookies, "missing").is_none());
    }
}
