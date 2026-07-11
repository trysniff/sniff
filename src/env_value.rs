use std::env;

pub(crate) fn normalize(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.len() >= 2 {
        let bytes = trimmed.as_bytes();
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return trimmed[1..trimmed.len() - 1].trim().to_string();
        }
    }
    trimmed.to_string()
}

pub(crate) fn read(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| normalize(&value))
        .filter(|value| !value.is_empty())
}
