pub fn normalize_path(p: &str) -> String {
    let mut normalized = p.replace('\\', "/");
    if normalized.starts_with("//?/") || normalized.starts_with("\\\\?\\") {
        normalized = normalized[4..].to_string();
    }
    if normalized.starts_with("./") {
        normalized = normalized[2..].to_string();
    }
    while normalized.contains("/./") {
        normalized = normalized.replace("/./", "/");
    }
    if normalized.ends_with("/.") {
        normalized.truncate(normalized.len().saturating_sub(2));
    }
    normalized
}
