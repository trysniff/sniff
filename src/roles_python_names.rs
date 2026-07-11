pub fn is_python_identifier_like(text: &str) -> bool {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) if first == '_' || first.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

pub fn is_python_alias_export_assignment(trimmed: &str) -> bool {
    let Some((lhs, rhs)) = trimmed.split_once('=') else {
        return false;
    };
    if trimmed.contains("==") || trimmed.contains("!=") {
        return false;
    }
    let lhs = lhs.trim();
    let rhs = rhs.trim().trim_end_matches(',').trim();
    let target = lhs
        .split_once(':')
        .map(|(name, _)| name)
        .unwrap_or(lhs)
        .trim();
    if !is_python_identifier_like(target) || rhs.is_empty() {
        return false;
    }
    if rhs.contains('(')
        || rhs.contains(')')
        || rhs.contains('[')
        || rhs.contains(']')
        || rhs.contains('{')
        || rhs.contains('}')
    {
        return false;
    }
    let mut saw_dot = false;
    for part in rhs.split('.') {
        if part.is_empty() || !is_python_identifier_like(part) {
            return false;
        }
        saw_dot = saw_dot || rhs.contains('.');
    }
    saw_dot || is_python_identifier_like(rhs)
}
