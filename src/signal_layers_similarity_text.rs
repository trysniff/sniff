use crate::roles::FileRole;
use crate::types::MethodRecord;
use std::collections::HashSet;

use super::super::similarity_roles::is_comparable_method;

pub(crate) fn shingles(tokens: &[String], size: usize) -> HashSet<String> {
    let mut set = HashSet::new();
    if tokens.is_empty() {
        return set;
    }
    if tokens.len() <= size {
        set.insert(tokens.join(" "));
        return set;
    }
    for window in tokens.windows(size) {
        set.insert(window.join(" "));
    }
    set
}

pub(crate) fn similarity(a: &HashSet<String>, b: &HashSet<String>) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let intersection = a.intersection(b).count() as f64;
    let union = a.union(b).count() as f64;
    if union == 0.0 {
        0.0
    } else {
        intersection / union
    }
}

pub(crate) fn similarity_for_pair(
    current_normalized: &str,
    current_shingles: &HashSet<String>,
    current_language: &str,
    other: &MethodRecord,
    other_role: FileRole,
    other_normalized: &str,
    other_shingles: &HashSet<String>,
) -> Option<(f64, bool)> {
    if current_language != other.language || !is_comparable_method(other, other_role) {
        return None;
    }

    let exact = current_normalized == other_normalized;
    let sim = if exact {
        1.0
    } else {
        similarity(current_shingles, other_shingles)
    };
    Some((sim, exact))
}
