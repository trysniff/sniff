fn is_assignment_comparison(trimmed: &str) -> bool {
    trimmed.contains("==")
        || trimmed.contains("!=")
        || trimmed.contains(">=")
        || trimmed.contains("<=")
}

fn is_assignment_name_like(text: &str) -> bool {
    text.chars()
        .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_' || ch == '.')
}

fn is_assignment_rhs_alias(rhs: &str) -> bool {
    let rhs_lower = rhs.to_lowercase();
    rhs_lower.starts_with("_")
        || rhs_lower.contains(".")
        || rhs_lower.contains(" as ")
        || rhs_lower.ends_with(")")
        || rhs_lower.ends_with("}")
        || rhs_lower.ends_with("]")
}

pub fn is_wrapper_assignment(trimmed: &str) -> bool {
    let Some((lhs_raw, rhs_raw)) = trimmed.split_once('=') else {
        return false;
    };

    if is_assignment_comparison(trimmed) {
        return false;
    }

    let lhs = lhs_raw.trim();
    let rhs = rhs_raw.trim().trim_end_matches(',');
    if lhs.is_empty() || rhs.is_empty() {
        return false;
    }

    if lhs.starts_with("__all__") {
        return true;
    }

    if rhs.contains('(') {
        return false;
    }

    let rhs_is_alias = is_assignment_rhs_alias(rhs);
    let rhs_is_const = is_assignment_name_like(rhs);
    let lhs_is_const = is_assignment_name_like(lhs);

    lhs_is_const || rhs_is_alias || rhs_is_const
}
