pub(super) fn count_params(param_text: &str) -> usize {
    let trimmed = param_text.trim();
    if trimmed.is_empty() {
        return 0;
    }
    trimmed
        .split(',')
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .count()
}

pub(super) fn parse_export_function(line: &str) -> Option<(String, bool, bool)> {
    let trimmed = line.trim();
    if trimmed.starts_with("export default function ") {
        let rest = trimmed.trim_start_matches("export default function ");
        let name = rest.split(['(', ' ', '{']).next()?.trim();
        return Some((name.to_string(), true, true));
    }
    if trimmed.starts_with("export function ") {
        let rest = trimmed.trim_start_matches("export function ");
        let name = rest.split(['(', ' ', '{']).next()?.trim();
        return Some((name.to_string(), true, false));
    }
    if trimmed.starts_with("function ") {
        let rest = trimmed.trim_start_matches("function ");
        let name = rest.split(['(', ' ', '{']).next()?.trim();
        return Some((name.to_string(), false, false));
    }
    None
}

pub(super) fn parse_arrow_function(line: &str) -> Option<(String, usize)> {
    let trimmed = line.trim();
    let eq_idx = trimmed.find("=>")?;
    let left = trimmed[..eq_idx].trim();
    if !left.contains("const ") && !left.contains("let ") && !left.contains("var ") {
        return None;
    }
    if !left.contains('=') {
        return None;
    }

    let rhs = left.split_once('=')?.1.trim();
    let rhs = if let Some(rest) = rhs.strip_prefix("async ") {
        rest.trim_start()
    } else {
        rhs
    };

    if let Some(rest) = rhs.strip_prefix('<') {
        let (_, after_generic) = rest.split_once('>')?;
        let after_generic = after_generic.trim_start();
        if !after_generic.starts_with('(') {
            return None;
        }
        if !after_generic.contains(')') {
            return None;
        }
    } else {
        if rhs.contains('(') && !rhs.starts_with('(') {
            return None;
        }
        if rhs.starts_with('(') && !rhs.contains(')') {
            return None;
        }
    }

    let name_part = left.split('=').next()?.split_whitespace().last()?.trim();
    if name_part.is_empty() {
        return None;
    }

    let params = left
        .split_once('(')
        .and_then(|(_, rest)| rest.rsplit_once(')').map(|(inside, _)| inside))
        .unwrap_or("");
    Some((name_part.to_string(), count_params(params)))
}
