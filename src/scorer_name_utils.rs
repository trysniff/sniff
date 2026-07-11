fn normalize_name(name: &str) -> String {
    let mut result = String::new();
    let chars: Vec<char> = name.chars().collect();
    for i in 0..chars.len() {
        let c = chars[i];
        if i > 0 {
            let prev = chars[i - 1];
            let is_next_lower = i + 1 < chars.len() && chars[i + 1].is_lowercase();
            let is_prev_lower_or_digit = prev.is_lowercase() || prev.is_ascii_digit();

            if (c.is_uppercase() && is_next_lower && prev != '_')
                || (is_prev_lower_or_digit && c.is_uppercase())
            {
                result.push('_');
            }
        }
        result.push(c.to_ascii_lowercase());
    }
    result
}

fn match_pattern(name: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        return name.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return name.ends_with(suffix);
    }
    name == pattern
}

fn token_count(name: &str) -> usize {
    name.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .count()
}

pub(super) fn is_generic(
    method_name: &str,
    config: &crate::config::ResolvedConfig,
    adapter: &crate::language_adapter::LanguageAdapter,
) -> bool {
    let norm_name = normalize_name(method_name);

    for pat in &adapter.allowed_names {
        if match_pattern(&norm_name, &normalize_name(pat)) {
            return false;
        }
    }

    let tokens = token_count(&norm_name);

    for pat in &config.generic_names {
        if match_pattern(&norm_name, &normalize_name(pat)) && tokens <= 2 {
            return true;
        }
    }

    for pat in &adapter.generic_names {
        if match_pattern(&norm_name, &normalize_name(pat)) && tokens <= 2 {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::is_generic;
    use crate::config::ResolvedConfig;
    use crate::language_adapter::{ExportDetection, LanguageAdapter};

    fn adapter() -> LanguageAdapter {
        LanguageAdapter {
            name: "python".to_string(),
            grammar_package: "tree-sitter-python".to_string(),
            extensions: vec![".py".to_string()],
            function_node_types: vec![],
            excluded_parent_types: vec![],
            name_field: "name".to_string(),
            params_field: "parameters".to_string(),
            param_node_types: vec![],
            nesting_node_types: vec![],
            export_detection: ExportDetection::Convention,
            generic_names: vec![
                "handle*".to_string(),
                "process*".to_string(),
                "get*".to_string(),
            ],
            allowed_names: vec![],
        }
    }

    #[test]
    fn long_descriptive_names_are_not_marked_generic() {
        let config = ResolvedConfig::default();
        let adapter = adapter();

        assert!(!is_generic("process_release_command", &config, &adapter));
        assert!(!is_generic("handle_github_webhook", &config, &adapter));
        assert!(!is_generic("get_pull_request", &config, &adapter));
    }

    #[test]
    fn short_greedy_names_are_still_generic() {
        let config = ResolvedConfig::default();
        let adapter = adapter();

        assert!(is_generic("get", &config, &adapter));
        assert!(is_generic("data", &config, &adapter));
        assert!(is_generic("process_data", &config, &adapter));
    }
}
