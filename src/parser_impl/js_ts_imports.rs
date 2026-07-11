use super::*;

pub(super) fn strip_quotes(value: &str) -> &str {
    value.trim().trim_matches('"').trim_matches('\'')
}

pub(super) fn parse_named_bindings(binding_text: &str) -> Vec<(String, String)> {
    let inner = binding_text
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .trim();

    if inner.is_empty() {
        return Vec::new();
    }

    inner
        .split(',')
        .filter_map(|part| {
            let spec = part.trim();
            if spec.is_empty() {
                return None;
            }

            let (source_name, local_name) =
                if let Some((source_name, alias_name)) = spec.split_once(" as ") {
                    (source_name.trim(), alias_name.trim())
                } else {
                    (spec, spec)
                };

            if source_name.is_empty() || local_name.is_empty() {
                return None;
            }

            Some((source_name.to_string(), local_name.to_string()))
        })
        .collect()
}

pub(super) fn parse_import(line: &str) -> Option<Vec<ImportRecord>> {
    let trimmed = line.trim().trim_end_matches(';');
    if !trimmed.starts_with("import ") || !trimmed.contains(" from ") {
        return None;
    }

    let mut parts = trimmed[7..].splitn(2, " from ");
    let spec = parts.next()?.trim();
    let source = strip_quotes(parts.next()?);
    let mut records = Vec::new();

    let mut remaining = spec;
    if let Some((default_part, named_part)) = spec.split_once(',') {
        let default_part = default_part.trim();
        if !default_part.starts_with('{') && !default_part.starts_with('*') {
            if !default_part.is_empty() {
                records.push(ImportRecord {
                    local_name: default_part.to_string(),
                    source_module: source.to_string(),
                    imported_name: "default".to_string(),
                });
            }
            remaining = named_part.trim();
        }
    }

    if remaining.starts_with("* as ") {
        let local_name = remaining.trim_start_matches("* as ").trim();
        if !local_name.is_empty() {
            records.push(ImportRecord {
                local_name: local_name.to_string(),
                source_module: source.to_string(),
                imported_name: "*".to_string(),
            });
        }
    } else if remaining.starts_with('{') {
        for (imported_name, local_name) in parse_named_bindings(remaining) {
            records.push(ImportRecord {
                local_name,
                source_module: source.to_string(),
                imported_name,
            });
        }
    } else if records.is_empty() {
        let local_name = remaining.trim();
        if !local_name.is_empty() {
            records.push(ImportRecord {
                local_name: local_name.to_string(),
                source_module: source.to_string(),
                imported_name: "default".to_string(),
            });
        }
    }

    if records.is_empty() {
        None
    } else {
        Some(records)
    }
}

pub(super) fn parse_export_from(line: &str) -> Option<Vec<ExportRecord>> {
    let trimmed = line.trim().trim_end_matches(';');
    if !trimmed.starts_with("export ") || !trimmed.contains(" from ") {
        return None;
    }

    let mut parts = trimmed[7..].splitn(2, " from ");
    let spec = parts.next()?.trim();
    let source = strip_quotes(parts.next()?);

    if spec == "*" {
        return Some(vec![ExportRecord {
            exported_name: "*".to_string(),
            local_symbol_name: "*".to_string(),
            source_module: Some(source.to_string()),
            source_symbol_name: Some("*".to_string()),
        }]);
    }

    if let Some(rest) = spec.strip_prefix("* as ") {
        let exported_name = rest.trim();
        if exported_name.is_empty() {
            return None;
        }
        return Some(vec![ExportRecord {
            exported_name: exported_name.to_string(),
            local_symbol_name: exported_name.to_string(),
            source_module: Some(source.to_string()),
            source_symbol_name: Some("*".to_string()),
        }]);
    }

    if !spec.starts_with('{') {
        return None;
    }

    let exports = parse_named_bindings(spec)
        .into_iter()
        .map(|(source_symbol_name, exported_name)| ExportRecord {
            exported_name: exported_name.clone(),
            local_symbol_name: exported_name,
            source_module: Some(source.to_string()),
            source_symbol_name: Some(source_symbol_name),
        })
        .collect();
    Some(exports)
}
