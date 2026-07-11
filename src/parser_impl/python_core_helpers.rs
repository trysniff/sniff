#![allow(dead_code)]

use super::*;

pub(super) fn line_indent(line: &str) -> usize {
    line.chars().take_while(|c| c.is_whitespace()).count()
}

pub(super) fn parse_python_name(trimmed: &str) -> Option<String> {
    trimmed
        .strip_prefix("def ")?
        .split_once('(')
        .map(|(name, _)| name.trim().to_string())
}

pub(super) fn parse_python_params(trimmed: &str) -> Vec<String> {
    let inside = trimmed
        .split_once('(')
        .and_then(|(_, rest)| rest.split_once(')').map(|(inside, _)| inside))
        .unwrap_or("");
    inside
        .split(',')
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.split_once(':')
                .map(|(name, _)| name.trim())
                .unwrap_or(part)
                .split_once('=')
                .map(|(name, _)| name.trim())
                .unwrap_or(part)
                .trim_start_matches('*')
                .trim()
                .to_string()
        })
        .filter(|name| !name.is_empty())
        .collect()
}

pub(super) fn parse_python_from_imports(trimmed: &str) -> Option<Vec<ImportRecord>> {
    let rest = trimmed.strip_prefix("from ")?;
    let (source_module, import_part) = rest.split_once(" import ")?;
    let source_module = source_module.trim().to_string();
    let import_part = import_part
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim();
    let mut records = Vec::new();

    for imported in import_part.split(',') {
        let imported = imported.trim();
        if imported.is_empty() {
            continue;
        }

        if imported == "*" {
            records.push(ImportRecord {
                local_name: "*".to_string(),
                source_module: source_module.clone(),
                imported_name: "*".to_string(),
            });
            continue;
        }

        let (imported_name, local_name) =
            if let Some((source_name, alias_name)) = imported.split_once(" as ") {
                (source_name.trim(), alias_name.trim())
            } else {
                let name = imported.split_whitespace().last()?;
                (name.trim(), name.trim())
            };

        if imported_name.is_empty() || local_name.is_empty() {
            continue;
        }

        records.push(ImportRecord {
            local_name: local_name.to_string(),
            source_module: source_module.clone(),
            imported_name: imported_name.to_string(),
        });
    }

    if records.is_empty() {
        None
    } else {
        Some(records)
    }
}

pub(super) fn parse_python_namespace_imports(trimmed: &str) -> Option<Vec<ImportRecord>> {
    let rest = trimmed.strip_prefix("import ")?;
    let mut records = Vec::new();

    for imported in rest.split(',') {
        let imported = imported.trim().trim_end_matches(';');
        if imported.is_empty() {
            continue;
        }

        let (module_path, local_name) =
            if let Some((module_path, alias_name)) = imported.split_once(" as ") {
                let module_path = module_path.trim();
                let alias_name = alias_name.trim();
                if module_path.is_empty() || alias_name.is_empty() {
                    continue;
                }
                (module_path, alias_name)
            } else {
                let module_path = imported.trim();
                let local_name = module_path.split('.').next().unwrap_or(module_path).trim();
                if module_path.is_empty() || local_name.is_empty() {
                    continue;
                }
                (module_path, local_name)
            };

        records.push(ImportRecord {
            local_name: local_name.to_string(),
            source_module: module_path.to_string(),
            imported_name: "*".to_string(),
        });
    }

    if records.is_empty() {
        None
    } else {
        Some(records)
    }
}
