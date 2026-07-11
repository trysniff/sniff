use super::core_helpers::*;
use super::python_blocks::block_end;
use super::python_refs_helpers::collect_python_refs;
use super::*;
use crate::types::{ExportRecord, MethodRecord, SymbolDefinition, SymbolKind};
use std::collections::HashSet;

#[allow(clippy::too_many_arguments)]
fn build_method_record(
    file_path: &str,
    source: &str,
    line_starts: &[usize],
    name: &str,
    start_line: usize,
    end_line: usize,
    param_count: usize,
    is_exported: bool,
) -> MethodRecord {
    let start_off = line_starts[start_line - 1];
    let end_off = if end_line < line_starts.len() {
        line_starts[end_line]
    } else {
        source.len()
    };
    MethodRecord {
        name: name.to_string(),
        file_path: file_path.to_string(),
        source: source[start_off..end_off].to_string(),
        loc: end_line.saturating_sub(start_line) + 1,
        param_count,
        start_line,
        end_line,
        is_exported,
        language: "python".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    }
}

fn push_method(methods: &mut Vec<MethodRecord>, method: MethodRecord) {
    methods.push(method);
}

pub(super) fn record_python_function(
    extractor: &mut PyExtractor<'_>,
    idx: usize,
    trimmed: &str,
    lines: &[&str],
) -> Option<(String, usize, HashSet<String>)> {
    let name = parse_python_name(trimmed)?;
    let indent = line_indent(lines[idx]);
    let params = parse_python_params(trimmed);
    let end_idx = block_end(lines, idx, indent);
    let start_line = idx + 1;
    let end_line = end_idx + 1;
    let shadowed: HashSet<String> = params.into_iter().collect();
    let shadowed_len = shadowed.len();
    extractor.definitions.push(SymbolDefinition {
        id: extractor.next_id,
        name: name.clone(),
        kind: SymbolKind::Function,
        start_line,
        end_line,
        is_exported: !name.starts_with('_'),
        owner_type: None,
    });
    extractor.next_id += 1;
    let method = build_method_record(
        &extractor.file_path,
        extractor.source,
        &extractor.line_index.line_starts,
        &name,
        start_line,
        end_line,
        shadowed_len,
        !name.starts_with('_'),
    );
    push_method(&mut extractor.methods, method);
    Some((name, end_idx, shadowed))
}

pub(super) fn scan_python_defs_and_imports(
    extractor: &mut PyExtractor<'_>,
) -> Vec<(usize, usize, HashSet<String>, String)> {
    if extractor.scanned {
        return Vec::new();
    }
    extractor.scanned = true;

    let lines: Vec<&str> = extractor.source.lines().collect();
    let mut idx = 0usize;
    let mut spans = Vec::new();
    let mut import_block: Option<String> = None;
    while idx < lines.len() {
        let trimmed = lines[idx].trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            idx += 1;
            continue;
        }

        if let Some(block) = import_block.as_mut() {
            if !block.is_empty() {
                block.push(' ');
            }
            block.push_str(trimmed);
            if trimmed.contains(')') {
                let import_stmt = block.trim().to_string();
                import_block = None;
                if let Some(import_records) = parse_python_namespace_imports(&import_stmt)
                    .or_else(|| parse_python_from_imports(&import_stmt))
                {
                    for import_record in import_records {
                        if import_record.imported_name == "*" {
                            extractor.exports.push(ExportRecord {
                                exported_name: "*".to_string(),
                                local_symbol_name: "*".to_string(),
                                source_module: Some(import_record.source_module.clone()),
                                source_symbol_name: Some("*".to_string()),
                            });
                        } else {
                            extractor.exports.push(ExportRecord {
                                exported_name: import_record.local_name.clone(),
                                local_symbol_name: import_record.local_name.clone(),
                                source_module: Some(import_record.source_module.clone()),
                                source_symbol_name: Some(import_record.imported_name.clone()),
                            });
                        }
                        extractor.imports.push(import_record);
                    }
                }
            }
            idx += 1;
            continue;
        }

        if let Some(import_records) =
            parse_python_namespace_imports(trimmed).or_else(|| parse_python_from_imports(trimmed))
        {
            for import_record in import_records {
                if import_record.imported_name == "*" {
                    extractor.exports.push(ExportRecord {
                        exported_name: "*".to_string(),
                        local_symbol_name: "*".to_string(),
                        source_module: Some(import_record.source_module.clone()),
                        source_symbol_name: Some("*".to_string()),
                    });
                } else {
                    extractor.exports.push(ExportRecord {
                        exported_name: import_record.local_name.clone(),
                        local_symbol_name: import_record.local_name.clone(),
                        source_module: Some(import_record.source_module.clone()),
                        source_symbol_name: Some(import_record.imported_name.clone()),
                    });
                }
                extractor.imports.push(import_record);
            }
            idx += 1;
            continue;
        }

        if trimmed.starts_with("from ") && trimmed.contains(" import (") {
            import_block = Some(trimmed.to_string());
            idx += 1;
            continue;
        }

        if let Some((_name, end_idx, shadowed)) =
            record_python_function(extractor, idx, trimmed, &lines)
        {
            spans.push((idx, end_idx, shadowed, trimmed.to_string()));
            idx = end_idx + 1;
            continue;
        }

        for reference in collect_python_refs(trimmed, &HashSet::new()) {
            extractor.references.push(SymbolReference {
                name: reference,
                line: idx + 1,
                snippet: trimmed.to_string(),
                resolved_symbol: None,
            });
        }

        idx += 1;
    }
    spans
}
