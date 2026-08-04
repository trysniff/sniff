use super::core_helpers::*;
use super::python_blocks::block_end;
use super::python_refs_helpers::collect_python_refs;
use super::*;
use crate::types::{ExportRecord, ImportRecord, MethodRecord, SymbolDefinition, SymbolKind};
use rustpython_ast::{Constant, Expr, Operator, Stmt};
use std::collections::HashSet;

fn static_export_names(expr: &Expr) -> Option<HashSet<String>> {
    let elements = match expr {
        Expr::List(list) => &list.elts,
        Expr::Tuple(tuple) => &tuple.elts,
        Expr::BinOp(binary) if binary.op == Operator::Add => {
            let mut names = static_export_names(&binary.left)?;
            names.extend(static_export_names(&binary.right)?);
            return Some(names);
        }
        _ => return None,
    };

    elements
        .iter()
        .map(|element| match element {
            Expr::Constant(value) => match &value.value {
                Constant::Str(name) => Some(name.clone()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

fn is_all_name(expr: &Expr) -> bool {
    matches!(expr, Expr::Name(name) if name.id.as_str() == "__all__")
}

fn apply_python_explicit_exports(extractor: &mut PyExtractor<'_>) {
    let Some(names) = extractor.explicit_exports.as_ref() else {
        return;
    };

    for definition in &mut extractor.definitions {
        if definition.owner_type.is_none() {
            definition.is_exported = names.contains(&definition.name);
        }
    }
    for method in &mut extractor.methods {
        let is_top_level = extractor.definitions.iter().any(|definition| {
            definition.owner_type.is_none()
                && definition.name == method.name
                && definition.start_line == method.start_line
        });
        if is_top_level {
            method.is_exported = names.contains(&method.name);
        }
    }

    extractor
        .exports
        .retain(|export| names.contains(&export.exported_name));
    for name in names {
        if extractor
            .exports
            .iter()
            .any(|export| export.exported_name == *name)
        {
            continue;
        }
        let imported = extractor
            .imports
            .iter()
            .find(|import| import.local_name == *name);
        extractor.exports.push(ExportRecord {
            exported_name: name.clone(),
            local_symbol_name: name.clone(),
            source_module: imported.map(|import| import.source_module.clone()),
            source_symbol_name: imported.map(|import| import.imported_name.clone()),
        });
    }
}

pub(super) fn record_python_explicit_exports(extractor: &mut PyExtractor<'_>, stmt: &Stmt) {
    match stmt {
        Stmt::Assign(assign) if assign.targets.iter().any(is_all_name) => {
            if let Some(names) = static_export_names(&assign.value) {
                extractor.explicit_exports = Some(names);
                apply_python_explicit_exports(extractor);
            }
        }
        Stmt::AnnAssign(assign) if is_all_name(&assign.target) => {
            if let Some(value) = assign.value.as_deref()
                && let Some(names) = static_export_names(value)
            {
                extractor.explicit_exports = Some(names);
                apply_python_explicit_exports(extractor);
            }
        }
        Stmt::AugAssign(assign) if assign.op == Operator::Add && is_all_name(&assign.target) => {
            if let Some(names) = static_export_names(&assign.value) {
                extractor
                    .explicit_exports
                    .get_or_insert_with(HashSet::new)
                    .extend(names);
                apply_python_explicit_exports(extractor);
            }
        }
        _ => {}
    }
}

fn python_attribute_path(expr: &Expr) -> Option<Vec<String>> {
    match expr {
        Expr::Name(name) => Some(vec![name.id.to_string()]),
        Expr::Attribute(attribute) => {
            let mut path = python_attribute_path(&attribute.value)?;
            path.push(attribute.attr.to_string());
            Some(path)
        }
        _ => None,
    }
}

fn python_assignment_alias(stmt: &Stmt) -> Option<(String, Vec<String>)> {
    let (target, value) = match stmt {
        Stmt::Assign(assign) if assign.targets.len() == 1 => {
            (assign.targets.first()?, assign.value.as_ref())
        }
        Stmt::AnnAssign(assign) => (assign.target.as_ref(), assign.value.as_deref()?),
        _ => return None,
    };
    let Expr::Name(target) = target else {
        return None;
    };
    let path = python_attribute_path(value)?;
    (path.len() >= 2).then(|| (target.id.to_string(), path))
}

pub(super) fn record_python_assignment_alias(extractor: &mut PyExtractor<'_>, stmt: &Stmt) {
    let Some((local_name, path)) = python_assignment_alias(stmt) else {
        return;
    };
    if extractor
        .imports
        .iter()
        .any(|import| import.local_name == local_name)
    {
        return;
    }
    let Some(base_import) = extractor
        .imports
        .iter()
        .find(|import| import.local_name == path[0])
        .cloned()
    else {
        return;
    };

    let mut source_parts = vec![base_import.source_module];
    if base_import.imported_name != "*" {
        source_parts.push(base_import.imported_name);
    }
    source_parts.extend(path[1..path.len() - 1].iter().cloned());
    record_python_imports(
        extractor,
        vec![ImportRecord {
            local_name,
            source_module: source_parts
                .into_iter()
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join("."),
            imported_name: path.last().cloned().unwrap_or_default(),
        }],
    );
}

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

fn record_python_imports(extractor: &mut PyExtractor<'_>, import_records: Vec<ImportRecord>) {
    for import_record in import_records {
        let is_wildcard = import_record.imported_name == "*";
        extractor.exports.push(ExportRecord {
            exported_name: if is_wildcard {
                "*".to_string()
            } else {
                import_record.local_name.clone()
            },
            local_symbol_name: if is_wildcard {
                "*".to_string()
            } else {
                import_record.local_name.clone()
            },
            source_module: Some(import_record.source_module.clone()),
            source_symbol_name: Some(if is_wildcard {
                "*".to_string()
            } else {
                import_record.imported_name.clone()
            }),
        });
        extractor.imports.push(import_record);
    }
}

fn record_scoped_python_imports(
    extractor: &mut PyExtractor<'_>,
    import_records: Vec<ImportRecord>,
    start_line: usize,
    end_line: usize,
) {
    for mut import_record in import_records {
        let local_name = import_record.local_name.clone();
        let scoped_name = format!("__sniff_scope_{start_line}_{local_name}");
        import_record.local_name = scoped_name.clone();
        extractor.scoped_imports.push(ScopedPythonImport {
            local_name,
            scoped_name,
            start_line,
            end_line,
        });
        extractor.imports.push(import_record);
    }
}

fn record_function_local_imports(
    extractor: &mut PyExtractor<'_>,
    lines: &[&str],
    start_idx: usize,
    end_idx: usize,
) {
    let mut idx = start_idx + 1;
    let mut import_block: Option<String> = None;
    while idx <= end_idx {
        let trimmed = lines[idx].trim();
        if let Some(block) = import_block.as_mut() {
            if !block.is_empty() {
                block.push(' ');
            }
            block.push_str(trimmed);
            if trimmed.contains(')') {
                let import_stmt = block.trim().to_string();
                import_block = None;
                if let Some(records) = parse_python_namespace_imports(&import_stmt)
                    .or_else(|| parse_python_from_imports(&import_stmt))
                {
                    record_scoped_python_imports(extractor, records, start_idx + 1, end_idx + 1);
                }
            }
            idx += 1;
            continue;
        }
        if let Some(records) =
            parse_python_namespace_imports(trimmed).or_else(|| parse_python_from_imports(trimmed))
        {
            record_scoped_python_imports(extractor, records, start_idx + 1, end_idx + 1);
        } else if trimmed.starts_with("from ") && trimmed.contains(" import (") {
            import_block = Some(trimmed.to_string());
        }
        idx += 1;
    }
}

fn python_class_record(trimmed: &str) -> Option<TypeRecord> {
    let rest = trimmed.strip_prefix("class ")?;
    let name = rest.split(['(', ':']).next()?.trim().to_string();
    let bases = rest
        .split_once('(')
        .and_then(|(_, bases)| bases.split_once(')').map(|(bases, _)| bases))
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|base| !base.is_empty())
        .map(|base| base.rsplit('.').next().unwrap_or(base).to_string())
        .collect();
    Some(TypeRecord { name, bases })
}

pub(super) fn record_python_function(
    extractor: &mut PyExtractor<'_>,
    idx: usize,
    trimmed: &str,
    lines: &[&str],
    owner_type: Option<String>,
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
        kind: if owner_type.is_some() {
            SymbolKind::Method
        } else {
            SymbolKind::Function
        },
        start_line,
        end_line,
        is_exported: !name.starts_with('_'),
        owner_type,
        receiver_type: None,
        value_type: None,
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
) -> Vec<(usize, usize, HashSet<String>)> {
    if extractor.scanned {
        return Vec::new();
    }
    extractor.scanned = true;

    let lines: Vec<&str> = extractor.source.lines().collect();
    let mut idx = 0usize;
    let mut spans = Vec::new();
    let mut class_ranges = Vec::<(usize, usize, String)>::new();
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
                    record_python_imports(extractor, import_records);
                }
            }
            idx += 1;
            continue;
        }

        if let Some(import_records) =
            parse_python_namespace_imports(trimmed).or_else(|| parse_python_from_imports(trimmed))
        {
            record_python_imports(extractor, import_records);
            idx += 1;
            continue;
        }

        if trimmed.starts_with("from ") && trimmed.contains(" import (") {
            import_block = Some(trimmed.to_string());
            idx += 1;
            continue;
        }

        if let Some(class_record) = python_class_record(trimmed) {
            let indent = line_indent(lines[idx]);
            class_ranges.push((
                idx,
                block_end(&lines, idx, indent),
                class_record.name.clone(),
            ));
            extractor.types.push(class_record);
            idx += 1;
            continue;
        }

        let owner_type = class_ranges
            .iter()
            .filter(|(start, end, _)| *start < idx && idx <= *end)
            .min_by_key(|(start, end, _)| end.saturating_sub(*start))
            .map(|(_, _, name)| name.clone());
        if let Some((_name, end_idx, shadowed)) =
            record_python_function(extractor, idx, trimmed, &lines, owner_type)
        {
            record_function_local_imports(extractor, &lines, idx, end_idx);
            spans.push((idx, end_idx, shadowed));
            idx = end_idx + 1;
            continue;
        }

        let imported_names = extractor
            .imports
            .iter()
            .map(|import| import.local_name.clone())
            .collect::<HashSet<_>>();
        for reference in collect_python_refs(trimmed, &HashSet::new(), &imported_names) {
            extractor.references.push(SymbolReference {
                name: reference.name,
                line: idx + 1,
                snippet: trimmed.to_string(),
                is_member_call: reference.is_member_call,
                is_callable_value: false,
                resolved_symbol: None,
            });
        }

        idx += 1;
    }
    spans
}
