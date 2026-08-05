use crate::types::{FileRecord, Reference};
use std::collections::HashMap;

struct TempRef {
    caller_file_path: String,
    line_num: usize,
    snippet: String,
}

fn get_caller_snippet(
    file: &FileRecord,
    lines: &[&str],
    idx: usize,
    line_num: usize,
) -> (String, usize) {
    if let Some(method) = file
        .methods
        .iter()
        .filter(|m| m.start_line <= line_num && line_num <= m.end_line)
        .min_by_key(|m| {
            (
                m.end_line.saturating_sub(m.start_line),
                usize::MAX - m.start_line,
            )
        })
    {
        let method_start = method.start_line.saturating_sub(1);
        let start = idx.saturating_sub(3).max(method_start);
        let end = idx.saturating_add(7).min(method.end_line).min(lines.len());
        let call_site = lines[start..end]
            .iter()
            .enumerate()
            .map(|(offset, line)| format!("{:>6} | {line}", start + offset + 1))
            .collect::<Vec<_>>()
            .join("\n");
        return (
            format!(
                "Caller Method: {} (lines {}-{})\nCall site at line {}:\n{}",
                method.name, method.start_line, method.end_line, line_num, call_site
            ),
            end,
        );
    }

    let start = idx.saturating_sub(4);
    let end = std::cmp::min(lines.len(), idx + 6);
    (lines[start..end].join("\n"), end)
}

fn resolve_reference_target(
    graph: &crate::symbol_graph::SymbolGraph,
    ref_file_path: &str,
    file_symbols: &crate::types::LocalFileSymbols,
    reference: &crate::types::SymbolReference,
) -> Option<(String, String, usize)> {
    match &reference.resolved_symbol {
        Some(crate::types::ResolvedSymbol::Local(def_id)) => file_symbols
            .definitions
            .iter()
            .find(|d| d.id == *def_id)
            .map(|def| (ref_file_path.to_string(), def.name.clone(), def.start_line)),
        Some(crate::types::ResolvedSymbol::External {
            file_path,
            symbol_name,
            definition_id,
        }) => graph.files.get(file_path).and_then(|ext_symbols| {
            let definitions = &ext_symbols.definitions;
            definition_id
                .and_then(|id| definitions.iter().find(|definition| definition.id == id))
                .or_else(|| {
                    definitions
                        .iter()
                        .find(|definition| definition.name == *symbol_name)
                })
                .map(|def| (file_path.clone(), def.name.clone(), def.start_line))
        }),
        None => None,
    }
}

fn rust_cfg_alternative_targets(
    graph: &crate::symbol_graph::SymbolGraph,
    file_records: &HashMap<String, &FileRecord>,
    primary: &(String, String, usize),
) -> Vec<(String, String, usize)> {
    let (target_file, target_name, target_line) = primary;
    if !target_file.to_ascii_lowercase().ends_with(".rs") {
        return vec![primary.clone()];
    }
    let Some(symbols) = graph.files.get(target_file) else {
        return vec![primary.clone()];
    };
    let Some(primary_definition) = symbols.definitions.iter().find(|definition| {
        definition.name == *target_name && definition.start_line == *target_line
    }) else {
        return vec![primary.clone()];
    };
    let Some(file) = file_records.get(target_file) else {
        return vec![primary.clone()];
    };
    let alternatives = symbols
        .definitions
        .iter()
        .filter(|definition| {
            definition.name == primary_definition.name
                && definition.owner_type == primary_definition.owner_type
                && std::mem::discriminant(&definition.kind)
                    == std::mem::discriminant(&primary_definition.kind)
        })
        .filter_map(|definition| {
            file.methods
                .iter()
                .find(|method| {
                    method.name == definition.name && method.start_line == definition.start_line
                })
                .filter(|method| {
                    method.source.lines().any(|line| {
                        let line = line.trim();
                        line.starts_with("#[cfg(") || line.starts_with("#[cfg_attr(")
                    })
                })
                .map(|_| {
                    (
                        target_file.clone(),
                        definition.name.clone(),
                        definition.start_line,
                    )
                })
        })
        .collect::<Vec<_>>();

    if alternatives.len() > 1 {
        alternatives
    } else {
        vec![primary.clone()]
    }
}

fn go_build_alternative_targets(
    graph: &crate::symbol_graph::SymbolGraph,
    file_records: &HashMap<String, &FileRecord>,
    primary: &(String, String, usize),
) -> Vec<(String, String, usize)> {
    let (target_file, target_name, target_line) = primary;
    if !target_file.to_ascii_lowercase().ends_with(".go") {
        return vec![primary.clone()];
    }
    let Some(primary_symbols) = graph.files.get(target_file) else {
        return vec![primary.clone()];
    };
    let Some(primary_definition) = primary_symbols.definitions.iter().find(|definition| {
        definition.name == *target_name && definition.start_line == *target_line
    }) else {
        return vec![primary.clone()];
    };
    let target_dir = std::path::Path::new(target_file).parent();
    let alternatives = graph
        .files
        .iter()
        .filter(|(file_path, _)| std::path::Path::new(file_path).parent() == target_dir)
        .filter(|(file_path, _)| {
            file_records.get(*file_path).is_some_and(|file| {
                file.source
                    .lines()
                    .take(5)
                    .any(|line| line.trim_start().starts_with("//go:build "))
            })
        })
        .flat_map(|(file_path, symbols)| {
            symbols
                .definitions
                .iter()
                .filter(|definition| {
                    definition.name == primary_definition.name
                        && definition.owner_type == primary_definition.owner_type
                        && std::mem::discriminant(&definition.kind)
                            == std::mem::discriminant(&primary_definition.kind)
                })
                .map(|definition| {
                    (
                        file_path.clone(),
                        definition.name.clone(),
                        definition.start_line,
                    )
                })
        })
        .collect::<Vec<_>>();

    if alternatives.len() > 1 {
        alternatives
    } else {
        vec![primary.clone()]
    }
}

fn collect_refs_for_file(
    collected_refs: &mut HashMap<(String, String, usize), Vec<TempRef>>,
    file_record: &FileRecord,
    file_records: &HashMap<String, &FileRecord>,
    graph: &crate::symbol_graph::SymbolGraph,
    ref_file_path: &str,
    file_symbols: &crate::types::LocalFileSymbols,
) {
    let lines: Vec<&str> = file_record.source.lines().collect();

    file_symbols.references.iter().for_each(|reference| {
        if let Some(target_key) =
            resolve_reference_target(graph, ref_file_path, file_symbols, reference)
        {
            let idx = reference.line.saturating_sub(1);
            let (snippet, _) = get_caller_snippet(file_record, &lines, idx, reference.line);
            for language_target in rust_cfg_alternative_targets(graph, file_records, &target_key) {
                for target_key in
                    go_build_alternative_targets(graph, file_records, &language_target)
                {
                    let entries = collected_refs.entry(target_key).or_default();
                    if entries.iter().any(|existing| {
                        existing
                            .caller_file_path
                            .eq_ignore_ascii_case(ref_file_path)
                            && existing.line_num == reference.line
                    }) {
                        continue;
                    }
                    entries.push(TempRef {
                        caller_file_path: ref_file_path.to_string(),
                        line_num: reference.line,
                        snippet: snippet.clone(),
                    });
                }
            }
        }
    });
}

fn collect_resolved_references(
    file_records: &[FileRecord],
    graph: &crate::symbol_graph::SymbolGraph,
) -> HashMap<(String, String, usize), Vec<TempRef>> {
    let file_map: HashMap<String, &FileRecord> = file_records
        .iter()
        .map(|file| (file.file_path.clone(), file))
        .collect();

    graph.files.iter().fold(
        HashMap::<(String, String, usize), Vec<TempRef>>::new(),
        |mut collected_refs, (ref_file_path, file_symbols)| {
            if let Some(file_record) = file_map.get(ref_file_path) {
                collect_refs_for_file(
                    &mut collected_refs,
                    file_record,
                    &file_map,
                    graph,
                    ref_file_path,
                    file_symbols,
                );
            }
            collected_refs
        },
    )
}

fn apply_reference(method: &mut crate::types::MethodRecord, reference: &TempRef) {
    method.real_ref_count += 1;
    method.references.push(Reference {
        file_path: reference.caller_file_path.clone(),
        line: reference.line_num,
        snippet: reference.snippet.clone(),
    });
}

fn apply_collected_refs(
    file_records: &mut [FileRecord],
    collected_refs: &HashMap<(String, String, usize), Vec<TempRef>>,
) {
    file_records.iter_mut().for_each(|file| {
        file.methods.iter_mut().for_each(|method| {
            let key = (
                method.file_path.clone(),
                method.name.clone(),
                method.start_line,
            );
            if let Some(refs) = collected_refs.get(&key) {
                let method_file_path = method.file_path.clone();
                let method_start_line = method.start_line;
                refs.iter()
                    .filter(|reference| {
                        reference.caller_file_path != method_file_path
                            || reference.line_num != method_start_line
                    })
                    .for_each(|reference| apply_reference(method, reference));
                method.references.sort_by(|left, right| {
                    left.file_path
                        .to_lowercase()
                        .cmp(&right.file_path.to_lowercase())
                        .then(left.line.cmp(&right.line))
                });
                method.real_ref_count = method.references.len();
            }
        });
    });
}

pub(super) fn build_references(
    file_records: &mut [FileRecord],
    graph: &crate::symbol_graph::SymbolGraph,
) {
    let context_records = file_records.to_vec();
    build_references_with_context(file_records, &context_records, graph);
}

pub(super) fn build_references_with_context(
    file_records: &mut [FileRecord],
    context_records: &[FileRecord],
    graph: &crate::symbol_graph::SymbolGraph,
) {
    for file in file_records.iter_mut() {
        for method in &mut file.methods {
            method.references.clear();
            method.real_ref_count = 0;
        }
    }
    let collected_refs = collect_resolved_references(context_records, graph);
    apply_collected_refs(file_records, &collected_refs);
}

pub(super) fn build_callee_context(
    file_records: &[FileRecord],
    graph: &crate::symbol_graph::SymbolGraph,
) -> HashMap<(String, String, usize), Vec<Reference>> {
    let file_map: HashMap<String, &FileRecord> = file_records
        .iter()
        .map(|file| (file.file_path.clone(), file))
        .collect();
    let mut contexts: HashMap<(String, String, usize), Vec<Reference>> = HashMap::new();

    for (file_path, file_symbols) in &graph.files {
        let Some(file_record) = file_map.get(file_path) else {
            continue;
        };

        for reference in &file_symbols.references {
            let Some((target_file, target_name, target_line)) =
                resolve_reference_target(graph, file_path, file_symbols, reference)
            else {
                continue;
            };
            let Some(caller_method) = file_record
                .methods
                .iter()
                .filter(|method| {
                    method.start_line <= reference.line && reference.line <= method.end_line
                })
                .min_by_key(|method| {
                    (
                        method.end_line.saturating_sub(method.start_line),
                        usize::MAX - method.start_line,
                    )
                })
            else {
                continue;
            };
            let Some(target_record) = file_map.get(&target_file) else {
                continue;
            };
            let Some(target_method) = target_record
                .methods
                .iter()
                .find(|method| method.name == target_name && method.start_line == target_line)
            else {
                continue;
            };

            let key = (
                caller_method.file_path.clone(),
                caller_method.name.clone(),
                caller_method.start_line,
            );
            let entries = contexts.entry(key).or_default();
            if entries
                .iter()
                .any(|entry| entry.file_path == target_file && entry.line == target_line)
            {
                continue;
            }
            entries.push(Reference {
                file_path: target_file,
                line: target_line,
                snippet: format!(
                    "Callee Method: {}\n{}",
                    target_method.name, target_method.source
                ),
            });
        }
    }

    contexts
}

#[cfg(test)]
mod tests {
    use super::{build_references, get_caller_snippet};
    use crate::parser::{parse_file, parse_file_symbols};
    use crate::symbol_graph::SymbolGraph;
    use crate::types::{
        FileRecord, LocalFileSymbols, MethodRecord, ResolvedSymbol, SymbolDefinition, SymbolKind,
        SymbolReference,
    };

    #[test]
    fn caller_snippets_bound_large_enclosing_methods_around_the_call_site() {
        let source = (1..=220)
            .map(|line| {
                if line == 150 {
                    "    return normalizeKeywordText(value);".to_string()
                } else {
                    format!("    const value_{line} = {line};")
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let method = MethodRecord {
            name: "runRuntime".to_string(),
            file_path: "src/runtime.ts".to_string(),
            source: source.clone(),
            loc: 220,
            param_count: 0,
            start_line: 1,
            end_line: 220,
            is_exported: true,
            language: "typescript".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        };
        let file = FileRecord {
            file_path: method.file_path.clone(),
            source,
            language: method.language.clone(),
            methods: vec![method],
        };
        let lines = file.source.lines().collect::<Vec<_>>();

        let (snippet, end) = get_caller_snippet(&file, &lines, 149, 150);

        assert!(snippet.contains("Caller Method: runRuntime (lines 1-220)"));
        assert!(snippet.contains("Call site at line 150:"));
        assert!(snippet.contains("150 |     return normalizeKeywordText(value);"));
        assert!(!snippet.contains("const value_1 = 1;"));
        assert!(snippet.len() < 1_000);
        assert_eq!(end, 156);
    }

    #[test]
    fn duplicate_parser_references_count_one_call_site() {
        let target = MethodRecord {
            name: "target".to_string(),
            file_path: "Target.kt".to_string(),
            source: "fun target() = Unit".to_string(),
            loc: 1,
            param_count: 0,
            start_line: 1,
            end_line: 1,
            is_exported: true,
            language: "kotlin".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        };
        let caller = MethodRecord {
            name: "caller".to_string(),
            file_path: "Caller.kt".to_string(),
            source: "fun caller() {\n  target()\n}".to_string(),
            loc: 3,
            param_count: 0,
            start_line: 1,
            end_line: 3,
            is_exported: true,
            language: "kotlin".to_string(),
            nesting_depth: 0,
            references: vec![],
            real_ref_count: 0,
        };
        let mut files = vec![
            FileRecord {
                file_path: target.file_path.clone(),
                source: target.source.clone(),
                language: target.language.clone(),
                methods: vec![target],
            },
            FileRecord {
                file_path: caller.file_path.clone(),
                source: caller.source.clone(),
                language: caller.language.clone(),
                methods: vec![caller],
            },
        ];
        let resolved = ResolvedSymbol::External {
            file_path: "Target.kt".to_string(),
            symbol_name: "target".to_string(),
            definition_id: Some(1),
        };
        let mut graph = SymbolGraph::new(".");
        graph.add_file(LocalFileSymbols {
            file_path: "Target.kt".to_string(),
            definitions: vec![SymbolDefinition {
                id: 1,
                name: "target".to_string(),
                kind: SymbolKind::Function,
                start_line: 1,
                end_line: 1,
                is_exported: true,
                owner_type: None,
                receiver_type: None,
                value_type: None,
            }],
            imports: vec![],
            exports: vec![],
            modules: vec![],
            types: vec![],
            references: vec![],
        });
        graph.add_file(LocalFileSymbols {
            file_path: "Caller.kt".to_string(),
            definitions: vec![],
            imports: vec![],
            exports: vec![],
            modules: vec![],
            types: vec![],
            references: vec![
                SymbolReference {
                    name: "target".to_string(),
                    line: 2,
                    snippet: "target()".to_string(),
                    is_member_call: false,
                    is_callable_value: false,
                    resolved_symbol: Some(resolved.clone()),
                },
                SymbolReference {
                    name: "target".to_string(),
                    line: 2,
                    snippet: "target()".to_string(),
                    is_member_call: false,
                    is_callable_value: false,
                    resolved_symbol: Some(resolved),
                },
            ],
        });

        build_references(&mut files, &graph);

        let target = &files[0].methods[0];
        assert_eq!(target.real_ref_count, 1);
        assert_eq!(target.references.len(), 1);
    }

    #[test]
    fn rust_cfg_alternatives_share_the_runtime_call_site() {
        let root = std::env::temp_dir().join(format!(
            "sniff_cfg_alternatives_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("output.rs");
        std::fs::write(
            &path,
            r#"fn print_entry() {
    print_entry_uncolorized();
}

#[cfg(unix)]
fn print_entry_uncolorized() {}

#[cfg(not(unix))]
fn print_entry_uncolorized() {}
"#,
        )
        .unwrap();
        let path = path.to_string_lossy().to_string();
        let mut files = vec![parse_file(&path)];
        let mut graph = SymbolGraph::new(&root.to_string_lossy());
        graph.add_file(parse_file_symbols(&path));
        graph.resolve_all();

        build_references(&mut files, &graph);

        let alternatives = files[0]
            .methods
            .iter()
            .filter(|method| method.name == "print_entry_uncolorized")
            .collect::<Vec<_>>();
        assert_eq!(alternatives.len(), 2);
        assert!(alternatives.iter().all(|method| method.real_ref_count == 1));
        std::fs::remove_dir_all(root).ok();
    }
}
