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
        .find(|m| m.start_line <= line_num && line_num <= m.end_line)
    {
        return (
            format!("Caller Method: {}\n{}", method.name, method.source),
            method.end_line,
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
        }) => graph.files.get(file_path).and_then(|ext_symbols| {
            ext_symbols
                .definitions
                .iter()
                .find(|d| d.name == *symbol_name)
                .map(|def| (file_path.clone(), def.name.clone(), def.start_line))
        }),
        None => None,
    }
}

fn collect_refs_for_file(
    collected_refs: &mut HashMap<(String, String, usize), Vec<TempRef>>,
    file_record: &FileRecord,
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
            collected_refs.entry(target_key).or_default().push(TempRef {
                caller_file_path: ref_file_path.to_string(),
                line_num: reference.line,
                snippet,
            });
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
    if method.references.len() < 10 {
        method.references.push(Reference {
            file_path: reference.caller_file_path.clone(),
            line: reference.line_num,
            snippet: reference.snippet.clone(),
        });
    }
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
            }
        });
    });
}

pub(super) fn build_references(
    file_records: &mut [FileRecord],
    graph: &crate::symbol_graph::SymbolGraph,
) {
    let collected_refs = collect_resolved_references(file_records, graph);
    apply_collected_refs(file_records, &collected_refs);
}
