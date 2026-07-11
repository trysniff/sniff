use super::*;
use crate::types::Reference;
use tree_sitter::Node;

fn method_source(lines: &[&str], start: usize, end: usize) -> String {
    lines[start..=end].join("\n")
}

#[allow(clippy::too_many_arguments)]
fn push_method(
    methods: &mut Vec<MethodRecord>,
    file_path: &str,
    name: &str,
    start: usize,
    end: usize,
    param_count: usize,
    is_exported: bool,
    source: String,
    refs: Vec<String>,
) {
    methods.push(MethodRecord {
        name: name.to_string(),
        file_path: file_path.to_string(),
        source,
        loc: end.saturating_sub(start) + 1,
        param_count,
        start_line: start + 1,
        end_line: end + 1,
        is_exported,
        language: "go".to_string(),
        nesting_depth: 0,
        references: refs
            .into_iter()
            .map(|name| Reference {
                file_path: file_path.to_string(),
                line: start + 1,
                snippet: name,
            })
            .collect(),
        real_ref_count: 0,
    });
}

pub(crate) fn extract_methods(
    _root: Node,
    source_bytes: &[u8],
    adapter: &LanguageAdapter,
    file_path: &str,
) -> Vec<MethodRecord> {
    let source = String::from_utf8_lossy(source_bytes);
    let lines: Vec<&str> = source.lines().collect();
    let mut methods = Vec::new();
    let mut i = 0usize;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if let Some((recv, name, param_count)) = defs::parse_func_name(trimmed) {
            let end = super::shared::scan_block_end(&lines, i);
            let refs = lines[i..=end]
                .iter()
                .flat_map(|line| super::refs::collect_refs(line))
                .filter(|r| r != &name)
                .collect::<Vec<_>>();
            push_method(
                &mut methods,
                file_path,
                &name,
                i,
                end,
                param_count,
                name.chars()
                    .next()
                    .map(|c| c.is_uppercase())
                    .unwrap_or(false),
                method_source(&lines, i, end),
                refs,
            );
            let _ = recv;
            i = end + 1;
            continue;
        }
        i += 1;
    }
    let _ = adapter;
    methods
}
