use super::super::python_refs_helpers as refs_helpers;
use super::*;
use std::collections::HashSet;

pub(crate) struct PythonSpan {
    pub start: usize,
    pub end: usize,
    pub shadowed: HashSet<String>,
}

pub(super) fn scan_python_references(extractor: &mut PyExtractor<'_>, spans: &[PythonSpan]) {
    let lines: Vec<&str> = extractor.source.lines().collect();
    let imported_names = extractor
        .imports
        .iter()
        .map(|import| import.local_name.clone())
        .collect::<HashSet<_>>();
    for span in spans {
        for (offset, body_line) in lines[span.start..=span.end].iter().enumerate() {
            let trimmed_body = body_line.trim();
            if trimmed_body.starts_with("def ") {
                continue;
            }
            let line_no = span.start + offset + 1;
            for reference in
                refs_helpers::collect_python_refs(trimmed_body, &span.shadowed, &imported_names)
            {
                let name = scope_qualified_reference(extractor, &reference.name, line_no);
                extractor.references.push(SymbolReference {
                    name,
                    line: line_no,
                    snippet: trimmed_body.to_string(),
                    is_member_call: reference.is_member_call,
                    is_callable_value: false,
                    resolved_symbol: None,
                });
            }
        }
    }
}

fn scope_qualified_reference(extractor: &PyExtractor<'_>, name: &str, line: usize) -> String {
    let (head, tail) = name
        .split_once('.')
        .map_or((name, None), |(head, tail)| (head, Some(tail)));
    let Some(import) = extractor
        .scoped_imports
        .iter()
        .filter(|import| {
            import.local_name == head && import.start_line <= line && line <= import.end_line
        })
        .min_by_key(|import| import.end_line.saturating_sub(import.start_line))
    else {
        return name.to_string();
    };
    tail.map_or_else(
        || import.scoped_name.clone(),
        |tail| format!("{}.{}", import.scoped_name, tail),
    )
}
