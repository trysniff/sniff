use super::super::python_refs_helpers as refs_helpers;
use super::*;
use std::collections::HashSet;

pub(crate) struct PythonSpan {
    pub start: usize,
    pub end: usize,
    pub shadowed: HashSet<String>,
    pub header: String,
}

pub(super) fn scan_python_references(extractor: &mut PyExtractor<'_>, spans: &[PythonSpan]) {
    let lines: Vec<&str> = extractor.source.lines().collect();
    for span in spans {
        for (offset, body_line) in lines[span.start..=span.end].iter().enumerate() {
            let trimmed_body = body_line.trim();
            if trimmed_body.starts_with("def ") {
                continue;
            }
            let line_no = span.start + offset + 1;
            for r in refs_helpers::collect_python_refs(trimmed_body, &span.shadowed) {
                extractor.references.push(SymbolReference {
                    name: r,
                    line: line_no,
                    snippet: trimmed_body.to_string(),
                    resolved_symbol: None,
                });
            }
        }
        let _ = &span.header;
    }
}
