use super::*;

pub(super) fn push_rust_reference(
    extractor: &mut RustExtractor<'_>,
    line: usize,
    snippet: &str,
    name: String,
) {
    extractor.references.push(SymbolReference {
        name,
        line,
        snippet: snippet.to_string(),
        resolved_symbol: None,
    });
}

fn collect_rust_line_refs(
    extractor: &mut RustExtractor<'_>,
    line_no: usize,
    body_line: &str,
    name: &str,
) {
    for ref_name in super::scan::collect_refs(body_line) {
        if ref_name != name {
            push_rust_reference(extractor, line_no, body_line.trim(), ref_name);
        }
    }
}

pub(super) fn collect_rust_refs(
    extractor: &mut RustExtractor<'_>,
    lines: &[&str],
    start: usize,
    end: usize,
    name: &str,
) {
    for (offset, body_line) in lines[start..=end].iter().enumerate() {
        collect_rust_line_refs(extractor, start + offset + 1, body_line, name);
    }
}
