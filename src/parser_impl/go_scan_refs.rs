use super::*;
use crate::types::SymbolReference;

pub(crate) fn scan_go_references(extractor: &mut SymbolExtractor<'_>, ranges: &[(usize, usize)]) {
    let source = String::from_utf8_lossy(extractor.source_bytes);
    let lines: Vec<&str> = source.lines().collect();
    for (start, end) in ranges {
        for (offset, body_line) in lines[*start..=*end].iter().enumerate() {
            for r in super::refs::collect_refs(body_line) {
                extractor.references.push(SymbolReference {
                    name: r,
                    line: start + offset + 1,
                    snippet: body_line.trim().to_string(),
                    resolved_symbol: None,
                });
            }
        }
    }
}
