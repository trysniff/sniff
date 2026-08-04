use super::*;
use crate::types::SymbolReference;

fn call_target_name(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" | "selector_expression" => node
            .utf8_text(source)
            .ok()
            .map(|value| value.chars().filter(|ch| !ch.is_whitespace()).collect()),
        "generic_type" | "parenthesized_expression" => node
            .named_children(&mut node.walk())
            .find_map(|child| call_target_name(child, source)),
        _ => None,
    }
}

fn collect_call_references(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    lines: &[&str],
    references: &mut Vec<SymbolReference>,
) {
    if node.kind() == "call_expression"
        && let Some(function) = node.child_by_field_name("function")
        && let Some(name) = call_target_name(function, source)
    {
        let line = function.start_position().row + 1;
        if !references
            .iter()
            .any(|reference| reference.name == name && reference.line == line)
        {
            references.push(SymbolReference {
                name,
                line,
                snippet: lines
                    .get(line.saturating_sub(1))
                    .map_or("", |line| line.trim())
                    .to_string(),
                is_member_call: false,
                is_callable_value: false,
                resolved_symbol: None,
            });
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_call_references(child, source, lines, references);
    }
}

pub(crate) fn scan_go_references(extractor: &mut SymbolExtractor<'_>, root: tree_sitter::Node<'_>) {
    let source = String::from_utf8_lossy(extractor.source_bytes);
    let lines: Vec<&str> = source.lines().collect();
    collect_call_references(
        root,
        extractor.source_bytes,
        &lines,
        &mut extractor.references,
    );
}
