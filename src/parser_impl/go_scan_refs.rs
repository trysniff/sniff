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
    local_functions: &HashSet<String>,
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
                is_member_call: function.kind() == "selector_expression",
                is_callable_value: false,
                resolved_symbol: None,
            });
        }

        if let Some(arguments) = node.child_by_field_name("arguments") {
            let mut cursor = arguments.walk();
            for argument in arguments.named_children(&mut cursor) {
                if argument.kind() != "identifier" {
                    continue;
                }
                let Ok(name) = argument.utf8_text(source) else {
                    continue;
                };
                if !local_functions.contains(name) {
                    continue;
                }
                let line = argument.start_position().row + 1;
                if references
                    .iter()
                    .any(|reference| reference.name == name && reference.line == line)
                {
                    continue;
                }
                references.push(SymbolReference {
                    name: name.to_string(),
                    line,
                    snippet: lines
                        .get(line.saturating_sub(1))
                        .map_or("", |line| line.trim())
                        .to_string(),
                    is_member_call: false,
                    is_callable_value: true,
                    resolved_symbol: None,
                });
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_call_references(child, source, lines, local_functions, references);
    }
}

pub(crate) fn scan_go_references(extractor: &mut SymbolExtractor<'_>, root: tree_sitter::Node<'_>) {
    let source = String::from_utf8_lossy(extractor.source_bytes);
    let lines: Vec<&str> = source.lines().collect();
    let local_functions = extractor
        .definitions
        .iter()
        .filter(|definition| {
            matches!(definition.kind, SymbolKind::Function) && definition.owner_type.is_none()
        })
        .map(|definition| definition.name.clone())
        .collect::<HashSet<_>>();
    collect_call_references(
        root,
        extractor.source_bytes,
        &lines,
        &local_functions,
        &mut extractor.references,
    );
}
