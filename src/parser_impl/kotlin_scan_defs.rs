use super::*;
use crate::types::{SymbolKind, SymbolReference};
use tree_sitter::Node;

fn simple_name_from_text(text: &str) -> Option<String> {
    let trimmed = text
        .trim()
        .trim_end_matches('{')
        .trim_end_matches('(')
        .trim_end_matches(':')
        .trim_end_matches('<')
        .trim_end_matches('>')
        .trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn node_text<'a>(node: Node, source: &'a str) -> Option<&'a str> {
    node.utf8_text(source.as_bytes()).ok()
}

fn first_identifier_from_node(node: Node, source: &str) -> Option<String> {
    let kind = node.kind();
    if matches!(kind, "simple_identifier" | "identifier" | "type_identifier")
        && let Some(text) = node_text(node, source)
    {
        return simple_name_from_text(text);
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(name) = first_identifier_from_node(child, source) {
            return Some(name);
        }
    }
    None
}

fn name_for_node(node: Node, source: &str) -> Option<String> {
    if let Some(field) = node.child_by_field_name("name") {
        if let Some(text) = node_text(field, source)
            && let Some(name) = simple_name_from_text(text)
        {
            return Some(name);
        }
        if let Some(name) = first_identifier_from_node(field, source) {
            return Some(name);
        }
    }
    first_identifier_from_node(node, source)
}

fn is_private_source(source: &str, start_row: usize) -> bool {
    source
        .lines()
        .nth(start_row)
        .map(|line| line.contains("private "))
        .unwrap_or(false)
}

fn collect_definition(
    extractor: &mut SymbolExtractor<'_>,
    node: Node,
    source: &str,
    kind: SymbolKind,
    owner_type: Option<String>,
) {
    let Some(name) = name_for_node(node, source) else {
        return;
    };
    extractor.definitions.push(SymbolDefinition {
        id: extractor.next_id,
        name,
        kind,
        start_line: node.start_position().row + 1,
        end_line: node.end_position().row + 1,
        is_exported: !is_private_source(source, node.start_position().row),
        owner_type,
    });
    extractor.next_id += 1;
}

fn collect_imports(extractor: &mut SymbolExtractor<'_>) {
    let source = String::from_utf8_lossy(extractor.source_bytes);
    for line in source.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("import ") {
            let source_module = rest.trim().trim_end_matches(';').to_string();
            let local_name = source_module
                .split('.')
                .next_back()
                .unwrap_or(&source_module)
                .trim()
                .to_string();
            extractor.imports.push(ImportRecord {
                local_name,
                source_module,
                imported_name: "*".to_string(),
            });
        }
    }
}

fn visit_node(
    extractor: &mut SymbolExtractor<'_>,
    node: Node,
    source: &str,
    owner_stack: &mut Vec<String>,
    function_ranges: &mut Vec<(usize, usize)>,
) {
    match node.kind() {
        "class_declaration"
        | "object_declaration"
        | "interface_declaration"
        | "enum_class_declaration"
        | "fun_interface_declaration" => {
            let owner = name_for_node(node, source);
            collect_definition(extractor, node, source, SymbolKind::Class, None);
            if let Some(owner) = owner {
                owner_stack.push(owner);
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    visit_node(extractor, child, source, owner_stack, function_ranges);
                }
                owner_stack.pop();
                return;
            }
        }
        "function_declaration" => {
            let name = match name_for_node(node, source) {
                Some(name) => name,
                None => return,
            };
            let source_text = node_text(node, source).unwrap_or("").to_string();
            let owner_type = owner_stack.last().cloned();
            let is_exported = !is_private_source(source, node.start_position().row);
            extractor.definitions.push(SymbolDefinition {
                id: extractor.next_id,
                name: name.clone(),
                kind: if owner_type.is_some() {
                    SymbolKind::Method
                } else {
                    SymbolKind::Function
                },
                start_line: node.start_position().row + 1,
                end_line: node.end_position().row + 1,
                is_exported,
                owner_type,
            });
            extractor.next_id += 1;
            for (offset, line) in source_text.lines().enumerate() {
                for r in super::refs::collect_refs(line) {
                    extractor.references.push(SymbolReference {
                        name: r,
                        line: node.start_position().row + offset + 1,
                        snippet: line.trim().to_string(),
                        resolved_symbol: None,
                    });
                }
            }
            function_ranges.push((node.start_position().row, node.end_position().row));
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        visit_node(extractor, child, source, owner_stack, function_ranges);
    }
}

pub(crate) fn scan_kotlin_defs_and_imports(
    extractor: &mut SymbolExtractor<'_>,
) -> Vec<(usize, usize)> {
    let source = String::from_utf8_lossy(extractor.source_bytes).into_owned();
    collect_imports(extractor);
    let mut ranges = Vec::new();
    if let Some(tree) = super::super::get_parser(extractor.adapter)
        .and_then(|mut parser| parser.parse(extractor.source_bytes, None))
    {
        let mut owner_stack = Vec::new();
        visit_node(
            extractor,
            tree.root_node(),
            &source,
            &mut owner_stack,
            &mut ranges,
        );
    }
    let _ = &extractor.adapter;
    let _ = &extractor.language;
    ranges
}
