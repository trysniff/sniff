use super::*;
use crate::types::Reference;
use tree_sitter::Node;

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
        language: "kotlin".to_string(),
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

fn node_text<'a>(node: Node, source: &'a str) -> Option<&'a str> {
    node.utf8_text(source.as_bytes()).ok()
}

fn name_for_node(node: Node, source: &str) -> Option<String> {
    if let Some(field) = node.child_by_field_name("name")
        && let Some(text) = node_text(field, source)
    {
        let cleaned = text.trim().trim_matches('`');
        if !cleaned.is_empty() {
            return Some(cleaned.to_string());
        }
    }

    let kind = node.kind();
    if matches!(kind, "simple_identifier" | "identifier" | "type_identifier")
        && let Some(text) = node_text(node, source)
    {
        let cleaned = text.trim().trim_matches('`');
        if !cleaned.is_empty() {
            return Some(cleaned.to_string());
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let child_kind = child.kind();
        if child_kind.contains("annotation") || child_kind.contains("modifier") {
            continue;
        }
        if let Some(name) = name_for_node(child, source) {
            return Some(name);
        }
    }
    None
}

fn count_params(node: Node, source: &str) -> usize {
    for field_name in ["value_parameters", "parameters"] {
        if let Some(params) = node.child_by_field_name(field_name) {
            let mut count = 0usize;
            let mut cursor = params.walk();
            for child in params.children(&mut cursor) {
                if child.kind() == "value_parameter" {
                    count += 1;
                }
            }
            if count > 0 {
                return count;
            }

            if let Some(text) = node_text(params, source) {
                let inner = text
                    .trim()
                    .trim_start_matches('(')
                    .trim_end_matches(')')
                    .trim();
                if inner.is_empty() {
                    return 0;
                }
                return inner.split(',').filter(|p| !p.trim().is_empty()).count();
            }
        }
    }
    0
}

fn collect_functions(
    node: Node,
    source: &str,
    file_path: &str,
    methods: &mut Vec<MethodRecord>,
    owner_stack: &mut Vec<(String, bool)>,
) {
    match node.kind() {
        "class_declaration"
        | "object_declaration"
        | "interface_declaration"
        | "enum_class_declaration"
        | "fun_interface_declaration" => {
            if let Some(owner) = name_for_node(node, source) {
                let owner_is_external = super::declaration_is_repository_external(node, source)
                    && owner_stack
                        .last()
                        .is_none_or(|(_, is_external)| *is_external);
                owner_stack.push((owner, owner_is_external));
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    collect_functions(child, source, file_path, methods, owner_stack);
                }
                owner_stack.pop();
                return;
            }
        }
        "function_declaration" => {
            let Some(name) = name_for_node(node, source) else {
                return;
            };
            if name == "Composable" {
                let mut fallback_cursor = node.walk();
                for child in node.children(&mut fallback_cursor) {
                    let child_kind = child.kind();
                    if child_kind.contains("annotation") || child_kind.contains("modifier") {
                        continue;
                    }
                    if let Some(text) = node_text(child, source) {
                        let cleaned = text.trim().trim_matches('`');
                        if !cleaned.is_empty()
                            && cleaned != "Composable"
                            && (child.kind().contains("identifier")
                                || child.kind().contains("simple"))
                        {
                            let start = node.start_position().row;
                            let end = node.end_position().row;
                            let source_text = node_text(node, source).unwrap_or("").to_string();
                            let refs = super::refs::collect_source_refs(&source_text)
                                .into_iter()
                                .flat_map(|(_, _, refs)| refs)
                                .filter(|r| r != cleaned)
                                .collect::<Vec<_>>();
                            let is_exported =
                                super::declaration_is_repository_external(node, source)
                                    && owner_stack
                                        .last()
                                        .is_none_or(|(_, is_external)| *is_external);
                            push_method(
                                methods,
                                file_path,
                                cleaned,
                                start,
                                end,
                                count_params(node, source),
                                is_exported,
                                source_text,
                                refs,
                            );
                            return;
                        }
                    }
                }
            }
            let start = node.start_position().row;
            let end = node.end_position().row;
            let source_text = node_text(node, source).unwrap_or("").to_string();
            let refs = super::refs::collect_source_refs(&source_text)
                .into_iter()
                .flat_map(|(_, _, refs)| refs)
                .filter(|r| r != &name)
                .collect::<Vec<_>>();
            let is_exported = super::declaration_is_repository_external(node, source)
                && owner_stack
                    .last()
                    .is_none_or(|(_, is_external)| *is_external);
            push_method(
                methods,
                file_path,
                &name,
                start,
                end,
                count_params(node, source),
                is_exported,
                source_text,
                refs,
            );
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_functions(child, source, file_path, methods, owner_stack);
    }
}

pub(crate) fn extract_methods(
    root: Node,
    source_bytes: &[u8],
    adapter: &LanguageAdapter,
    file_path: &str,
) -> Vec<MethodRecord> {
    let source = String::from_utf8_lossy(source_bytes);
    let mut methods = Vec::new();
    let mut owner_stack = Vec::new();
    collect_functions(root, &source, file_path, &mut methods, &mut owner_stack);
    let _ = adapter;
    methods
}
