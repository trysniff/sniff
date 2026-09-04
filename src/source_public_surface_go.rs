use super::{
    SourceByteRange, SourcePublicBindingKind, SourcePublicDeclaration, SourcePublicNamespace,
    SourcePublicSurface, SourcePublicSymbolKind,
};
use tree_sitter::Node;

pub(super) fn census(file_path: &str, source: &[u8]) -> Result<SourcePublicSurface, String> {
    let tree = crate::parser::parse_tree_sitter_source_checked(file_path, source)?;
    let mut declarations = Vec::new();
    collect(tree.root_node(), source, None, &mut declarations)?;
    Ok(SourcePublicSurface {
        declarations,
        reexports: Vec::new(),
    })
}

fn collect(
    node: Node<'_>,
    source: &[u8],
    owner: Option<&str>,
    declarations: &mut Vec<SourcePublicDeclaration>,
) -> Result<(), String> {
    match node.kind() {
        "function_declaration" => {
            record_named(
                node,
                source,
                None,
                SourcePublicSymbolKind::Callable,
                declarations,
            )?;
            return Ok(());
        }
        "method_declaration" => {
            let receiver = node
                .child_by_field_name("receiver")
                .and_then(|receiver| receiver_type_name(receiver, source));
            record_named(
                node,
                source,
                receiver.as_deref(),
                SourcePublicSymbolKind::Method,
                declarations,
            )?;
            return Ok(());
        }
        "type_spec" | "type_alias" => {
            let name = record_named(
                node,
                source,
                None,
                SourcePublicSymbolKind::Type,
                declarations,
            )?;
            if let Some(type_node) = node.child_by_field_name("type") {
                collect(type_node, source, name.as_deref(), declarations)?;
            }
            return Ok(());
        }
        "const_spec" => {
            record_names(
                node,
                source,
                None,
                SourcePublicSymbolKind::Constant,
                declarations,
            )?;
            return Ok(());
        }
        "var_spec" => {
            record_names(
                node,
                source,
                None,
                SourcePublicSymbolKind::Variable,
                declarations,
            )?;
            return Ok(());
        }
        "field_declaration" => {
            record_names(
                node,
                source,
                owner,
                SourcePublicSymbolKind::Field,
                declarations,
            )?;
        }
        "method_elem" => {
            record_named(
                node,
                source,
                owner,
                SourcePublicSymbolKind::Method,
                declarations,
            )?;
            return Ok(());
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect(child, source, owner, declarations)?;
    }
    Ok(())
}

fn record_named(
    node: Node<'_>,
    source: &[u8],
    owner: Option<&str>,
    kind: SourcePublicSymbolKind,
    declarations: &mut Vec<SourcePublicDeclaration>,
) -> Result<Option<String>, String> {
    let Some(name) = node.child_by_field_name("name") else {
        return Ok(None);
    };
    let text = node_text(name, source)?;
    if is_exported_identifier(text) {
        declarations.push(declaration(name, text, owner, kind));
    }
    Ok(Some(text.to_string()))
}

fn record_names(
    node: Node<'_>,
    source: &[u8],
    owner: Option<&str>,
    kind: SourcePublicSymbolKind,
    declarations: &mut Vec<SourcePublicDeclaration>,
) -> Result<(), String> {
    let mut cursor = node.walk();
    for name in node.children_by_field_name("name", &mut cursor) {
        let text = node_text(name, source)?;
        if is_exported_identifier(text) {
            declarations.push(declaration(name, text, owner, kind));
        }
    }

    // An embedded field has a type but no explicit name; its declared field name
    // is the final type identifier under Go's language rules.
    if node.kind() == "field_declaration"
        && node.child_by_field_name("name").is_none()
        && let Some(type_node) = node.child_by_field_name("type")
        && let Some(name) = embedded_field_identifier(type_node)
    {
        let text = node_text(name, source)?;
        if is_exported_identifier(text) {
            declarations.push(declaration(name, text, owner, kind));
        }
    }
    Ok(())
}

fn declaration(
    name: Node<'_>,
    text: &str,
    owner: Option<&str>,
    kind: SourcePublicSymbolKind,
) -> SourcePublicDeclaration {
    SourcePublicDeclaration {
        name: text.to_string(),
        target_name: text.to_string(),
        owner: owner.map(str::to_string),
        namespace: if owner.is_some() {
            SourcePublicNamespace::InstanceMember
        } else {
            SourcePublicNamespace::Module
        },
        kind,
        exposed_identifier: SourceByteRange {
            start: name.start_byte(),
            end: name.end_byte(),
        },
        compiler_anchor: SourceByteRange {
            start: name.start_byte(),
            end: name.end_byte(),
        },
        binding: SourcePublicBindingKind::Definition,
        source_module: None,
    }
}

fn final_identifier(node: Node<'_>) -> Option<Node<'_>> {
    if matches!(
        node.kind(),
        "identifier" | "type_identifier" | "field_identifier"
    ) {
        return Some(node);
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter_map(final_identifier)
        .last()
}

fn embedded_field_identifier(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "generic_type" => node
            .child_by_field_name("type")
            .and_then(embedded_field_identifier),
        "pointer_type" => node.named_child(0).and_then(embedded_field_identifier),
        _ => final_identifier(node),
    }
}

fn receiver_type_name(receiver: Node<'_>, source: &[u8]) -> Option<String> {
    let name = final_identifier(receiver)?;
    name.utf8_text(source).ok().map(str::to_string)
}

fn node_text<'a>(node: Node<'_>, source: &'a [u8]) -> Result<&'a str, String> {
    node.utf8_text(source)
        .map_err(|error| format!("Go AST identifier is not valid UTF-8: {error}"))
}

fn is_exported_identifier(name: &str) -> bool {
    name.chars().next().is_some_and(char::is_uppercase)
}
