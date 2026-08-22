use super::super::intentional_boundary_ast_compiler_references::{
    AstCompilerReferenceIdentity, AstCompilerReferenceRequirement,
};
use super::super::intentional_boundary_compatibility_version::contains_explicit_version;
use super::IntentionalBoundarySemanticRange;
use tree_sitter::Node;

pub(super) struct KotlinCompatibilityContract {
    pub contract: IntentionalBoundarySemanticRange,
    pub annotation_type: AstCompilerReferenceRequirement,
}

pub(super) fn versioned_compatibility_contract(
    repository_path: &str,
    source: &[u8],
    declaration: Node<'_>,
) -> Option<KotlinCompatibilityContract> {
    let modifiers = direct_named_child(declaration, "modifiers")?;
    let mut cursor = modifiers.walk();
    let contracts = modifiers
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "annotation")
        .filter_map(|annotation| annotation_contract(repository_path, source, annotation))
        .collect::<Vec<_>>();
    let [contract] = contracts.as_slice() else {
        return None;
    };
    Some(KotlinCompatibilityContract {
        contract: contract.contract.clone(),
        annotation_type: contract.annotation_type.clone(),
    })
}

fn annotation_contract(
    repository_path: &str,
    source: &[u8],
    annotation: Node<'_>,
) -> Option<KotlinCompatibilityContract> {
    if direct_named_child(annotation, "use_site_target").is_some() {
        return None;
    }
    let invocation = direct_named_child(annotation, "constructor_invocation")?;
    let annotation_type = direct_named_child(invocation, "user_type")
        .or_else(|| direct_named_child(invocation, "type"))?;
    let type_identifier = rightmost_identifier(annotation_type)?;
    let arguments = direct_named_child(invocation, "value_arguments")?;
    let message = exact_message_argument(source, arguments)?;
    if message.kind() != "string_literal"
        || contains_descendant(message, "interpolation")
        || !literal_contains_version(source, message)
    {
        return None;
    }
    Some(KotlinCompatibilityContract {
        contract: super::node_range(repository_path, annotation),
        annotation_type: AstCompilerReferenceRequirement {
            range: super::node_range(repository_path, type_identifier),
            identity: AstCompilerReferenceIdentity::KotlinDeprecated,
        },
    })
}

fn exact_message_argument<'tree>(source: &[u8], arguments: Node<'tree>) -> Option<Node<'tree>> {
    let mut cursor = arguments.walk();
    let values = arguments
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "value_argument")
        .collect::<Vec<_>>();
    let mut messages = Vec::new();
    for (position, argument) in values.into_iter().enumerate() {
        let (name, value) = argument_parts(source, argument)?;
        if name.as_deref() == Some("message") || (position == 0 && name.is_none()) {
            messages.push(value);
        }
    }
    let [message] = messages.as_slice() else {
        return None;
    };
    Some(*message)
}

fn argument_parts<'tree>(
    source: &[u8],
    argument: Node<'tree>,
) -> Option<(Option<String>, Node<'tree>)> {
    let mut cursor = argument.walk();
    let children = argument.named_children(&mut cursor).collect::<Vec<_>>();
    match children.as_slice() {
        [value] => Some((None, *value)),
        [name, value] if name.kind() == "identifier" => {
            let separator = source.get(name.end_byte()..value.start_byte())?;
            if separator.iter().filter(|byte| **byte == b'=').count() != 1 {
                return None;
            }
            Some((Some(name.utf8_text(source).ok()?.to_string()), *value))
        }
        _ => None,
    }
}

fn literal_contains_version(source: &[u8], literal: Node<'_>) -> bool {
    let Ok(text) = literal.utf8_text(source) else {
        return false;
    };
    let Some(message) = text
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    else {
        return false;
    };
    contains_explicit_version(message)
}

fn direct_named_child<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

fn rightmost_identifier(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "identifier" {
        return Some(node);
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter_map(rightmost_identifier)
        .last()
}

fn contains_descendant(node: Node<'_>, kind: &str) -> bool {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| child.kind() == kind || contains_descendant(child, kind))
}
