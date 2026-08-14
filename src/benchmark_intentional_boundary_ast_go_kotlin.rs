use super::intentional_boundary_ast::{
    AstCallableCandidate, AstMethodSyntaxFacts, align_callable_candidates, census_language_ast,
    validate_language_ast,
};
use super::{
    IntentionalBoundaryAstCensus, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticRange,
    IntentionalBoundarySourceCensus,
};
use std::path::Path;
use tree_sitter::Node;

const GO: &str = "go";
const KOTLIN: &str = "kotlin";

pub fn census_intentional_boundary_go_ast(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
) -> Result<IntentionalBoundaryAstCensus, String> {
    census_language_ast(
        repository,
        revision,
        root,
        inventory,
        source_census,
        semantic_census,
        GO,
        go_syntax_facts,
    )
}

pub fn census_intentional_boundary_kotlin_ast(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
) -> Result<IntentionalBoundaryAstCensus, String> {
    census_language_ast(
        repository,
        revision,
        root,
        inventory,
        source_census,
        semantic_census,
        KOTLIN,
        kotlin_syntax_facts,
    )
}

pub fn validate_intentional_boundary_go_ast_census(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    ast_census: &IntentionalBoundaryAstCensus,
) -> Result<(), String> {
    validate_language_ast(
        repository,
        revision,
        root,
        inventory,
        source_census,
        semantic_census,
        ast_census,
        GO,
        go_syntax_facts,
    )
}

pub fn validate_intentional_boundary_kotlin_ast_census(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    ast_census: &IntentionalBoundaryAstCensus,
) -> Result<(), String> {
    validate_language_ast(
        repository,
        revision,
        root,
        inventory,
        source_census,
        semantic_census,
        ast_census,
        KOTLIN,
        kotlin_syntax_facts,
    )
}

fn go_syntax_facts(
    repository_path: &str,
    record: &crate::types::FileRecord,
) -> Result<AstMethodSyntaxFacts, String> {
    syntax_facts(repository_path, record, GO, go_candidate)
}

fn kotlin_syntax_facts(
    repository_path: &str,
    record: &crate::types::FileRecord,
) -> Result<AstMethodSyntaxFacts, String> {
    syntax_facts(repository_path, record, KOTLIN, kotlin_candidate)
}

type CandidateExtractor = fn(&str, Node<'_>) -> Option<AstCallableCandidate>;

fn syntax_facts(
    repository_path: &str,
    record: &crate::types::FileRecord,
    language: &str,
    extractor: CandidateExtractor,
) -> Result<AstMethodSyntaxFacts, String> {
    if record.language != language {
        return Err(format!(
            "{language} AST received {} parser record: {repository_path}",
            record.language
        ));
    }
    let tree =
        crate::parser::parse_tree_sitter_source_checked(repository_path, record.source.as_bytes())?;
    let mut candidates = Vec::new();
    collect_candidates(
        repository_path,
        tree.root_node(),
        language,
        extractor,
        &mut candidates,
    );
    align_callable_candidates(repository_path, language, record, candidates)
}

fn collect_candidates(
    repository_path: &str,
    node: Node<'_>,
    language: &str,
    extractor: CandidateExtractor,
    candidates: &mut Vec<AstCallableCandidate>,
) {
    let is_callable = match language {
        GO => matches!(node.kind(), "function_declaration" | "method_declaration"),
        KOTLIN => node.kind() == "function_declaration",
        _ => false,
    };
    if is_callable && let Some(candidate) = extractor(repository_path, node) {
        candidates.push(candidate);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_candidates(repository_path, child, language, extractor, candidates);
    }
}

fn go_candidate(repository_path: &str, declaration: Node<'_>) -> Option<AstCallableCandidate> {
    let body = declaration.child_by_field_name("body");
    Some(candidate(
        declaration,
        body.and_then(go_thin_delegation)
            .map(|call| node_range(repository_path, call)),
    ))
}

fn go_thin_delegation(body: Node<'_>) -> Option<Node<'_>> {
    let statement = only_meaningful_child(body)?;
    match statement.kind() {
        "return_statement" => {
            let expressions = only_meaningful_child(statement)?;
            if expressions.kind() != "expression_list" {
                return None;
            }
            go_forwarding_call(only_meaningful_child(expressions)?)
        }
        "expression_statement" => go_forwarding_call(only_meaningful_child(statement)?),
        _ => None,
    }
}

fn go_forwarding_call(expression: Node<'_>) -> Option<Node<'_>> {
    match expression.kind() {
        "call_expression" => Some(expression),
        "parenthesized_expression" => go_forwarding_call(only_meaningful_child(expression)?),
        _ => None,
    }
}

fn kotlin_candidate(repository_path: &str, declaration: Node<'_>) -> Option<AstCallableCandidate> {
    let mut cursor = declaration.walk();
    let body = declaration
        .named_children(&mut cursor)
        .find(|child| child.kind() == "function_body");
    Some(candidate(
        declaration,
        body.and_then(kotlin_thin_delegation)
            .map(|call| node_range(repository_path, call)),
    ))
}

fn kotlin_thin_delegation(body: Node<'_>) -> Option<Node<'_>> {
    let expression_or_block = only_meaningful_child(body)?;
    let expression = if expression_or_block.kind() == "block" {
        only_meaningful_child(expression_or_block)?
    } else {
        expression_or_block
    };
    kotlin_forwarding_call(expression)
}

fn kotlin_forwarding_call(expression: Node<'_>) -> Option<Node<'_>> {
    match expression.kind() {
        "call_expression" => Some(expression),
        "parenthesized_expression" => kotlin_forwarding_call(only_meaningful_child(expression)?),
        "return_expression" => {
            let label = expression.child_by_field_name("label");
            let mut cursor = expression.walk();
            let values = expression
                .named_children(&mut cursor)
                .filter(|child| !is_comment(*child) && Some(*child) != label)
                .collect::<Vec<_>>();
            let [value] = values.as_slice() else {
                return None;
            };
            kotlin_forwarding_call(*value)
        }
        _ => None,
    }
}

fn candidate(
    declaration: Node<'_>,
    thin_delegation: Option<IntentionalBoundarySemanticRange>,
) -> AstCallableCandidate {
    AstCallableCandidate {
        byte_start: declaration.start_byte(),
        byte_end: declaration.end_byte(),
        start_line: declaration.start_position().row + 1,
        end_line: declaration.end_position().row + 1,
        thin_delegation,
    }
}

fn only_meaningful_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let children = node
        .named_children(&mut cursor)
        .filter(|child| !is_comment(*child))
        .collect::<Vec<_>>();
    let [child] = children.as_slice() else {
        return None;
    };
    Some(*child)
}

fn is_comment(node: Node<'_>) -> bool {
    matches!(node.kind(), "comment" | "line_comment" | "block_comment")
}

fn node_range(repository_path: &str, node: Node<'_>) -> IntentionalBoundarySemanticRange {
    let start = node.start_position();
    let end = node.end_position();
    IntentionalBoundarySemanticRange {
        repository_path: repository_path.to_string(),
        start_line_zero_based: start.row as u32,
        start_character_zero_based: start.column as u32,
        end_line_zero_based: end.row as u32,
        end_character_zero_based: end.column as u32,
    }
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_ast_go_kotlin_tests.rs"]
mod tests;
