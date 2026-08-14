use super::{
    IntentionalBoundaryAstCensus, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticRange,
    IntentionalBoundarySourceCensus,
};
use oxc_ast::Visit;
use oxc_ast::ast::{
    ArrowFunctionExpression, ChainElement, Expression, Function, FunctionBody, MethodDefinition,
    Statement,
};
use oxc_ast::visit::walk;
use oxc_span::{SourceType, Span};
use oxc_syntax::scope::ScopeFlags;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::intentional_boundary_ast::{
    AstMethodSyntaxFact, AstMethodSyntaxFacts, census_language_ast, validate_language_ast,
};

pub fn census_intentional_boundary_javascript_ast(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
) -> Result<IntentionalBoundaryAstCensus, String> {
    census_js_ts_ast(
        repository,
        revision,
        root,
        inventory,
        source_census,
        semantic_census,
        "javascript",
    )
}

pub fn census_intentional_boundary_typescript_ast(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
) -> Result<IntentionalBoundaryAstCensus, String> {
    census_js_ts_ast(
        repository,
        revision,
        root,
        inventory,
        source_census,
        semantic_census,
        "typescript",
    )
}

pub fn validate_intentional_boundary_javascript_ast_census(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    ast_census: &IntentionalBoundaryAstCensus,
) -> Result<(), String> {
    validate_js_ts_ast(
        repository,
        revision,
        root,
        inventory,
        source_census,
        semantic_census,
        ast_census,
        "javascript",
    )
}

pub fn validate_intentional_boundary_typescript_ast_census(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    ast_census: &IntentionalBoundaryAstCensus,
) -> Result<(), String> {
    validate_js_ts_ast(
        repository,
        revision,
        root,
        inventory,
        source_census,
        semantic_census,
        ast_census,
        "typescript",
    )
}

#[allow(clippy::too_many_arguments)]
fn census_js_ts_ast(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    language: &str,
) -> Result<IntentionalBoundaryAstCensus, String> {
    census_language_ast(
        repository,
        revision,
        root,
        inventory,
        source_census,
        semantic_census,
        language,
        js_ts_syntax_facts,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_js_ts_ast(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    ast_census: &IntentionalBoundaryAstCensus,
    language: &str,
) -> Result<(), String> {
    validate_language_ast(
        repository,
        revision,
        root,
        inventory,
        source_census,
        semantic_census,
        ast_census,
        language,
        js_ts_syntax_facts,
    )
}

#[derive(Clone)]
struct CallableCandidate {
    span: Span,
    start_line: usize,
    end_line: usize,
    thin_delegation: Option<IntentionalBoundarySemanticRange>,
}

fn js_ts_syntax_facts(
    repository_path: &str,
    record: &crate::types::FileRecord,
) -> Result<AstMethodSyntaxFacts, String> {
    let allocator = oxc_allocator::Allocator::default();
    let source_type = SourceType::from_path(Path::new(repository_path)).unwrap_or_default();
    let parsed = oxc_parser::Parser::new(&allocator, &record.source, source_type).parse();
    if !parsed.errors.is_empty() {
        return Err(format!(
            "failed to parse JavaScript/TypeScript AST {repository_path}: {} parser error(s): {:?}",
            parsed.errors.len(),
            parsed.errors
        ));
    }
    let mut visitor = JsTsBodyVisitor {
        repository_path,
        line_starts: line_starts(&record.source),
        candidates: Vec::new(),
    };
    visitor.visit_program(&parsed.program);
    align_candidates(repository_path, record, visitor.candidates)
}

struct JsTsBodyVisitor<'a> {
    repository_path: &'a str,
    line_starts: Vec<usize>,
    candidates: Vec<CallableCandidate>,
}

impl JsTsBodyVisitor<'_> {
    fn record(&mut self, span: Span, body: Option<&FunctionBody<'_>>) {
        let start_line = line_for_offset(span.start as usize, &self.line_starts) + 1;
        let end_line = line_for_offset(span.end.saturating_sub(1) as usize, &self.line_starts) + 1;
        let thin_delegation = body
            .and_then(thin_delegation_expression)
            .map(|call| offset_range(self.repository_path, call, &self.line_starts));
        self.candidates.push(CallableCandidate {
            span,
            start_line,
            end_line,
            thin_delegation,
        });
    }
}

impl<'a> Visit<'a> for JsTsBodyVisitor<'_> {
    fn visit_function(&mut self, function: &Function<'a>, flags: Option<ScopeFlags>) {
        self.record(function.span, function.body.as_deref());
        walk::walk_function(self, function, flags);
    }

    fn visit_arrow_expression(&mut self, expression: &ArrowFunctionExpression<'a>) {
        self.record(expression.span, Some(&expression.body));
        walk::walk_arrow_expression(self, expression);
    }

    fn visit_method_definition(&mut self, definition: &MethodDefinition<'a>) {
        self.record(definition.span, definition.value.body.as_deref());
        walk::walk_function(self, &definition.value, Some(definition.kind.scope_flags()));
    }
}

fn align_candidates(
    repository_path: &str,
    record: &crate::types::FileRecord,
    candidates: Vec<CallableCandidate>,
) -> Result<AstMethodSyntaxFacts, String> {
    let mut candidates_by_lines = BTreeMap::<(usize, usize), Vec<CallableCandidate>>::new();
    let mut seen_spans = BTreeSet::new();
    for candidate in candidates {
        if seen_spans.insert((candidate.span.start, candidate.span.end)) {
            candidates_by_lines
                .entry((candidate.start_line, candidate.end_line))
                .or_default()
                .push(candidate);
        }
    }
    let mut methods_by_lines = BTreeMap::<(usize, usize), Vec<&crate::types::MethodRecord>>::new();
    for method in &record.methods {
        methods_by_lines
            .entry((method.start_line, method.end_line))
            .or_default()
            .push(method);
    }
    if candidates_by_lines.keys().collect::<Vec<_>>() != methods_by_lines.keys().collect::<Vec<_>>()
    {
        return Err(format!(
            "JavaScript/TypeScript AST callable ranges changed from parser census: {repository_path}"
        ));
    }
    let mut facts = BTreeMap::new();
    for (lines, methods) in methods_by_lines {
        let candidates = candidates_by_lines
            .get_mut(&lines)
            .expect("candidate keys were compared");
        candidates.sort_by_key(|candidate| (candidate.span.start, candidate.span.end));
        if methods.len() != candidates.len() {
            return Err(format!(
                "JavaScript/TypeScript AST callable count changed at {}:{}-{}",
                repository_path, lines.0, lines.1
            ));
        }
        for (method, candidate) in methods.into_iter().zip(candidates.iter()) {
            let previous = facts.insert(
                (method.name.clone(), method.start_line),
                AstMethodSyntaxFact {
                    end_line: candidate.end_line,
                    thin_delegation: candidate.thin_delegation.clone(),
                },
            );
            if previous.is_some() {
                return Err(format!(
                    "JavaScript/TypeScript AST repeated parser method identity: {}:{}:{}",
                    repository_path, method.start_line, method.name
                ));
            }
        }
    }
    Ok(facts)
}

fn thin_delegation_expression(body: &FunctionBody<'_>) -> Option<Span> {
    if !body.directives.is_empty() {
        return None;
    }
    let [statement] = body.statements.as_slice() else {
        return None;
    };
    match statement {
        Statement::ReturnStatement(value) => value.argument.as_ref().and_then(forwarding_call),
        Statement::ExpressionStatement(value) => forwarding_call(&value.expression),
        _ => None,
    }
}

fn forwarding_call(expression: &Expression<'_>) -> Option<Span> {
    match expression {
        Expression::CallExpression(value) => Some(value.span),
        Expression::AwaitExpression(value) => forwarding_call(&value.argument),
        Expression::ChainExpression(value) => match &value.expression {
            ChainElement::CallExpression(call) => Some(call.span),
            _ => None,
        },
        Expression::ParenthesizedExpression(value) => forwarding_call(&value.expression),
        Expression::TSAsExpression(value) => forwarding_call(&value.expression),
        Expression::TSInstantiationExpression(value) => forwarding_call(&value.expression),
        Expression::TSNonNullExpression(value) => forwarding_call(&value.expression),
        Expression::TSSatisfiesExpression(value) => forwarding_call(&value.expression),
        Expression::TSTypeAssertion(value) => forwarding_call(&value.expression),
        _ => None,
    }
}

fn line_starts(source: &str) -> Vec<usize> {
    std::iter::once(0)
        .chain(
            source
                .bytes()
                .enumerate()
                .filter_map(|(index, byte)| (byte == b'\n').then_some(index + 1)),
        )
        .collect()
}

fn line_for_offset(offset: usize, starts: &[usize]) -> usize {
    starts
        .partition_point(|start| *start <= offset)
        .saturating_sub(1)
}

fn offset_range(
    repository_path: &str,
    span: Span,
    starts: &[usize],
) -> IntentionalBoundarySemanticRange {
    let start = span.start as usize;
    let end = span.end as usize;
    let start_line = line_for_offset(start, starts);
    let end_line = line_for_offset(end, starts);
    IntentionalBoundarySemanticRange {
        repository_path: repository_path.to_string(),
        start_line_zero_based: start_line as u32,
        start_character_zero_based: start.saturating_sub(starts[start_line]) as u32,
        end_line_zero_based: end_line as u32,
        end_character_zero_based: end.saturating_sub(starts[end_line]) as u32,
    }
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_ast_js_ts_tests.rs"]
mod tests;
