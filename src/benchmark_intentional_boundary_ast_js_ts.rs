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
use std::path::Path;

use super::intentional_boundary_ast::{
    AstCallableCandidate, AstMethodSyntaxFacts, align_callable_candidates, census_language_ast,
    validate_language_ast,
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
    align_callable_candidates(
        repository_path,
        "JavaScript/TypeScript",
        record,
        visitor.candidates,
    )
}

struct JsTsBodyVisitor<'a> {
    repository_path: &'a str,
    line_starts: Vec<usize>,
    candidates: Vec<AstCallableCandidate>,
}

impl JsTsBodyVisitor<'_> {
    fn record(&mut self, span: Span, body: Option<&FunctionBody<'_>>) {
        let start_line = line_for_offset(span.start as usize, &self.line_starts) + 1;
        let end_line = line_for_offset(span.end.saturating_sub(1) as usize, &self.line_starts) + 1;
        let thin_delegation = body
            .and_then(thin_delegation_expression)
            .map(|call| offset_range(self.repository_path, call, &self.line_starts));
        self.candidates.push(AstCallableCandidate {
            byte_start: span.start as usize,
            byte_end: span.end as usize,
            start_line,
            end_line,
            thin_delegation,
            distinct_retry_outcomes: None,
            versioned_compatibility_annotation: None,
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
