use super::{
    IntentionalBoundaryAstCensus, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticRange,
    IntentionalBoundarySourceCensus,
};
use oxc_ast::Visit;
use oxc_ast::ast::{
    ArrowFunctionExpression, ChainElement, Declaration, ExportDefaultDeclaration,
    ExportDefaultDeclarationKind, ExportNamedDeclaration, Expression, Function, FunctionBody,
    MethodDefinition, Modifiers, ObjectProperty, PropertyDefinition, Statement,
    VariableDeclaration,
};
use oxc_ast::visit::walk;
use oxc_span::{SourceType, Span};
use oxc_syntax::scope::ScopeFlags;
use std::path::Path;

#[cfg(test)]
use super::intentional_boundary_ast::derive_language_ast_census;
use super::intentional_boundary_ast::{
    AstCallableCandidate, AstMethodSyntaxFacts, align_callable_candidates, census_language_ast,
    validate_language_ast,
};

#[path = "benchmark_intentional_boundary_ast_js_ts_retry.rs"]
mod retry;
use retry::find_retry_loop;

#[path = "benchmark_intentional_boundary_ast_js_ts_compatibility.rs"]
mod compatibility;

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
    let comments = parsed.trivias.comments().collect::<Vec<_>>();
    let mut visitor = JsTsBodyVisitor {
        repository_path,
        source: &record.source,
        comments,
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
    source: &'a str,
    comments: Vec<(oxc_ast::CommentKind, Span)>,
    line_starts: Vec<usize>,
    candidates: Vec<AstCallableCandidate>,
}

impl JsTsBodyVisitor<'_> {
    fn record(&mut self, span: Span, body: Option<&FunctionBody<'_>>, declaration_start: u32) {
        let start_line = line_for_offset(span.start as usize, &self.line_starts) + 1;
        let end_line = line_for_offset(span.end.saturating_sub(1) as usize, &self.line_starts) + 1;
        let thin_delegation = body
            .and_then(thin_delegation_expression)
            .map(|call| offset_range(self.repository_path, call, &self.line_starts));
        let distinct_retry_outcomes =
            body.and_then(|body| find_retry_loop(&body.statements))
                .map(|(retryable, terminal)| {
                    (
                        offset_range(self.repository_path, retryable, &self.line_starts),
                        offset_range(self.repository_path, terminal, &self.line_starts),
                    )
                });
        self.candidates.push(AstCallableCandidate {
            byte_start: span.start as usize,
            byte_end: span.end as usize,
            start_line,
            end_line,
            thin_delegation,
            distinct_retry_outcomes,
            generator_marker: None,
            versioned_compatibility_source_contract:
                compatibility::versioned_compatibility_contract(
                    self.source,
                    &self.comments,
                    declaration_start,
                )
                .map(|comment| offset_range(self.repository_path, comment, &self.line_starts)),
            versioned_compatibility_compiler_references: Vec::new(),
        });
    }

    fn record_direct_callable(&mut self, expression: &Expression<'_>, declaration_start: u32) {
        match expression {
            Expression::ArrowFunctionExpression(arrow) => {
                self.record(arrow.span, Some(&arrow.body), declaration_start);
            }
            Expression::FunctionExpression(function) => {
                self.record(function.span, function.body.as_deref(), declaration_start);
            }
            _ => {}
        }
    }

    fn declaration_start(modifiers: &Modifiers<'_>, fallback: u32) -> u32 {
        modifiers
            .find(|_| true)
            .map_or(fallback, |modifier| modifier.span.start)
    }

    fn record_variable_callables(
        &mut self,
        declaration: &VariableDeclaration<'_>,
        declaration_start: u32,
    ) {
        let callables = declaration
            .declarations
            .iter()
            .filter_map(|declarator| declarator.init.as_ref())
            .filter(|expression| {
                matches!(
                    expression,
                    Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
                )
            })
            .collect::<Vec<_>>();
        if let [callable] = callables.as_slice() {
            self.record_direct_callable(callable, declaration_start);
        }
    }
}

#[cfg(test)]
pub(super) fn derive_js_ts_ast_census(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    files: &[crate::types::FileRecord],
    language: &str,
) -> Result<IntentionalBoundaryAstCensus, String> {
    derive_language_ast_census(
        source_census,
        semantic_census,
        files,
        language,
        js_ts_syntax_facts,
    )
}

impl<'a> Visit<'a> for JsTsBodyVisitor<'_> {
    fn visit_function(&mut self, function: &Function<'a>, flags: Option<ScopeFlags>) {
        self.record(
            function.span,
            function.body.as_deref(),
            Self::declaration_start(&function.modifiers, function.span.start),
        );
        walk::walk_function(self, function, flags);
    }

    fn visit_arrow_expression(&mut self, expression: &ArrowFunctionExpression<'a>) {
        self.record(
            expression.span,
            Some(&expression.body),
            expression.span.start,
        );
        walk::walk_arrow_expression(self, expression);
    }

    fn visit_method_definition(&mut self, definition: &MethodDefinition<'a>) {
        self.record(
            definition.span,
            definition.value.body.as_deref(),
            definition.span.start,
        );
        walk::walk_function(self, &definition.value, Some(definition.kind.scope_flags()));
    }

    fn visit_variable_declaration(&mut self, declaration: &VariableDeclaration<'a>) {
        self.record_variable_callables(
            declaration,
            Self::declaration_start(&declaration.modifiers, declaration.span.start),
        );
        walk::walk_variable_declaration(self, declaration);
    }

    fn visit_property_definition(&mut self, definition: &PropertyDefinition<'a>) {
        if let Some(value) = &definition.value {
            self.record_direct_callable(value, definition.span.start);
        }
        walk::walk_property_definition(self, definition);
    }

    fn visit_object_property(&mut self, property: &ObjectProperty<'a>) {
        self.record_direct_callable(&property.value, property.span.start);
        walk::walk_object_property(self, property);
    }

    fn visit_export_named_declaration(&mut self, export: &ExportNamedDeclaration<'a>) {
        match &export.declaration {
            Some(Declaration::FunctionDeclaration(function)) => {
                self.record(function.span, function.body.as_deref(), export.span.start);
            }
            Some(Declaration::VariableDeclaration(declaration)) => {
                self.record_variable_callables(declaration, export.span.start);
            }
            _ => {}
        }
        walk::walk_export_named_declaration(self, export);
    }

    fn visit_export_default_declaration(&mut self, export: &ExportDefaultDeclaration<'a>) {
        match &export.declaration {
            ExportDefaultDeclarationKind::FunctionDeclaration(function) => {
                self.record(function.span, function.body.as_deref(), export.span.start);
            }
            ExportDefaultDeclarationKind::ArrowFunctionExpression(arrow) => {
                self.record(arrow.span, Some(&arrow.body), export.span.start);
            }
            ExportDefaultDeclarationKind::FunctionExpression(function) => {
                self.record(function.span, function.body.as_deref(), export.span.start);
            }
            _ => {}
        }
        walk::walk_export_default_declaration(self, export);
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
