use super::{
    IntentionalBoundaryAstCensus, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticRange,
    IntentionalBoundarySourceCensus,
};
use std::collections::BTreeMap;
use std::path::Path;
use syn::spanned::Spanned;
use syn::visit::Visit;

use super::intentional_boundary_ast::{
    AstMethodSyntaxFact, AstMethodSyntaxFacts, census_language_ast, derive_language_ast_census,
    validate_language_ast,
};
use super::intentional_boundary_ast_outcome::{AstDerivationError, ast_parser_rejected};

const LANGUAGE: &str = "rust";

pub fn census_intentional_boundary_rust_ast(
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
        LANGUAGE,
        rust_syntax_facts,
    )
}

pub fn validate_intentional_boundary_rust_ast_census(
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
        LANGUAGE,
        rust_syntax_facts,
    )
}

pub(super) fn derive_rust_ast_census(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    files: &[crate::types::FileRecord],
) -> Result<IntentionalBoundaryAstCensus, AstDerivationError> {
    derive_language_ast_census(
        source_census,
        semantic_census,
        files,
        LANGUAGE,
        rust_syntax_facts,
    )
}

pub(super) fn rust_syntax_facts(
    repository_path: &str,
    record: &crate::types::FileRecord,
) -> Result<AstMethodSyntaxFacts, AstDerivationError> {
    let file = syn::parse_file(&record.source).map_err(|error| {
        ast_parser_rejected(
            LANGUAGE,
            repository_path,
            format!("failed to parse Rust AST: {error}"),
        )
    })?;
    let mut visitor = RustBodyVisitor {
        repository_path,
        methods: BTreeMap::new(),
    };
    visitor.visit_file(&file);
    Ok(visitor.methods)
}

struct RustBodyVisitor<'a> {
    repository_path: &'a str,
    methods: AstMethodSyntaxFacts,
}

impl RustBodyVisitor<'_> {
    fn record(
        &mut self,
        name: String,
        span: proc_macro2::Span,
        attrs: &[syn::Attribute],
        block: Option<&syn::Block>,
    ) {
        let key = (name, span.start().line);
        let fact = AstMethodSyntaxFact {
            end_line: span.end().line,
            thin_delegation: block
                .and_then(thin_delegation_expression)
                .map(|expression| span_range(self.repository_path, expression.span())),
            distinct_retry_outcomes: block.and_then(distinct_retry_outcomes).map(
                |(retryable, terminal)| {
                    (
                        span_range(self.repository_path, retryable),
                        span_range(self.repository_path, terminal),
                    )
                },
            ),
            generator_marker: None,
            versioned_compatibility_source_contract: versioned_compatibility_annotation(attrs)
                .map(|attribute| span_range(self.repository_path, attribute.span())),
            versioned_compatibility_compiler_references: Vec::new(),
        };
        self.methods.insert(key, fact);
    }
}

impl<'ast> Visit<'ast> for RustBodyVisitor<'_> {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.record(
            node.sig.ident.to_string(),
            node.span(),
            &node.attrs,
            Some(&node.block),
        );
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.record(
            node.sig.ident.to_string(),
            node.span(),
            &node.attrs,
            Some(&node.block),
        );
        syn::visit::visit_impl_item_fn(self, node);
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        self.record(
            node.sig.ident.to_string(),
            node.span(),
            &node.attrs,
            node.default.as_ref(),
        );
        syn::visit::visit_trait_item_fn(self, node);
    }

    fn visit_foreign_item_fn(&mut self, node: &'ast syn::ForeignItemFn) {
        self.record(node.sig.ident.to_string(), node.span(), &node.attrs, None);
        syn::visit::visit_foreign_item_fn(self, node);
    }
}

fn distinct_retry_outcomes(block: &syn::Block) -> Option<(proc_macro2::Span, proc_macro2::Span)> {
    let mut visitor = RetryLoopVisitor::default();
    visitor.visit_block(block);
    visitor.outcomes
}

#[derive(Default)]
struct RetryLoopVisitor {
    outcomes: Option<(proc_macro2::Span, proc_macro2::Span)>,
}

impl<'ast> Visit<'ast> for RetryLoopVisitor {
    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        if self.outcomes.is_some() {
            return;
        }
        let loop_label = node
            .label
            .as_ref()
            .map(|label| label.name.ident.to_string());
        let mut visitor = LoopMatchVisitor {
            loop_label: loop_label.as_deref(),
            outcomes: None,
        };
        visitor.visit_block(&node.body);
        self.outcomes = visitor.outcomes;
    }

    fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {}

    fn visit_expr_async(&mut self, _node: &'ast syn::ExprAsync) {}
}

struct LoopMatchVisitor<'a> {
    loop_label: Option<&'a str>,
    outcomes: Option<(proc_macro2::Span, proc_macro2::Span)>,
}

impl<'ast> Visit<'ast> for LoopMatchVisitor<'_> {
    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        if self.outcomes.is_some() {
            return;
        }
        let mut retryable = Vec::new();
        let mut terminal = Vec::new();
        for (arm_index, arm) in node.arms.iter().enumerate() {
            let mut flow = BranchFlowVisitor {
                loop_label: self.loop_label,
                retryable: false,
                terminal: false,
            };
            flow.visit_expr(&arm.body);
            if flow.retryable {
                retryable.push((arm_index, arm.body.span()));
            }
            if flow.terminal {
                terminal.push((arm_index, arm.body.span()));
            }
        }
        if let Some((retryable, terminal)) =
            retryable.iter().find_map(|(retry_index, retry_span)| {
                terminal
                    .iter()
                    .find(|(terminal_index, _)| terminal_index != retry_index)
                    .map(|(_, terminal_span)| (*retry_span, *terminal_span))
            })
        {
            self.outcomes = Some((retryable, terminal));
            return;
        }
        syn::visit::visit_expr_match(self, node);
    }

    fn visit_expr_loop(&mut self, _node: &'ast syn::ExprLoop) {}

    fn visit_expr_while(&mut self, _node: &'ast syn::ExprWhile) {}

    fn visit_expr_for_loop(&mut self, _node: &'ast syn::ExprForLoop) {}

    fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {}

    fn visit_expr_async(&mut self, _node: &'ast syn::ExprAsync) {}
}

struct BranchFlowVisitor<'a> {
    loop_label: Option<&'a str>,
    retryable: bool,
    terminal: bool,
}

impl Visit<'_> for BranchFlowVisitor<'_> {
    fn visit_expr_continue(&mut self, node: &syn::ExprContinue) {
        if flow_targets_loop(node.label.as_ref(), self.loop_label) {
            self.retryable = true;
        }
    }

    fn visit_expr_break(&mut self, node: &syn::ExprBreak) {
        if flow_targets_loop(node.label.as_ref(), self.loop_label) {
            self.terminal = true;
        }
    }

    fn visit_expr_return(&mut self, _node: &syn::ExprReturn) {
        self.terminal = true;
    }

    fn visit_expr_loop(&mut self, _node: &syn::ExprLoop) {}

    fn visit_expr_while(&mut self, _node: &syn::ExprWhile) {}

    fn visit_expr_for_loop(&mut self, _node: &syn::ExprForLoop) {}

    fn visit_expr_closure(&mut self, _node: &syn::ExprClosure) {}

    fn visit_expr_async(&mut self, _node: &syn::ExprAsync) {}
}

fn flow_targets_loop(label: Option<&syn::Lifetime>, loop_label: Option<&str>) -> bool {
    match label {
        None => true,
        Some(label) => loop_label == Some(label.ident.to_string().as_str()),
    }
}

fn versioned_compatibility_annotation(attrs: &[syn::Attribute]) -> Option<&syn::Attribute> {
    attrs.iter().find(|attribute| {
        if !attribute.path().is_ident("deprecated") {
            return false;
        }
        let mut versioned = false;
        attribute
            .parse_nested_meta(|meta| {
                if meta.path.is_ident("since") {
                    let value = meta.value()?;
                    let version: syn::LitStr = value.parse()?;
                    versioned = !version.value().trim().is_empty();
                } else if meta.path.is_ident("note") {
                    let value = meta.value()?;
                    let _: syn::LitStr = value.parse()?;
                } else {
                    return Err(meta.error("unsupported deprecated attribute field"));
                }
                Ok(())
            })
            .is_ok()
            && versioned
    })
}

fn thin_delegation_expression(block: &syn::Block) -> Option<&syn::Expr> {
    let [statement] = block.stmts.as_slice() else {
        return None;
    };
    let syn::Stmt::Expr(expression, _) = statement else {
        return None;
    };
    forwarding_call(expression)
}

fn forwarding_call(expression: &syn::Expr) -> Option<&syn::Expr> {
    match expression {
        syn::Expr::Call(_) | syn::Expr::MethodCall(_) => Some(expression),
        syn::Expr::Await(value) => forwarding_call(&value.base),
        syn::Expr::Group(value) => forwarding_call(&value.expr),
        syn::Expr::Paren(value) => forwarding_call(&value.expr),
        syn::Expr::Return(value) => value.expr.as_deref().and_then(forwarding_call),
        syn::Expr::Try(value) => forwarding_call(&value.expr),
        _ => None,
    }
}

fn span_range(repository_path: &str, span: proc_macro2::Span) -> IntentionalBoundarySemanticRange {
    IntentionalBoundarySemanticRange {
        repository_path: repository_path.to_string(),
        start_line_zero_based: span.start().line.saturating_sub(1) as u32,
        start_character_zero_based: span.start().column as u32,
        end_line_zero_based: span.end().line.saturating_sub(1) as u32,
        end_character_zero_based: span.end().column as u32,
    }
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_ast_rust_tests.rs"]
mod tests;
