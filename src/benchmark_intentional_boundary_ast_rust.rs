use super::{
    IntentionalBoundaryAstCensus, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticRange,
    IntentionalBoundarySourceCensus,
};
use std::collections::BTreeMap;
use std::path::Path;
use syn::spanned::Spanned;
use syn::visit::Visit;

#[cfg(test)]
use super::intentional_boundary_ast::derive_language_ast_census;
use super::intentional_boundary_ast::{
    AstMethodSyntaxFact, AstMethodSyntaxFacts, census_language_ast, validate_language_ast,
};

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

#[cfg(test)]
fn derive_rust_ast_census(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    files: &[crate::types::FileRecord],
) -> Result<IntentionalBoundaryAstCensus, String> {
    derive_language_ast_census(
        source_census,
        semantic_census,
        files,
        LANGUAGE,
        rust_syntax_facts,
    )
}

fn rust_syntax_facts(
    repository_path: &str,
    record: &crate::types::FileRecord,
) -> Result<AstMethodSyntaxFacts, String> {
    let file = syn::parse_file(&record.source)
        .map_err(|error| format!("failed to parse Rust AST {repository_path}: {error}"))?;
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
    fn record(&mut self, name: String, span: proc_macro2::Span, block: Option<&syn::Block>) {
        let key = (name, span.start().line);
        let fact = AstMethodSyntaxFact {
            end_line: span.end().line,
            thin_delegation: block
                .and_then(thin_delegation_expression)
                .map(|expression| span_range(self.repository_path, expression.span())),
        };
        self.methods.insert(key, fact);
    }
}

impl<'ast> Visit<'ast> for RustBodyVisitor<'_> {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.record(node.sig.ident.to_string(), node.span(), Some(&node.block));
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.record(node.sig.ident.to_string(), node.span(), Some(&node.block));
        syn::visit::visit_impl_item_fn(self, node);
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        self.record(
            node.sig.ident.to_string(),
            node.span(),
            node.default.as_ref(),
        );
        syn::visit::visit_trait_item_fn(self, node);
    }

    fn visit_foreign_item_fn(&mut self, node: &'ast syn::ForeignItemFn) {
        self.record(node.sig.ident.to_string(), node.span(), None);
        syn::visit::visit_foreign_item_fn(self, node);
    }
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
