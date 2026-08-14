use super::{
    INTENTIONAL_BOUNDARY_AST_CENSUS_SCHEMA_VERSION, IntentionalBoundaryAstCensus,
    IntentionalBoundaryAstFact, IntentionalBoundaryAstMethod, IntentionalBoundaryAstMethodStatus,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundarySemanticCensus,
    IntentionalBoundarySemanticMethod, IntentionalBoundarySemanticMethodStatus,
    IntentionalBoundarySemanticRange, IntentionalBoundarySemanticResolution,
    IntentionalBoundarySourceCensus, intentional_boundary_file_records,
    validate_intentional_boundary_semantic_census, validate_intentional_boundary_source_census,
};
use crate::types::FileRecord;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;
use syn::spanned::Spanned;
use syn::visit::Visit;

const AST_CONTRACT: &str = "sniffbench-intentional-boundary-source-ast-v1";
type RustMethodKey = (String, usize, usize);
type RustMethodSyntaxFacts = BTreeMap<RustMethodKey, Option<IntentionalBoundarySemanticRange>>;

pub fn census_intentional_boundary_rust_ast(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
) -> Result<IntentionalBoundaryAstCensus, String> {
    validate_intentional_boundary_source_census(
        repository,
        revision,
        root,
        inventory,
        source_census,
    )?;
    validate_intentional_boundary_semantic_census(source_census, semantic_census)?;
    let files = intentional_boundary_file_records(root, inventory, source_census)?;
    derive_rust_ast_census(source_census, semantic_census, &files)
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
    let expected = census_intentional_boundary_rust_ast(
        repository,
        revision,
        root,
        inventory,
        source_census,
        semantic_census,
    )?;
    if ast_census != &expected {
        return Err("intentional-boundary Rust AST census changed".to_string());
    }
    Ok(())
}

fn derive_rust_ast_census(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    files: &[FileRecord],
) -> Result<IntentionalBoundaryAstCensus, String> {
    if files.len() != source_census.source_files.len() {
        return Err("intentional-boundary AST input omitted source files".to_string());
    }
    let semantic_methods = semantic_census
        .methods
        .iter()
        .map(|method| (method.parser_unit_id.as_str(), method))
        .collect::<BTreeMap<_, _>>();
    let mut methods = Vec::new();
    for (source_file, file) in source_census.source_files.iter().zip(files) {
        if source_file.language != file.language {
            return Err(format!(
                "intentional-boundary AST input changed parser language: {}",
                source_file.repository_path
            ));
        }
        if source_file.language != "rust" {
            continue;
        }
        let syntax = rust_syntax_facts(&source_file.repository_path, &file.source)?;
        for source_method in &source_file.methods {
            let semantic_method = semantic_methods
                .get(source_method.parser_unit_id.as_str())
                .ok_or_else(|| {
                    format!(
                        "intentional-boundary AST input omitted semantic method {}",
                        source_method.parser_unit_id
                    )
                })?;
            methods.push(derive_method(source_method, semantic_method, &syntax)?);
        }
    }
    methods.sort_by(|left, right| left.parser_unit_id.cmp(&right.parser_unit_id));
    let fact_count = methods
        .iter()
        .map(|method| match &method.status {
            IntentionalBoundaryAstMethodStatus::Resolved { facts, .. } => facts.len(),
            _ => 0,
        })
        .sum();
    let mut census = IntentionalBoundaryAstCensus {
        schema_version: INTENTIONAL_BOUNDARY_AST_CENSUS_SCHEMA_VERSION,
        ast_contract: AST_CONTRACT.to_string(),
        repository: semantic_census.repository.clone(),
        revision: semantic_census.revision.clone(),
        source_census_sha256: source_census.census_sha256.clone(),
        semantic_census_sha256: semantic_census.semantic_census_sha256.clone(),
        languages: vec!["rust".to_string()],
        method_count: methods.len(),
        fact_count,
        methods,
        ast_census_sha256: String::new(),
    };
    census.ast_census_sha256 = compute_ast_census_sha256(&census)?;
    Ok(census)
}

fn derive_method(
    source_method: &super::IntentionalBoundaryMethodCensusEntry,
    semantic_method: &IntentionalBoundarySemanticMethod,
    syntax: &RustMethodSyntaxFacts,
) -> Result<IntentionalBoundaryAstMethod, String> {
    if semantic_method.symbol_name != source_method.symbol_name
        || semantic_method.start_line != source_method.start_line
        || semantic_method.end_line != source_method.end_line
    {
        return Err(format!(
            "intentional-boundary AST semantic identity changed for {}",
            source_method.parser_unit_id
        ));
    }
    let status = match &semantic_method.status {
        IntentionalBoundarySemanticMethodStatus::Resolved { symbol, .. } => {
            let mut facts = Vec::new();
            if let Some(Some(call_expression)) = syntax.get(&(
                source_method.symbol_name.clone(),
                source_method.start_line,
                source_method.end_line,
            )) {
                let outgoing = semantic_method
                    .calls
                    .iter()
                    .filter(|call| call.caller == symbol.symbol_id)
                    .collect::<Vec<_>>();
                if let [call] = outgoing.as_slice()
                    && let IntentionalBoundarySemanticResolution::Resolved { value: callee } =
                        &call.callee
                    && range_contains(call_expression, &call.callsite)
                {
                    facts.push(IntentionalBoundaryAstFact::ThinDelegation {
                        call_expression: call_expression.clone(),
                        compiler_callsite: call.callsite.clone(),
                        resolved_callee_symbol_id: callee.clone(),
                    });
                }
            }
            IntentionalBoundaryAstMethodStatus::Resolved {
                subject_symbol_id: symbol.symbol_id.clone(),
                facts,
            }
        }
        IntentionalBoundarySemanticMethodStatus::CompilerExcluded { reason } => {
            IntentionalBoundaryAstMethodStatus::CompilerExcluded {
                reason: reason.clone(),
            }
        }
        IntentionalBoundarySemanticMethodStatus::Unresolved {
            reason,
            raw_target,
            detail,
        } => IntentionalBoundaryAstMethodStatus::Unresolved {
            reason: *reason,
            raw_target: raw_target.clone(),
            detail: detail.clone(),
        },
    };
    Ok(IntentionalBoundaryAstMethod {
        parser_unit_id: source_method.parser_unit_id.clone(),
        repository_path: semantic_method.repository_path.clone(),
        language: "rust".to_string(),
        symbol_name: source_method.symbol_name.clone(),
        start_line: source_method.start_line,
        end_line: source_method.end_line,
        status,
    })
}

fn range_contains(
    outer: &IntentionalBoundarySemanticRange,
    inner: &IntentionalBoundarySemanticRange,
) -> bool {
    outer.repository_path == inner.repository_path
        && (
            outer.start_line_zero_based,
            outer.start_character_zero_based,
        ) <= (
            inner.start_line_zero_based,
            inner.start_character_zero_based,
        )
        && (outer.end_line_zero_based, outer.end_character_zero_based)
            >= (inner.end_line_zero_based, inner.end_character_zero_based)
}

fn rust_syntax_facts(repository_path: &str, source: &str) -> Result<RustMethodSyntaxFacts, String> {
    let file = syn::parse_file(source)
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
    methods: RustMethodSyntaxFacts,
}

impl RustBodyVisitor<'_> {
    fn record(&mut self, name: String, span: proc_macro2::Span, block: Option<&syn::Block>) {
        let key = (name, span.start().line, span.end().line);
        let fact = block
            .and_then(thin_delegation_expression)
            .map(|expression| span_range(self.repository_path, expression.span()));
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

fn compute_ast_census_sha256(census: &IntentionalBoundaryAstCensus) -> Result<String, String> {
    let bytes = serde_json::to_vec(&(
        census.schema_version,
        &census.ast_contract,
        &census.repository,
        &census.revision,
        &census.source_census_sha256,
        &census.semantic_census_sha256,
        &census.languages,
        &census.methods,
        census.method_count,
        census.fact_count,
    ))
    .map_err(|error| format!("failed to commit intentional-boundary AST census: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_ast_rust_tests.rs"]
mod tests;
