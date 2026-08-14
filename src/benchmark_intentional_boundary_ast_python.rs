use super::{
    IntentionalBoundaryAstCensus, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticRange,
    IntentionalBoundarySourceCensus,
};
use rustpython_ast::{Expr, Stmt, Visitor, text_size::TextRange};
use std::collections::BTreeMap;
use std::path::Path;

#[cfg(test)]
use super::intentional_boundary_ast::derive_language_ast_census;
use super::intentional_boundary_ast::{
    AstMethodSyntaxFact, AstMethodSyntaxFacts, census_language_ast, validate_language_ast,
};

const LANGUAGE: &str = "python";

pub fn census_intentional_boundary_python_ast(
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
        python_syntax_facts,
    )
}

pub fn validate_intentional_boundary_python_ast_census(
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
        python_syntax_facts,
    )
}

#[cfg(test)]
fn derive_python_ast_census(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    files: &[crate::types::FileRecord],
) -> Result<IntentionalBoundaryAstCensus, String> {
    derive_language_ast_census(
        source_census,
        semantic_census,
        files,
        LANGUAGE,
        python_syntax_facts,
    )
}

fn python_syntax_facts(
    repository_path: &str,
    source: &str,
) -> Result<AstMethodSyntaxFacts, String> {
    let parsed = rustpython_parser::parse(source, rustpython_parser::Mode::Module, repository_path)
        .map_err(|error| format!("failed to parse Python AST {repository_path}: {error}"))?;
    let rustpython_ast::Mod::Module(module) = parsed else {
        return Err(format!(
            "failed to parse Python AST {repository_path}: source is not a module"
        ));
    };
    let mut visitor = PythonBodyVisitor {
        repository_path,
        line_starts: line_starts(source),
        methods: BTreeMap::new(),
    };
    for statement in module.body {
        visitor.visit_stmt(statement);
    }
    Ok(visitor.methods)
}

struct PythonBodyVisitor<'a> {
    repository_path: &'a str,
    line_starts: Vec<usize>,
    methods: AstMethodSyntaxFacts,
}

impl PythonBodyVisitor<'_> {
    fn record(&mut self, name: String, range: TextRange, body: &[Stmt]) {
        let (start_line, end_line) = method_lines(range, &self.line_starts);
        let fact = AstMethodSyntaxFact {
            end_line,
            thin_delegation: thin_delegation_expression(body)
                .map(|expression| text_range(self.repository_path, expression, &self.line_starts)),
        };
        self.methods.insert((name, start_line), fact);
    }
}

impl Visitor for PythonBodyVisitor<'_> {
    fn visit_stmt_function_def(&mut self, node: rustpython_ast::StmtFunctionDef) {
        self.record(node.name.to_string(), node.range, &node.body);
        self.generic_visit_stmt_function_def(node);
    }

    fn visit_stmt_async_function_def(&mut self, node: rustpython_ast::StmtAsyncFunctionDef) {
        self.record(node.name.to_string(), node.range, &node.body);
        self.generic_visit_stmt_async_function_def(node);
    }
}

fn thin_delegation_expression(body: &[Stmt]) -> Option<TextRange> {
    let [statement] = body else {
        return None;
    };
    match statement {
        Stmt::Return(value) => value.value.as_deref().and_then(forwarding_call),
        Stmt::Expr(value) => forwarding_call(&value.value),
        _ => None,
    }
}

fn forwarding_call(expression: &Expr) -> Option<TextRange> {
    match expression {
        Expr::Call(value) => Some(value.range),
        Expr::Await(value) => forwarding_call(&value.value),
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

fn method_lines(range: TextRange, starts: &[usize]) -> (usize, usize) {
    let start = u32::from(range.start()) as usize;
    let end = u32::from(range.end()) as usize;
    (
        line_for_offset(start, starts) + 1,
        line_for_offset(end.saturating_sub(1), starts) + 1,
    )
}

fn text_range(
    repository_path: &str,
    range: TextRange,
    starts: &[usize],
) -> IntentionalBoundarySemanticRange {
    let start = u32::from(range.start()) as usize;
    let end = u32::from(range.end()) as usize;
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

fn line_for_offset(offset: usize, starts: &[usize]) -> usize {
    starts
        .partition_point(|start| *start <= offset)
        .saturating_sub(1)
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_ast_python_tests.rs"]
mod tests;
