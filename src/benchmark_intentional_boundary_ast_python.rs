use super::{
    IntentionalBoundaryAstCensus, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticRange,
    IntentionalBoundarySourceCensus,
};
use rustpython_ast::{ExceptHandler, Expr, Ranged, Stmt, Visitor, text_size::TextRange};
use std::collections::BTreeMap;
use std::path::Path;

#[cfg(test)]
use super::intentional_boundary_ast::derive_language_ast_census;
use super::intentional_boundary_ast::{
    AstMethodSyntaxFact, AstMethodSyntaxFacts, census_language_ast, validate_language_ast,
};
use super::intentional_boundary_ast_compiler_references::{
    AstCompilerReferenceIdentity, AstCompilerReferenceRequirement,
};
use super::intentional_boundary_ast_python_compatibility::versioned_compatibility_contract;

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
pub(super) fn derive_python_ast_census(
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
    record: &crate::types::FileRecord,
) -> Result<AstMethodSyntaxFacts, String> {
    let source = &record.source;
    let parsed = rustpython_parser::parse(source, rustpython_parser::Mode::Module, repository_path)
        .map_err(|error| format!("failed to parse Python AST {repository_path}: {error}"))?;
    let rustpython_ast::Mod::Module(module) = parsed else {
        return Err(format!(
            "failed to parse Python AST {repository_path}: source is not a module"
        ));
    };
    let mut visitor = PythonBodyVisitor {
        repository_path,
        source,
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
    source: &'a str,
    line_starts: Vec<usize>,
    methods: AstMethodSyntaxFacts,
}

impl PythonBodyVisitor<'_> {
    fn record(&mut self, name: String, range: TextRange, body: &[Stmt]) {
        let (start_line, end_line) = method_lines(range, &self.line_starts);
        let compatibility = versioned_compatibility_contract(self.source, body);
        let fact = AstMethodSyntaxFact {
            end_line,
            thin_delegation: thin_delegation_expression(body)
                .map(|expression| text_range(self.repository_path, expression, &self.line_starts)),
            distinct_retry_outcomes: distinct_retry_outcomes(body).map(|(retryable, terminal)| {
                (
                    text_range(self.repository_path, retryable, &self.line_starts),
                    text_range(self.repository_path, terminal, &self.line_starts),
                )
            }),
            generator_marker: None,
            versioned_compatibility_source_contract: compatibility
                .as_ref()
                .map(|value| text_range(self.repository_path, value.contract, &self.line_starts)),
            versioned_compatibility_compiler_references: compatibility
                .map(|value| {
                    vec![
                        AstCompilerReferenceRequirement {
                            range: text_range(
                                self.repository_path,
                                value.warnings_warn,
                                &self.line_starts,
                            ),
                            identity: AstCompilerReferenceIdentity::PythonWarningsWarn,
                        },
                        AstCompilerReferenceRequirement {
                            range: text_range(
                                self.repository_path,
                                value.deprecation_warning,
                                &self.line_starts,
                            ),
                            identity: AstCompilerReferenceIdentity::PythonDeprecationWarning,
                        },
                    ]
                })
                .unwrap_or_default(),
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

fn distinct_retry_outcomes(body: &[Stmt]) -> Option<(TextRange, TextRange)> {
    find_retry_loop(body)
}

fn find_retry_loop(statements: &[Stmt]) -> Option<(TextRange, TextRange)> {
    for statement in statements {
        let outcome = match statement {
            Stmt::For(node) => outcomes_in_loop(&node.body)
                .or_else(|| find_retry_loop(&node.body))
                .or_else(|| find_retry_loop(&node.orelse)),
            Stmt::AsyncFor(node) => outcomes_in_loop(&node.body)
                .or_else(|| find_retry_loop(&node.body))
                .or_else(|| find_retry_loop(&node.orelse)),
            Stmt::While(node) => outcomes_in_loop(&node.body)
                .or_else(|| find_retry_loop(&node.body))
                .or_else(|| find_retry_loop(&node.orelse)),
            Stmt::If(node) => find_retry_loop(&node.body).or_else(|| find_retry_loop(&node.orelse)),
            Stmt::With(node) => find_retry_loop(&node.body),
            Stmt::AsyncWith(node) => find_retry_loop(&node.body),
            Stmt::Match(node) => node
                .cases
                .iter()
                .find_map(|case| find_retry_loop(&case.body)),
            Stmt::Try(node) => find_retry_loop(&node.body)
                .or_else(|| {
                    node.handlers
                        .iter()
                        .find_map(|handler| find_retry_loop(except_body(handler)))
                })
                .or_else(|| find_retry_loop(&node.orelse))
                .or_else(|| find_retry_loop(&node.finalbody)),
            Stmt::TryStar(node) => find_retry_loop(&node.body)
                .or_else(|| {
                    node.handlers
                        .iter()
                        .find_map(|handler| find_retry_loop(except_body(handler)))
                })
                .or_else(|| find_retry_loop(&node.orelse))
                .or_else(|| find_retry_loop(&node.finalbody)),
            Stmt::FunctionDef(_) | Stmt::AsyncFunctionDef(_) | Stmt::ClassDef(_) => None,
            _ => None,
        };
        if outcome.is_some() {
            return outcome;
        }
    }
    None
}

fn outcomes_in_loop(statements: &[Stmt]) -> Option<(TextRange, TextRange)> {
    for statement in statements {
        let outcomes = match statement {
            Stmt::If(node) if !node.orelse.is_empty() => {
                distinct_branch_outcomes([branch_flow(&node.body), branch_flow(&node.orelse)])
            }
            Stmt::Match(node) => distinct_branch_outcomes(
                node.cases
                    .iter()
                    .map(|case| branch_flow(&case.body))
                    .collect::<Vec<_>>(),
            ),
            Stmt::Try(node) if node.finalbody.is_empty() => {
                distinct_try_outcomes(&node.body, &node.orelse, &node.handlers)
            }
            Stmt::TryStar(node) if node.finalbody.is_empty() => {
                distinct_try_outcomes(&node.body, &node.orelse, &node.handlers)
            }
            _ => None,
        };
        if outcomes.is_some() {
            return outcomes;
        }
        let nested = match statement {
            Stmt::If(node) => {
                outcomes_in_loop(&node.body).or_else(|| outcomes_in_loop(&node.orelse))
            }
            Stmt::With(node) => outcomes_in_loop(&node.body),
            Stmt::AsyncWith(node) => outcomes_in_loop(&node.body),
            Stmt::Match(node) => node
                .cases
                .iter()
                .find_map(|case| outcomes_in_loop(&case.body)),
            Stmt::Try(node) => outcomes_in_loop(&node.body)
                .or_else(|| {
                    node.handlers
                        .iter()
                        .find_map(|handler| outcomes_in_loop(except_body(handler)))
                })
                .or_else(|| outcomes_in_loop(&node.orelse))
                .or_else(|| outcomes_in_loop(&node.finalbody)),
            Stmt::TryStar(node) => outcomes_in_loop(&node.body)
                .or_else(|| {
                    node.handlers
                        .iter()
                        .find_map(|handler| outcomes_in_loop(except_body(handler)))
                })
                .or_else(|| outcomes_in_loop(&node.orelse))
                .or_else(|| outcomes_in_loop(&node.finalbody)),
            Stmt::For(_)
            | Stmt::AsyncFor(_)
            | Stmt::While(_)
            | Stmt::FunctionDef(_)
            | Stmt::AsyncFunctionDef(_)
            | Stmt::ClassDef(_) => None,
            _ => None,
        };
        if nested.is_some() {
            return nested;
        }
    }
    None
}

#[derive(Clone, Copy, Default)]
struct BranchFlow {
    retryable: Option<TextRange>,
    terminal: Option<TextRange>,
}

fn distinct_try_outcomes(
    body: &[Stmt],
    orelse: &[Stmt],
    handlers: &[ExceptHandler],
) -> Option<(TextRange, TextRange)> {
    let mut success = branch_flow(body);
    merge_flow(&mut success, branch_flow(orelse));
    let mut branches = vec![success];
    branches.extend(
        handlers
            .iter()
            .map(|handler| branch_flow(except_body(handler))),
    );
    distinct_branch_outcomes(branches)
}

fn distinct_branch_outcomes(
    branches: impl IntoIterator<Item = BranchFlow>,
) -> Option<(TextRange, TextRange)> {
    let branches = branches.into_iter().collect::<Vec<_>>();
    for (retry_index, retry_branch) in branches.iter().enumerate() {
        let Some(retryable) = retry_branch.retryable else {
            continue;
        };
        if let Some(terminal) = branches
            .iter()
            .enumerate()
            .find(|(terminal_index, branch)| {
                *terminal_index != retry_index && branch.terminal.is_some()
            })
            .and_then(|(_, branch)| branch.terminal)
        {
            return Some((retryable, terminal));
        }
    }
    None
}

fn branch_flow(statements: &[Stmt]) -> BranchFlow {
    let mut flow = BranchFlow::default();
    for statement in statements {
        match statement {
            Stmt::Continue(_) => {
                flow.retryable.get_or_insert(statement.range());
            }
            Stmt::Return(_) | Stmt::Raise(_) | Stmt::Break(_) => {
                flow.terminal.get_or_insert(statement.range());
            }
            Stmt::If(node) => {
                merge_flow(&mut flow, branch_flow(&node.body));
                merge_flow(&mut flow, branch_flow(&node.orelse));
            }
            Stmt::With(node) => merge_flow(&mut flow, branch_flow(&node.body)),
            Stmt::AsyncWith(node) => merge_flow(&mut flow, branch_flow(&node.body)),
            Stmt::Match(node) => {
                for case in &node.cases {
                    merge_flow(&mut flow, branch_flow(&case.body));
                }
            }
            Stmt::Try(node) => {
                merge_flow(&mut flow, branch_flow(&node.body));
                for handler in &node.handlers {
                    merge_flow(&mut flow, branch_flow(except_body(handler)));
                }
                merge_flow(&mut flow, branch_flow(&node.orelse));
                merge_flow(&mut flow, branch_flow(&node.finalbody));
            }
            Stmt::TryStar(node) => {
                merge_flow(&mut flow, branch_flow(&node.body));
                for handler in &node.handlers {
                    merge_flow(&mut flow, branch_flow(except_body(handler)));
                }
                merge_flow(&mut flow, branch_flow(&node.orelse));
                merge_flow(&mut flow, branch_flow(&node.finalbody));
            }
            Stmt::For(_)
            | Stmt::AsyncFor(_)
            | Stmt::While(_)
            | Stmt::FunctionDef(_)
            | Stmt::AsyncFunctionDef(_)
            | Stmt::ClassDef(_) => {}
            _ => {}
        }
    }
    flow
}

fn merge_flow(flow: &mut BranchFlow, nested: BranchFlow) {
    if flow.retryable.is_none() {
        flow.retryable = nested.retryable;
    }
    if flow.terminal.is_none() {
        flow.terminal = nested.terminal;
    }
}

fn except_body(handler: &ExceptHandler) -> &[Stmt] {
    let ExceptHandler::ExceptHandler(handler) = handler;
    &handler.body
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
