use oxc_ast::ast::Statement;
use oxc_span::Span;

pub(super) fn find_retry_loop(statements: &[Statement<'_>]) -> Option<(Span, Span)> {
    statements.iter().find_map(find_retry_loop_in_statement)
}

fn find_retry_loop_in_statement(statement: &Statement<'_>) -> Option<(Span, Span)> {
    match statement {
        Statement::DoWhileStatement(_)
        | Statement::WhileStatement(_)
        | Statement::ForStatement(_)
        | Statement::ForInStatement(_)
        | Statement::ForOfStatement(_) => iteration_outcomes(statement, None),
        Statement::LabeledStatement(node) if node.body.is_iteration_statement() => {
            iteration_outcomes(&node.body, Some(node.label.name.as_str()))
        }
        Statement::BlockStatement(node) => find_retry_loop(&node.body),
        Statement::IfStatement(node) => {
            find_retry_loop_in_statement(&node.consequent).or_else(|| {
                node.alternate
                    .as_ref()
                    .and_then(find_retry_loop_in_statement)
            })
        }
        Statement::LabeledStatement(node) => find_retry_loop_in_statement(&node.body),
        Statement::SwitchStatement(node) => node
            .cases
            .iter()
            .find_map(|case| find_retry_loop(&case.consequent)),
        Statement::TryStatement(node) => find_retry_loop(&node.block.body)
            .or_else(|| {
                node.handler
                    .as_ref()
                    .and_then(|handler| find_retry_loop(&handler.body.body))
            })
            .or_else(|| {
                node.finalizer
                    .as_ref()
                    .and_then(|finalizer| find_retry_loop(&finalizer.body))
            }),
        Statement::WithStatement(node) => find_retry_loop_in_statement(&node.body),
        _ => None,
    }
}

fn iteration_outcomes(statement: &Statement<'_>, loop_label: Option<&str>) -> Option<(Span, Span)> {
    match statement {
        Statement::DoWhileStatement(node) => loop_outcomes(&node.body, loop_label),
        Statement::WhileStatement(node) => loop_outcomes(&node.body, loop_label),
        Statement::ForStatement(node) => loop_outcomes(&node.body, loop_label),
        Statement::ForInStatement(node) => loop_outcomes(&node.body, loop_label),
        Statement::ForOfStatement(node) => loop_outcomes(&node.body, loop_label),
        _ => None,
    }
}

fn loop_outcomes(body: &Statement<'_>, loop_label: Option<&str>) -> Option<(Span, Span)> {
    outcomes_in_loop_statement(body, loop_label).or_else(|| find_retry_loop_in_statement(body))
}

fn outcomes_in_loop(
    statements: &[Statement<'_>],
    loop_label: Option<&str>,
) -> Option<(Span, Span)> {
    statements
        .iter()
        .find_map(|statement| outcomes_in_loop_statement(statement, loop_label))
}

fn outcomes_in_loop_statement(
    statement: &Statement<'_>,
    loop_label: Option<&str>,
) -> Option<(Span, Span)> {
    match statement {
        Statement::BlockStatement(node) => outcomes_in_loop(&node.body, loop_label),
        Statement::IfStatement(node) => {
            let direct = node.alternate.as_ref().and_then(|alternate| {
                distinct_branch_outcomes([
                    branch_flow(&node.consequent, loop_label, 0),
                    branch_flow(alternate, loop_label, 0),
                ])
            });
            direct
                .or_else(|| outcomes_in_loop_statement(&node.consequent, loop_label))
                .or_else(|| {
                    node.alternate
                        .as_ref()
                        .and_then(|alternate| outcomes_in_loop_statement(alternate, loop_label))
                })
        }
        Statement::SwitchStatement(node) => {
            let direct = distinct_branch_outcomes(
                node.cases
                    .iter()
                    .map(|case| branch_flow_statements(&case.consequent, loop_label, 1)),
            );
            direct.or_else(|| {
                node.cases
                    .iter()
                    .find_map(|case| outcomes_in_loop(&case.consequent, loop_label))
            })
        }
        Statement::TryStatement(node) => {
            let direct = if node.finalizer.is_none() {
                node.handler.as_ref().and_then(|handler| {
                    distinct_branch_outcomes([
                        branch_flow_statements(&node.block.body, loop_label, 0),
                        branch_flow_statements(&handler.body.body, loop_label, 0),
                    ])
                })
            } else {
                None
            };
            direct
                .or_else(|| outcomes_in_loop(&node.block.body, loop_label))
                .or_else(|| {
                    node.handler
                        .as_ref()
                        .and_then(|handler| outcomes_in_loop(&handler.body.body, loop_label))
                })
                .or_else(|| {
                    node.finalizer
                        .as_ref()
                        .and_then(|finalizer| outcomes_in_loop(&finalizer.body, loop_label))
                })
        }
        Statement::LabeledStatement(node) => outcomes_in_loop_statement(&node.body, loop_label),
        Statement::WithStatement(node) => outcomes_in_loop_statement(&node.body, loop_label),
        Statement::DoWhileStatement(_)
        | Statement::WhileStatement(_)
        | Statement::ForStatement(_)
        | Statement::ForInStatement(_)
        | Statement::ForOfStatement(_) => None,
        _ => None,
    }
}

#[derive(Clone, Copy, Default)]
struct BranchFlow {
    retryable: Option<Span>,
    terminal: Option<Span>,
}

fn distinct_branch_outcomes(
    branches: impl IntoIterator<Item = BranchFlow>,
) -> Option<(Span, Span)> {
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

fn branch_flow_statements(
    statements: &[Statement<'_>],
    loop_label: Option<&str>,
    switch_depth: usize,
) -> BranchFlow {
    let mut flow = BranchFlow::default();
    for statement in statements {
        merge_flow(&mut flow, branch_flow(statement, loop_label, switch_depth));
    }
    flow
}

fn branch_flow(
    statement: &Statement<'_>,
    loop_label: Option<&str>,
    switch_depth: usize,
) -> BranchFlow {
    match statement {
        Statement::ContinueStatement(node)
            if flow_targets_loop(
                node.label.as_ref().map(|label| label.name.as_str()),
                loop_label,
            ) =>
        {
            BranchFlow {
                retryable: Some(node.span),
                terminal: None,
            }
        }
        Statement::BreakStatement(node)
            if break_targets_loop(
                node.label.as_ref().map(|label| label.name.as_str()),
                loop_label,
                switch_depth,
            ) =>
        {
            BranchFlow {
                retryable: None,
                terminal: Some(node.span),
            }
        }
        Statement::ReturnStatement(node) => BranchFlow {
            retryable: None,
            terminal: Some(node.span),
        },
        Statement::ThrowStatement(node) => BranchFlow {
            retryable: None,
            terminal: Some(node.span),
        },
        Statement::BlockStatement(node) => {
            branch_flow_statements(&node.body, loop_label, switch_depth)
        }
        Statement::IfStatement(node) => {
            let mut flow = branch_flow(&node.consequent, loop_label, switch_depth);
            if let Some(alternate) = &node.alternate {
                merge_flow(&mut flow, branch_flow(alternate, loop_label, switch_depth));
            }
            flow
        }
        Statement::LabeledStatement(node) => branch_flow(&node.body, loop_label, switch_depth),
        Statement::SwitchStatement(node) => {
            let mut flow = BranchFlow::default();
            for case in &node.cases {
                merge_flow(
                    &mut flow,
                    branch_flow_statements(&case.consequent, loop_label, switch_depth + 1),
                );
            }
            flow
        }
        Statement::TryStatement(node) => {
            let mut flow = branch_flow_statements(&node.block.body, loop_label, switch_depth);
            if let Some(handler) = &node.handler {
                merge_flow(
                    &mut flow,
                    branch_flow_statements(&handler.body.body, loop_label, switch_depth),
                );
            }
            if let Some(finalizer) = &node.finalizer {
                merge_flow(
                    &mut flow,
                    branch_flow_statements(&finalizer.body, loop_label, switch_depth),
                );
            }
            flow
        }
        Statement::WithStatement(node) => branch_flow(&node.body, loop_label, switch_depth),
        Statement::DoWhileStatement(_)
        | Statement::WhileStatement(_)
        | Statement::ForStatement(_)
        | Statement::ForInStatement(_)
        | Statement::ForOfStatement(_) => BranchFlow::default(),
        _ => BranchFlow::default(),
    }
}

fn flow_targets_loop(label: Option<&str>, loop_label: Option<&str>) -> bool {
    label.is_none() || label == loop_label
}

fn break_targets_loop(label: Option<&str>, loop_label: Option<&str>, switch_depth: usize) -> bool {
    match label {
        Some(label) => Some(label) == loop_label,
        None => switch_depth == 0,
    }
}

fn merge_flow(flow: &mut BranchFlow, nested: BranchFlow) {
    if flow.retryable.is_none() {
        flow.retryable = nested.retryable;
    }
    if flow.terminal.is_none() {
        flow.terminal = nested.terminal;
    }
}
