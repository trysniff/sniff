use tree_sitter::Node;

pub(super) fn find_retry_loop<'tree>(
    node: Node<'tree>,
    source: &[u8],
) -> Option<(Node<'tree>, Node<'tree>)> {
    if is_callable_scope(node) {
        return None;
    }
    if node.kind() == "labeled_statement"
        && let Some(loop_node) = labeled_loop(node)
    {
        let label = node
            .child_by_field_name("label")
            .and_then(|label| label.utf8_text(source).ok())?;
        return iteration_outcomes(loop_node, Some(label), source).or_else(|| {
            loop_node
                .child_by_field_name("body")
                .and_then(|body| find_retry_loop(body, source))
        });
    }
    if node.kind() == "for_statement" {
        return iteration_outcomes(node, None, source).or_else(|| {
            node.child_by_field_name("body")
                .and_then(|body| find_retry_loop(body, source))
        });
    }
    named_children(node).find_map(|child| find_retry_loop(child, source))
}

fn iteration_outcomes<'tree>(
    loop_node: Node<'tree>,
    loop_label: Option<&str>,
    source: &[u8],
) -> Option<(Node<'tree>, Node<'tree>)> {
    let body = loop_node.child_by_field_name("body")?;
    outcomes_in_loop(body, loop_label, source)
}

fn outcomes_in_loop<'tree>(
    node: Node<'tree>,
    loop_label: Option<&str>,
    source: &[u8],
) -> Option<(Node<'tree>, Node<'tree>)> {
    match node.kind() {
        "if_statement" => {
            let direct = node
                .child_by_field_name("alternative")
                .and_then(|alternative| {
                    distinct_branch_outcomes([
                        branch_flow(
                            node.child_by_field_name("consequence")?,
                            loop_label,
                            source,
                            0,
                        ),
                        branch_flow(alternative, loop_label, source, 0),
                    ])
                });
            direct.or_else(|| {
                branch_nodes(node).find_map(|branch| outcomes_in_loop(branch, loop_label, source))
            })
        }
        "expression_switch_statement" | "type_switch_statement" | "select_statement" => {
            let branches = branch_nodes(node).collect::<Vec<_>>();
            let direct = distinct_branch_outcomes(
                branches
                    .iter()
                    .map(|branch| branch_flow(*branch, loop_label, source, 1)),
            );
            direct.or_else(|| {
                branches
                    .into_iter()
                    .find_map(|branch| outcomes_in_loop(branch, loop_label, source))
            })
        }
        "for_statement" | "func_literal" | "function_declaration" | "method_declaration" => None,
        _ => named_children(node).find_map(|child| outcomes_in_loop(child, loop_label, source)),
    }
}

#[derive(Clone, Copy, Default)]
struct BranchFlow<'tree> {
    retryable: Option<Node<'tree>>,
    terminal: Option<Node<'tree>>,
}

fn distinct_branch_outcomes<'tree>(
    branches: impl IntoIterator<Item = BranchFlow<'tree>>,
) -> Option<(Node<'tree>, Node<'tree>)> {
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

fn branch_flow<'tree>(
    node: Node<'tree>,
    loop_label: Option<&str>,
    source: &[u8],
    breakable_depth: usize,
) -> BranchFlow<'tree> {
    match node.kind() {
        "continue_statement" if flow_targets_loop(statement_label(node, source), loop_label) => {
            BranchFlow {
                retryable: Some(node),
                terminal: None,
            }
        }
        "break_statement"
            if break_targets_loop(statement_label(node, source), loop_label, breakable_depth) =>
        {
            BranchFlow {
                retryable: None,
                terminal: Some(node),
            }
        }
        "return_statement" => BranchFlow {
            retryable: None,
            terminal: Some(node),
        },
        "for_statement" | "func_literal" | "function_declaration" | "method_declaration" => {
            BranchFlow::default()
        }
        "expression_switch_statement" | "type_switch_statement" | "select_statement" => {
            merge_children(node, loop_label, source, breakable_depth + 1)
        }
        _ => merge_children(node, loop_label, source, breakable_depth),
    }
}

fn merge_children<'tree>(
    node: Node<'tree>,
    loop_label: Option<&str>,
    source: &[u8],
    breakable_depth: usize,
) -> BranchFlow<'tree> {
    let mut flow = BranchFlow::default();
    for child in named_children(node) {
        merge_flow(
            &mut flow,
            branch_flow(child, loop_label, source, breakable_depth),
        );
    }
    flow
}

fn merge_flow<'tree>(flow: &mut BranchFlow<'tree>, nested: BranchFlow<'tree>) {
    if flow.retryable.is_none() {
        flow.retryable = nested.retryable;
    }
    if flow.terminal.is_none() {
        flow.terminal = nested.terminal;
    }
}

fn flow_targets_loop(label: Option<&str>, loop_label: Option<&str>) -> bool {
    label.is_none() || label == loop_label
}

fn break_targets_loop(
    label: Option<&str>,
    loop_label: Option<&str>,
    breakable_depth: usize,
) -> bool {
    match label {
        Some(label) => Some(label) == loop_label,
        None => breakable_depth == 0,
    }
}

fn statement_label<'source>(node: Node<'_>, source: &'source [u8]) -> Option<&'source str> {
    named_children(node)
        .find(|child| child.kind() == "label_name")
        .and_then(|label| label.utf8_text(source).ok())
}

fn labeled_loop(node: Node<'_>) -> Option<Node<'_>> {
    named_children(node).find(|child| child.kind() == "for_statement")
}

fn branch_nodes(node: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    named_children(node).filter(|child| {
        matches!(
            child.kind(),
            "block"
                | "if_statement"
                | "expression_case"
                | "type_case"
                | "communication_case"
                | "default_case"
        )
    })
}

fn named_children(node: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .collect::<Vec<_>>()
        .into_iter()
}

fn is_callable_scope(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "func_literal" | "function_declaration" | "method_declaration"
    )
}
