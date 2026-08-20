use tree_sitter::Node;

pub(super) fn find_retry_loop<'tree>(
    node: Node<'tree>,
    source: &[u8],
) -> Option<(Node<'tree>, Node<'tree>)> {
    if is_callable_scope(node) {
        return None;
    }
    if is_loop(node) {
        let label = loop_label(node, source);
        let body = loop_body(node)?;
        return outcomes_in_loop(body, label, source).or_else(|| find_retry_loop(body, source));
    }
    named_children(node).find_map(|child| find_retry_loop(child, source))
}

fn outcomes_in_loop<'tree>(
    node: Node<'tree>,
    loop_label: Option<&str>,
    source: &[u8],
) -> Option<(Node<'tree>, Node<'tree>)> {
    match node.kind() {
        "if_expression" => {
            let branches = if_branches(node)?;
            let direct = distinct_branch_outcomes(
                branches
                    .iter()
                    .map(|branch| branch_flow(*branch, loop_label, source)),
            );
            direct.or_else(|| {
                branches
                    .into_iter()
                    .find_map(|branch| outcomes_in_loop(branch, loop_label, source))
            })
        }
        "when_expression" => {
            let branches = when_branch_bodies(node).collect::<Vec<_>>();
            let direct = distinct_branch_outcomes(
                branches
                    .iter()
                    .map(|branch| branch_flow(*branch, loop_label, source)),
            );
            direct.or_else(|| {
                branches
                    .into_iter()
                    .find_map(|branch| outcomes_in_loop(branch, loop_label, source))
            })
        }
        "try_expression" => {
            let branches = try_branches(node).collect::<Vec<_>>();
            let direct = (!has_finally(node)).then(|| {
                distinct_branch_outcomes(
                    branches
                        .iter()
                        .map(|branch| branch_flow(*branch, loop_label, source)),
                )
            });
            direct.flatten().or_else(|| {
                branches
                    .into_iter()
                    .find_map(|branch| outcomes_in_loop(branch, loop_label, source))
            })
        }
        kind if is_loop_kind(kind) || is_callable_kind(kind) => None,
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
) -> BranchFlow<'tree> {
    if let Some(control) = control_flow(node, source) {
        return match control {
            ControlFlow::Continue(label) if flow_targets_loop(label, loop_label) => BranchFlow {
                retryable: Some(node),
                terminal: None,
            },
            ControlFlow::Break(label) if flow_targets_loop(label, loop_label) => BranchFlow {
                retryable: None,
                terminal: Some(node),
            },
            _ => BranchFlow::default(),
        };
    }
    match node.kind() {
        "return_expression" if node.child_by_field_name("label").is_none() => BranchFlow {
            retryable: None,
            terminal: Some(node),
        },
        "throw_expression" => BranchFlow {
            retryable: None,
            terminal: Some(node),
        },
        "try_expression" if has_finally(node) => BranchFlow::default(),
        kind if is_loop_kind(kind) || is_callable_kind(kind) => BranchFlow::default(),
        _ => merge_children(node, loop_label, source),
    }
}

fn merge_children<'tree>(
    node: Node<'tree>,
    loop_label: Option<&str>,
    source: &[u8],
) -> BranchFlow<'tree> {
    let mut flow = BranchFlow::default();
    for child in named_children(node) {
        merge_flow(&mut flow, branch_flow(child, loop_label, source));
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

enum ControlFlow<'source> {
    Continue(Option<&'source str>),
    Break(Option<&'source str>),
}

fn control_flow<'source>(node: Node<'_>, source: &'source [u8]) -> Option<ControlFlow<'source>> {
    if node.kind() == "identifier" {
        return match node.utf8_text(source).ok()? {
            "continue" => Some(ControlFlow::Continue(None)),
            "break" => Some(ControlFlow::Break(None)),
            _ => None,
        };
    }
    if node.kind() != "labeled_expression" {
        return None;
    }
    let children = named_children(node).collect::<Vec<_>>();
    let [marker, target] = children.as_slice() else {
        return None;
    };
    if marker.kind() != "label" || target.kind() != "identifier" {
        return None;
    }
    let target = target.utf8_text(source).ok()?;
    match marker.utf8_text(source).ok()? {
        "continue@" => Some(ControlFlow::Continue(Some(target))),
        "break@" => Some(ControlFlow::Break(Some(target))),
        _ => None,
    }
}

fn flow_targets_loop(label: Option<&str>, loop_label: Option<&str>) -> bool {
    label.is_none() || label == loop_label
}

fn loop_label<'source>(node: Node<'_>, source: &'source [u8]) -> Option<&'source str> {
    named_children(node)
        .find(|child| child.kind() == "label")
        .and_then(|label| label.utf8_text(source).ok())
        .and_then(|label| label.strip_suffix('@'))
}

fn loop_body(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "do_while_statement" {
        let condition = node.child_by_field_name("condition")?;
        return named_children(node).find(|child| child.kind() != "label" && *child != condition);
    }
    let children = children(node).collect::<Vec<_>>();
    let closing_paren = children.iter().rposition(|child| child.kind() == ")")?;
    children
        .into_iter()
        .skip(closing_paren + 1)
        .find(|child| child.is_named())
}

fn if_branches(node: Node<'_>) -> Option<Vec<Node<'_>>> {
    let condition = node.child_by_field_name("condition")?;
    let branches = named_children(node)
        .filter(|child| *child != condition)
        .collect::<Vec<_>>();
    (branches.len() == 2).then_some(branches)
}

fn when_branch_bodies(node: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    named_children(node)
        .filter(|child| child.kind() == "when_entry")
        .filter_map(|entry| named_children(entry).last())
}

fn try_branches(node: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    named_children(node).filter(|child| matches!(child.kind(), "block" | "catch_block"))
}

fn has_finally(node: Node<'_>) -> bool {
    named_children(node).any(|child| child.kind() == "finally_block")
}

fn is_loop(node: Node<'_>) -> bool {
    is_loop_kind(node.kind())
}

fn is_loop_kind(kind: &str) -> bool {
    matches!(
        kind,
        "for_statement" | "while_statement" | "do_while_statement"
    )
}

fn is_callable_scope(node: Node<'_>) -> bool {
    is_callable_kind(node.kind())
}

fn is_callable_kind(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration" | "anonymous_function" | "lambda_literal"
    )
}

fn named_children(node: Node<'_>) -> impl DoubleEndedIterator<Item = Node<'_>> {
    children(node).filter(|child| child.is_named())
}

fn children(node: Node<'_>) -> impl DoubleEndedIterator<Item = Node<'_>> {
    (0..node.child_count()).filter_map(move |index| node.child(index))
}
