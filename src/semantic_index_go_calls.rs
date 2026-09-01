use crate::semantic_index::{
    RepositoryPath, SemanticCallEdge, SemanticDispatch, SemanticDocument, SemanticIndex,
    SemanticLocation, SemanticOccurrenceRole, SemanticPosition, SemanticPositionEncoding,
    SemanticResolution, SemanticSourceRange, SemanticSymbolId, SemanticUnresolvedEdge,
    SemanticUnresolvedEdgeKind, SemanticUnresolvedReason,
};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use tree_sitter::{Node, Point};

pub(super) fn enrich_go_calls(index: &mut SemanticIndex, source_root: &Path) -> Result<(), String> {
    let paths = index.documents.keys().cloned().collect::<Vec<_>>();
    for path in paths {
        let document = index
            .documents
            .get(&path)
            .ok_or_else(|| format!("Go semantic document disappeared: {}", path.0))?;
        let source_path = source_root.join(Path::new(&path.0));
        let source = fs::read_to_string(&source_path).map_err(|error| {
            format!(
                "failed to read compiler-selected Go source {}: {error}",
                source_path.display()
            )
        })?;
        let (calls, unresolved) = analyze_go_document(&path, document, &source)?;
        validate_call_symbols(index, &calls, &unresolved)?;
        index.calls.extend(calls);
        index.unresolved_edges.extend(unresolved);
    }
    Ok(())
}

fn validate_call_symbols(
    index: &SemanticIndex,
    calls: &BTreeSet<SemanticCallEdge>,
    unresolved: &BTreeSet<SemanticUnresolvedEdge>,
) -> Result<(), String> {
    let mut referenced = calls
        .iter()
        .flat_map(|call| {
            std::iter::once(&call.caller).chain(match &call.callee {
                SemanticResolution::Resolved { value } => Some(value),
                SemanticResolution::Unresolved { .. } => None,
            })
        })
        .chain(unresolved.iter().filter_map(|edge| edge.source.as_ref()));
    if let Some(missing) = referenced.find(|symbol| !index.symbols.contains_key(*symbol)) {
        return Err(format!(
            "Go AST/SCIP call binding references symbol absent from the compiler index: {}",
            missing.0
        ));
    }
    Ok(())
}

fn analyze_go_document(
    path: &RepositoryPath,
    document: &SemanticDocument,
    source: &str,
) -> Result<(BTreeSet<SemanticCallEdge>, BTreeSet<SemanticUnresolvedEdge>), String> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_go::language())
        .map_err(|error| format!("failed to initialize Go call parser: {error}"))?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| format!("Go call parser produced no tree for {}", path.0))?;
    if tree.root_node().has_error() {
        return Err(format!(
            "Go call parser could not represent compiler-selected source {}; no name-based call fallback was used",
            path.0
        ));
    }

    let mut calls = BTreeSet::new();
    let mut unresolved = BTreeSet::new();
    collect_calls(
        tree.root_node(),
        None,
        path,
        document,
        source,
        &mut calls,
        &mut unresolved,
    )?;
    Ok((calls, unresolved))
}

fn collect_calls(
    node: Node<'_>,
    inherited_caller: Option<SemanticSymbolId>,
    path: &RepositoryPath,
    document: &SemanticDocument,
    source: &str,
    calls: &mut BTreeSet<SemanticCallEdge>,
    unresolved: &mut BTreeSet<SemanticUnresolvedEdge>,
) -> Result<(), String> {
    let caller = match node.kind() {
        "function_declaration" | "method_declaration" => node
            .child_by_field_name("name")
            .map(|name| node_range(name, source, document.position_encoding))
            .transpose()?
            .and_then(|range| exact_definition(document, range)),
        "func_literal" => None,
        _ => inherited_caller,
    };

    if node.kind() == "call_expression" {
        collect_call(
            node,
            caller.clone(),
            path,
            document,
            source,
            calls,
            unresolved,
        )?;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_calls(
            child,
            caller.clone(),
            path,
            document,
            source,
            calls,
            unresolved,
        )?;
    }
    Ok(())
}

fn collect_call(
    call: Node<'_>,
    caller: Option<SemanticSymbolId>,
    path: &RepositoryPath,
    document: &SemanticDocument,
    source: &str,
    calls: &mut BTreeSet<SemanticCallEdge>,
    unresolved: &mut BTreeSet<SemanticUnresolvedEdge>,
) -> Result<(), String> {
    let function = call.child_by_field_name("function").ok_or_else(|| {
        format!(
            "Go call expression at {}:{} has no function field",
            path.0,
            call.start_position().row + 1
        )
    })?;
    let raw_target = function
        .utf8_text(source.as_bytes())
        .ok()
        .map(str::to_string);
    let Some(target) = call_target_node(function) else {
        let range = node_range(function, source, document.position_encoding)?;
        unresolved.insert(unresolved_call(
            caller,
            path,
            range,
            SemanticUnresolvedReason::UnsupportedConstruct,
            raw_target,
            "Go call target syntax is not supported by the exact AST/SCIP binder",
        ));
        return Ok(());
    };
    let range = node_range(target, source, document.position_encoding)?;
    let target_symbol = exact_reference(document, range);
    match (caller, target_symbol) {
        (Some(caller), ExactSymbol::Resolved(callee)) => {
            calls.insert(SemanticCallEdge {
                caller,
                callsite: SemanticLocation {
                    document: path.clone(),
                    range,
                },
                callee: SemanticResolution::Resolved { value: callee },
                dispatch: if function.kind() == "identifier" {
                    SemanticDispatch::Static
                } else {
                    SemanticDispatch::Unknown
                },
            });
        }
        (caller, exact) => {
            let (reason, detail) = match (&caller, exact) {
                (None, _) => (
                    SemanticUnresolvedReason::UnsupportedConstruct,
                    "Go call is not enclosed by an exactly resolved named function or method",
                ),
                (Some(_), ExactSymbol::Missing) => (
                    SemanticUnresolvedReason::MissingIndexerFact,
                    "Go call target has no exact SCIP occurrence at the AST target range",
                ),
                (Some(_), ExactSymbol::Ambiguous) => (
                    SemanticUnresolvedReason::Ambiguous,
                    "Go call target range maps to multiple SCIP symbols",
                ),
                (Some(_), ExactSymbol::Resolved(_)) => unreachable!(),
            };
            unresolved.insert(unresolved_call(
                caller, path, range, reason, raw_target, detail,
            ));
        }
    }
    Ok(())
}

fn call_target_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "identifier" => Some(node),
        "selector_expression" => node.child_by_field_name("field"),
        "generic_type" | "index_expression" => node
            .child_by_field_name("type")
            .or_else(|| node.child_by_field_name("operand"))
            .and_then(call_target_node),
        "parenthesized_expression" => node.named_child(0).and_then(call_target_node),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExactSymbol {
    Resolved(SemanticSymbolId),
    Missing,
    Ambiguous,
}

fn exact_reference(document: &SemanticDocument, range: SemanticSourceRange) -> ExactSymbol {
    let symbols = document
        .occurrences
        .iter()
        .filter(|occurrence| occurrence.range == range)
        .filter_map(|occurrence| occurrence.symbol.clone())
        .collect::<BTreeSet<_>>();
    match symbols.len() {
        0 => ExactSymbol::Missing,
        1 => ExactSymbol::Resolved(symbols.into_iter().next().unwrap()),
        _ => ExactSymbol::Ambiguous,
    }
}

fn exact_definition(
    document: &SemanticDocument,
    range: SemanticSourceRange,
) -> Option<SemanticSymbolId> {
    let symbols = document
        .occurrences
        .iter()
        .filter(|occurrence| {
            occurrence.range == range
                && occurrence
                    .roles
                    .contains(&SemanticOccurrenceRole::Definition)
        })
        .filter_map(|occurrence| occurrence.symbol.clone())
        .collect::<BTreeSet<_>>();
    (symbols.len() == 1).then(|| symbols.into_iter().next().unwrap())
}

fn unresolved_call(
    source: Option<SemanticSymbolId>,
    path: &RepositoryPath,
    range: SemanticSourceRange,
    reason: SemanticUnresolvedReason,
    raw_target: Option<String>,
    detail: &str,
) -> SemanticUnresolvedEdge {
    SemanticUnresolvedEdge {
        source,
        location: SemanticLocation {
            document: path.clone(),
            range,
        },
        edge_kind: SemanticUnresolvedEdgeKind::Call,
        reason,
        raw_target,
        detail: detail.to_string(),
    }
}

fn node_range(
    node: Node<'_>,
    source: &str,
    encoding: SemanticPositionEncoding,
) -> Result<SemanticSourceRange, String> {
    Ok(SemanticSourceRange {
        start: semantic_position(node.start_position(), source, encoding)?,
        end: semantic_position(node.end_position(), source, encoding)?,
    })
}

fn semantic_position(
    point: Point,
    source: &str,
    encoding: SemanticPositionEncoding,
) -> Result<SemanticPosition, String> {
    let line = source
        .split('\n')
        .nth(point.row)
        .ok_or_else(|| format!("Go AST point references missing line {}", point.row + 1))?;
    if point.column > line.len() || !line.is_char_boundary(point.column) {
        return Err(format!(
            "Go AST point {}:{} is not a UTF-8 boundary",
            point.row + 1,
            point.column
        ));
    }
    let prefix = &line[..point.column];
    let character = match encoding {
        SemanticPositionEncoding::Utf8 => prefix.len(),
        SemanticPositionEncoding::Utf16 => prefix.encode_utf16().count(),
        SemanticPositionEncoding::Utf32 => prefix.chars().count(),
    };
    Ok(SemanticPosition {
        line: u32::try_from(point.row).map_err(|_| "Go AST line overflowed u32".to_string())?,
        character: u32::try_from(character)
            .map_err(|_| "Go AST character offset overflowed u32".to_string())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic_index::{SemanticDocument, SemanticOccurrence};

    fn occurrence(
        line: u32,
        start: u32,
        end: u32,
        symbol: &str,
        definition: bool,
    ) -> SemanticOccurrence {
        SemanticOccurrence {
            range: SemanticSourceRange {
                start: SemanticPosition {
                    line,
                    character: start,
                },
                end: SemanticPosition {
                    line,
                    character: end,
                },
            },
            symbol: Some(SemanticSymbolId(symbol.to_string())),
            roles: definition
                .then_some(SemanticOccurrenceRole::Definition)
                .into_iter()
                .collect(),
            override_documentation: Vec::new(),
        }
    }

    #[test]
    fn exact_go_ast_and_scip_ranges_produce_a_call_edge() {
        let source = "package app\nfunc Run() string { return contract.Invoke() }\n";
        let document = SemanticDocument {
            path: RepositoryPath("app/app.go".to_string()),
            language: "go".to_string(),
            position_encoding: SemanticPositionEncoding::Utf8,
            embedded_text: None,
            occurrences: vec![
                occurrence(1, 5, 8, "run", true),
                occurrence(1, 36, 42, "invoke", false),
            ],
        };

        let (calls, unresolved) = analyze_go_document(&document.path, &document, source).unwrap();

        assert!(unresolved.is_empty());
        let call = calls.iter().next().unwrap();
        assert_eq!(call.caller, SemanticSymbolId("run".to_string()));
        assert_eq!(
            call.callee,
            SemanticResolution::Resolved {
                value: SemanticSymbolId("invoke".to_string())
            }
        );
        assert_eq!(call.callsite.range.start.character, 36);
    }

    #[test]
    fn missing_scip_target_is_explicitly_unresolved() {
        let source = "package app\nfunc Run() { missing() }\n";
        let document = SemanticDocument {
            path: RepositoryPath("app/app.go".to_string()),
            language: "go".to_string(),
            position_encoding: SemanticPositionEncoding::Utf8,
            embedded_text: None,
            occurrences: vec![occurrence(1, 5, 8, "run", true)],
        };

        let (calls, unresolved) = analyze_go_document(&document.path, &document, source).unwrap();

        assert!(calls.is_empty());
        assert_eq!(unresolved.len(), 1);
        let edge = unresolved.iter().next().unwrap();
        assert_eq!(edge.reason, SemanticUnresolvedReason::MissingIndexerFact);
        assert_eq!(edge.raw_target.as_deref(), Some("missing"));
    }
}
