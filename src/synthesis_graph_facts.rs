use super::{FileScopeFact, GraphEdge, GraphFacts};
use crate::report_types::MethodReviewRecord;
use crate::symbol_graph::SymbolGraph;
use crate::types::{FindingTier, ResolvedSymbol, SymbolKind};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Join resolved graph references to the persisted method census without
/// guessing across unresolved names or ambiguous definitions.
#[cfg(test)]
pub(crate) fn build_graph_facts(records: &[MethodReviewRecord], graph: &SymbolGraph) -> GraphFacts {
    build_graph_facts_inner(records, graph, None, None)
}

/// Build synthesis context from the custom graph plus exact compiler facts
/// attached to each AST method. The custom graph remains supplemental evidence.
pub(crate) fn build_graph_facts_with_compiler(
    records: &[MethodReviewRecord],
    graph: &SymbolGraph,
    compiler_methods: &crate::semantic_method_join::CompilerMethodContexts,
    compiler_references: &[crate::semantic_method_join::CompilerMethodReference],
) -> GraphFacts {
    build_graph_facts_inner(
        records,
        graph,
        Some(compiler_methods),
        Some(compiler_references),
    )
}

fn build_graph_facts_inner(
    records: &[MethodReviewRecord],
    graph: &SymbolGraph,
    compiler_methods: Option<&crate::semantic_method_join::CompilerMethodContexts>,
    compiler_references: Option<&[crate::semantic_method_join::CompilerMethodReference]>,
) -> GraphFacts {
    let mut file_roles = records
        .iter()
        .map(|record| {
            (
                record.file_path.clone(),
                crate::roles::file_role_label(crate::roles::classify_file_role(&record.file_path))
                    .to_string(),
            )
        })
        .collect::<Vec<_>>();
    file_roles.sort();
    file_roles.dedup();
    let mut file_scope_counts = BTreeMap::<String, [usize; 4]>::new();
    for record in records {
        let counts = file_scope_counts
            .entry(record.file_path.clone())
            .or_default();
        let index = match record.verdict.tier {
            FindingTier::Clean => 0,
            FindingTier::KindaSlop => 1,
            FindingTier::Slop => 2,
            FindingTier::Unresolved => 3,
        };
        counts[index] += 1;
    }
    let file_scopes = file_scope_counts
        .into_iter()
        .map(|(file_path, counts)| FileScopeFact {
            file_path,
            method_count: counts.iter().sum(),
            clean_count: counts[0],
            kinda_slop_count: counts[1],
            slop_count: counts[2],
            unresolved_count: counts[3],
        })
        .collect::<Vec<_>>();
    let mut definitions = HashMap::<(String, usize), String>::new();
    for (file_path, symbols) in &graph.files {
        for definition in &symbols.definitions {
            if !matches!(definition.kind, SymbolKind::Function | SymbolKind::Method) {
                continue;
            }
            let matches = records
                .iter()
                .filter(|record| {
                    record.file_path == *file_path
                        && record.method_name == definition.name
                        && record.start_line == definition.start_line
                })
                .map(|record| record.unit_id.clone())
                .collect::<Vec<_>>();
            if matches.len() == 1 {
                definitions.insert((file_path.clone(), definition.id), matches[0].clone());
            }
        }
    }

    let mut facts = GraphFacts {
        file_roles,
        file_scopes,
        compiler_methods: compiler_methods.cloned().unwrap_or_default(),
        ..GraphFacts::default()
    };
    for (file_path, symbols) in &graph.files {
        for reference in &symbols.references {
            let caller = records
                .iter()
                .filter(|record| {
                    record.file_path == *file_path
                        && record.start_line <= reference.line
                        && reference.line <= record.end_line
                })
                .min_by_key(|record| record.end_line.saturating_sub(record.start_line));
            let Some(caller) = caller else {
                continue;
            };
            let target = match &reference.resolved_symbol {
                Some(ResolvedSymbol::Local(definition_id)) => {
                    definitions.get(&(file_path.clone(), *definition_id))
                }
                Some(ResolvedSymbol::External {
                    file_path: target_file,
                    definition_id: Some(definition_id),
                    ..
                }) => definitions.get(&(target_file.clone(), *definition_id)),
                Some(ResolvedSymbol::External {
                    definition_id: None,
                    ..
                }) => {
                    facts.external_references += 1;
                    continue;
                }
                None => {
                    facts.unresolved_references += 1;
                    continue;
                }
            };
            let Some(callee_unit_id) = target else {
                facts.unresolved_references += 1;
                continue;
            };
            facts.edges.push(GraphEdge {
                caller_unit_id: caller.unit_id.clone(),
                callee_unit_id: callee_unit_id.clone(),
                line: reference.line,
                snippet: reference.snippet.clone(),
            });
        }
    }
    facts.edges.sort_by(|left, right| {
        (
            &left.caller_unit_id,
            &left.callee_unit_id,
            left.line,
            &left.snippet,
        )
            .cmp(&(
                &right.caller_unit_id,
                &right.callee_unit_id,
                right.line,
                &right.snippet,
            ))
    });
    facts.edges.dedup();
    if let Some(references) = compiler_references {
        facts.supplemental_edges = std::mem::take(&mut facts.edges);
        let mut method_units = BTreeMap::<String, Option<String>>::new();
        for record in records {
            let key = crate::semantic_method_join::method_context_key(
                &record.file_path,
                &record.method_name,
                record.start_line,
            );
            method_units
                .entry(key)
                .and_modify(|unit| *unit = None)
                .or_insert(Some(record.unit_id.clone()));
        }
        let mut pairs = BTreeMap::new();
        for reference in references {
            let (Some(Some(source)), Some(Some(target))) = (
                method_units.get(&reference.source_method),
                method_units.get(&reference.target_method),
            ) else {
                continue;
            };
            if source == target {
                continue;
            }
            pairs.entry(reference).or_insert_with(|| GraphEdge {
                caller_unit_id: source.clone(),
                callee_unit_id: target.clone(),
                line: reference.line as usize,
                snippet: format!(
                    "compiler {:?}; variant={:?}; symbol={:?}; file={:?}",
                    reference.kind, reference.variant, reference.symbol.0, reference.file.0,
                ),
            });
        }
        facts.edges = pairs.into_values().collect();
        let confirmed = facts
            .edges
            .iter()
            .map(|edge| (edge.caller_unit_id.clone(), edge.callee_unit_id.clone()))
            .collect::<HashSet<_>>();
        facts.supplemental_edges.retain(|edge| {
            confirmed.contains(&(edge.caller_unit_id.clone(), edge.callee_unit_id.clone()))
        });
    }
    facts
}
