use super::*;
use crate::semantic_index::{
    RepositoryPath, SemanticIndexVariant, SemanticSymbolId, SemanticVariantId,
};
use crate::semantic_method_join::{
    CompilerMethodReference, CompilerRelationshipKind, method_context_key,
};
use crate::symbol_graph::SymbolGraph;

fn records() -> Vec<MethodReviewRecord> {
    vec![
        super::tests::record("source", "source", "call target"),
        super::tests::record("target", "target", "return value"),
    ]
}

fn reference(
    records: &[MethodReviewRecord],
    variant: &str,
    kind: CompilerRelationshipKind,
) -> CompilerMethodReference {
    CompilerMethodReference {
        variant: SemanticIndexVariant::Qualified {
            identity: SemanticVariantId(variant.to_string()),
            dimensions: BTreeMap::from([("target".to_string(), variant.to_string())]),
        },
        kind,
        source_method: method_context_key(
            &records[0].file_path,
            &records[0].method_name,
            records[0].start_line,
        ),
        target_method: method_context_key(
            &records[1].file_path,
            &records[1].method_name,
            records[1].start_line,
        ),
        file: RepositoryPath("src/demo.py".to_string()),
        line: 2,
        symbol: SemanticSymbolId("provider-target".to_string()),
    }
}

#[test]
fn synthesis_retains_worlds_and_call_reference_kinds_for_the_same_method_pair() {
    let records = records();
    let linux = reference(&records, "linux", CompilerRelationshipKind::Reference);
    let windows = reference(&records, "windows", CompilerRelationshipKind::Reference);
    let call = reference(&records, "linux", CompilerRelationshipKind::Call);
    let references = vec![linux.clone(), windows, call, linux];
    let facts = build_graph_facts_with_compiler(
        &records,
        &SymbolGraph::new("."),
        &BTreeMap::new(),
        &references,
    );
    assert_eq!(facts.edges.len(), 3);
    let prompt = render_synthesis_prompt_with_graph(&records, &facts);
    assert_eq!(prompt.matches("source=source target=target").count(), 3);
    for evidence in [
        "linux",
        "windows",
        "compiler Call",
        "compiler Reference",
        "provider-target",
    ] {
        assert!(prompt.contains(evidence));
    }
    assert!(prompt.contains("Edges from different worlds do not prove coexecution"));
}

#[test]
fn changed_variant_dimensions_change_durable_synthesis_evidence_identity() {
    let records = records();
    let left = reference(&records, "linux", CompilerRelationshipKind::Reference);
    let mut right = left.clone();
    let SemanticIndexVariant::Qualified { dimensions, .. } = &mut right.variant else {
        unreachable!()
    };
    dimensions.insert("features".to_string(), "different".to_string());
    let facts = |reference| {
        build_graph_facts_with_compiler(
            &records,
            &SymbolGraph::new("."),
            &BTreeMap::new(),
            &[reference],
        )
    };
    assert_ne!(facts(left).stable_key(), facts(right).stable_key());
}

#[test]
fn synthesis_reference_order_is_stable_and_distinct_locations_are_not_collapsed() {
    let records = records();
    let first = reference(&records, "linux", CompilerRelationshipKind::Reference);
    let mut second = first.clone();
    second.line = 3;
    let facts = |references: &[CompilerMethodReference]| {
        build_graph_facts_with_compiler(
            &records,
            &SymbolGraph::new("."),
            &BTreeMap::new(),
            references,
        )
    };
    let forward = facts(&[first.clone(), second.clone()]);
    let reverse = facts(&[second, first]);
    assert_eq!(forward.edges.len(), 2);
    assert_eq!(forward.stable_key(), reverse.stable_key());
    assert_eq!(
        render_synthesis_prompt_with_graph(&records, &forward),
        render_synthesis_prompt_with_graph(&records, &reverse)
    );
}

#[test]
fn multiple_worlds_do_not_create_duplicate_cross_chunk_review_requests() {
    let mut records = records();
    records.push(super::tests::record("third", "third", "return value"));
    let mut references = vec![
        reference(&records, "linux", CompilerRelationshipKind::Reference),
        reference(&records, "windows", CompilerRelationshipKind::Reference),
        reference(&records, "linux", CompilerRelationshipKind::Call),
    ];
    for world in ["linux", "windows"] {
        let mut edge = reference(&records[1..], world, CompilerRelationshipKind::Reference);
        edge.symbol = SemanticSymbolId("provider-third".to_string());
        references.push(edge);
    }
    let facts = build_graph_facts_with_compiler(
        &records,
        &SymbolGraph::new("."),
        &BTreeMap::new(),
        &references,
    );
    let limit = render_synthesis_prompt_with_graph(&records[..2], &facts)
        .len()
        .max(render_synthesis_prompt_with_graph(&records[1..], &facts).len());
    assert!(render_synthesis_prompt_with_graph(&records, &facts).len() > limit);
    let chunks = split_records(&records, &facts, limit).unwrap();
    let boundary = chunks
        .iter()
        .filter(|chunk| {
            chunk.iter().any(|record| record.unit_id == "target")
                && chunk.iter().any(|record| record.unit_id == "third")
        })
        .collect::<Vec<_>>();
    assert_eq!(boundary.len(), 1);
    let packet = render_synthesis_prompt_with_graph(boundary[0], &facts);
    assert!(packet.contains("linux"));
    assert!(packet.contains("windows"));
}
