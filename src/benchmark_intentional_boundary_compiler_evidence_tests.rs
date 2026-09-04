use super::*;
use crate::benchmark::release::{
    IntentionalBoundaryIndexerKind, IntentionalBoundaryMethodCensusEntry,
    IntentionalBoundarySemanticCallFacts, IntentionalBoundarySemanticDispatch,
    IntentionalBoundarySemanticImportFacts, IntentionalBoundarySemanticIndexerCensus,
    IntentionalBoundarySemanticMethod, IntentionalBoundarySemanticMethodStatus,
    IntentionalBoundarySemanticOrigin, IntentionalBoundarySemanticRange,
    IntentionalBoundarySemanticRelationshipFacts, IntentionalBoundarySemanticRelationshipKind,
    IntentionalBoundarySemanticResolution, IntentionalBoundarySemanticSurface,
    IntentionalBoundarySemanticSymbolCategory, IntentionalBoundarySemanticSymbolFacts,
    IntentionalBoundarySemanticTestFacts, IntentionalBoundarySemanticTestKind,
    IntentionalBoundarySemanticVisibility, IntentionalBoundarySourceFile,
};

fn location() -> IntentionalBoundarySemanticRange {
    IntentionalBoundarySemanticRange {
        repository_path: "src/lib.rs".to_string(),
        start_line_zero_based: 0,
        start_character_zero_based: 7,
        end_line_zero_based: 0,
        end_character_zero_based: 14,
    }
}

fn fixture() -> (
    IntentionalBoundarySourceCensus,
    IntentionalBoundarySemanticCensus,
) {
    let method_id = "ibm-v1:fixture".to_string();
    let source_census = IntentionalBoundarySourceCensus {
        schema_version: 1,
        census_contract: "fixture".to_string(),
        repository: "github.com/example/evidence".to_string(),
        revision: "a".repeat(40),
        inventory_sha256: "b".repeat(64),
        tracked_entry_count: 1,
        source_files: vec![IntentionalBoundarySourceFile {
            repository_path: "src/lib.rs".to_string(),
            object_id: "c".repeat(40),
            byte_length: 32,
            source_sha256: "d".repeat(64),
            language: "rust".to_string(),
            methods: vec![IntentionalBoundaryMethodCensusEntry {
                parser_unit_id: method_id.clone(),
                symbol_name: "process".to_string(),
                start_line: 1,
                end_line: 1,
                source_sha256: "e".repeat(64),
                is_exported: true,
            }],
        }],
        source_file_count: 1,
        method_count: 1,
        census_sha256: "f".repeat(64),
    };
    let symbol_id = "rust fixture process".to_string();
    let mut semantic_census = IntentionalBoundarySemanticCensus {
        schema_version: super::super::INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_SCHEMA_VERSION,
        semantic_contract: super::super::intentional_boundary_semantic::SEMANTIC_CENSUS_CONTRACT
            .to_string(),
        repository: source_census.repository.clone(),
        revision: source_census.revision.clone(),
        source_census_sha256: source_census.census_sha256.clone(),
        indexers: vec![IntentionalBoundarySemanticIndexerCensus {
            indexer: IntentionalBoundaryIndexerKind::Rust,
            tool_name: "fixture-indexer".to_string(),
            tool_version: Some("1.0.0".to_string()),
            semantic_facts_sha256: "1".repeat(64),
            diagnostic_count: 0,
            diagnostics_sha256: "2".repeat(64),
            document_count: 1,
            symbol_count: 4,
            relationship_count: 1,
            import_count: 1,
            call_count: 1,
            test_relationship_count: 1,
            unresolved_edge_count: 0,
        }],
        source_references: Vec::new(),
        methods: vec![IntentionalBoundarySemanticMethod {
            parser_unit_id: method_id,
            repository_path: "src/lib.rs".to_string(),
            symbol_name: "process".to_string(),
            start_line: 1,
            end_line: 1,
            indexer: IntentionalBoundaryIndexerKind::Rust,
            status: IntentionalBoundarySemanticMethodStatus::Resolved {
                symbol: Box::new(IntentionalBoundarySemanticSymbolFacts {
                    symbol_id: symbol_id.clone(),
                    provider_identity: symbol_id.clone(),
                    display_name: Some("process".to_string()),
                    category: IntentionalBoundarySemanticSymbolCategory::Callable,
                    provider_kind: "function".to_string(),
                    documentation: Vec::new(),
                    signatures: vec![
                        crate::benchmark::IntentionalBoundarySemanticSignatureFacts {
                            language: "rust".to_string(),
                            text: "fn process()".to_string(),
                            referenced_symbols: Vec::new(),
                        },
                    ],
                    owner: None,
                    definitions: vec![location()],
                    visibility: IntentionalBoundarySemanticVisibility::Public,
                    surfaces: vec![
                        IntentionalBoundarySemanticSurface::PublicApi,
                        IntentionalBoundarySemanticSurface::FrameworkRegistration,
                    ],
                    origin: IntentionalBoundarySemanticOrigin::Repository,
                    ambiguity_notes: Vec::new(),
                }),
                joined_definition: Some(location()),
            },
            occurrences: Vec::new(),
            calls: vec![IntentionalBoundarySemanticCallFacts {
                caller: "rust fixture caller".to_string(),
                callee: IntentionalBoundarySemanticResolution::Resolved {
                    value: symbol_id.clone(),
                },
                callsite: location(),
                dispatch: IntentionalBoundarySemanticDispatch::Static,
            }],
            relationships: vec![IntentionalBoundarySemanticRelationshipFacts {
                source: symbol_id.clone(),
                target: "rust fixture trait".to_string(),
                kind: IntentionalBoundarySemanticRelationshipKind::Implementation,
            }],
            imports: vec![IntentionalBoundarySemanticImportFacts {
                location: location(),
                target: IntentionalBoundarySemanticResolution::Resolved {
                    value: symbol_id.clone(),
                },
                reexport: IntentionalBoundarySemanticResolution::Resolved { value: true },
            }],
            test_relationships: vec![IntentionalBoundarySemanticTestFacts {
                test_symbol: "rust fixture test".to_string(),
                production: IntentionalBoundarySemanticResolution::Resolved { value: symbol_id },
                kind: IntentionalBoundarySemanticTestKind::Mocks,
            }],
        }],
        resolved_method_count: 1,
        compiler_excluded_method_count: 0,
        unresolved_method_count: 0,
        semantic_census_sha256: String::new(),
    };
    semantic_census.semantic_census_sha256 =
        super::super::intentional_boundary_semantic::compute_semantic_census_sha256(
            &semantic_census,
        )
        .unwrap();
    (source_census, semantic_census)
}

#[test]
fn emits_only_typed_compiler_proofs_with_exact_locations() {
    let (source, semantic) = fixture();

    let evidence = extract_intentional_boundary_compiler_evidence(&source, &semantic).unwrap();

    assert_eq!(evidence.atoms.len(), 7);
    assert!(evidence.atoms.iter().all(|atom| {
        matches!(
            atom.proof,
            IntentionalBoundaryEvidenceProof::CompilerSemanticIndex(_)
        ) && !atom.locations.is_empty()
    }));
    assert_eq!(
        evidence
            .atom_count_by_kind
            .get(&BoundaryEvidenceKind::ResolvedConsumer),
        Some(&2)
    );
    assert!(
        !evidence
            .atom_count_by_kind
            .contains_key(&BoundaryEvidenceKind::PassingBehaviorTest)
    );
    validate_intentional_boundary_compiler_evidence(&source, &semantic, &evidence).unwrap();
}

#[test]
fn compiler_evidence_replay_rejects_tampering() {
    let (source, semantic) = fixture();
    let mut evidence = extract_intentional_boundary_compiler_evidence(&source, &semantic).unwrap();
    evidence.atoms.pop();

    assert!(
        validate_intentional_boundary_compiler_evidence(&source, &semantic, &evidence)
            .unwrap_err()
            .contains("changed")
    );
}

#[test]
fn resolved_symbol_without_a_source_location_cannot_be_evidence() {
    let (source, mut semantic) = fixture();
    let IntentionalBoundarySemanticMethodStatus::Resolved {
        symbol,
        joined_definition,
    } = &mut semantic.methods[0].status
    else {
        unreachable!();
    };
    symbol.definitions.clear();
    *joined_definition = None;
    semantic.semantic_census_sha256 =
        super::super::intentional_boundary_semantic::compute_semantic_census_sha256(&semantic)
            .unwrap();

    assert!(
        extract_intentional_boundary_compiler_evidence(&source, &semantic)
            .unwrap_err()
            .contains("unrelated compiler facts")
    );
}
