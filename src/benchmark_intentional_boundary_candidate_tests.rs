use super::*;
use crate::benchmark::release::{
    IntentionalBoundaryAstProofKind, IntentionalBoundaryCompilerProofKind,
    IntentionalBoundaryEvidenceProof, IntentionalBoundaryIndexerKind,
    IntentionalBoundaryManifestProofKind, IntentionalBoundaryMethodCensusEntry,
    IntentionalBoundarySemanticIndexerCensus, IntentionalBoundarySemanticMethod,
    IntentionalBoundarySemanticMethodStatus, IntentionalBoundarySemanticOrigin,
    IntentionalBoundarySemanticRange, IntentionalBoundarySemanticSymbolCategory,
    IntentionalBoundarySemanticSymbolFacts, IntentionalBoundarySemanticVisibility,
    IntentionalBoundarySourceFile,
};
use std::collections::BTreeMap;

const POLICY: &[u8] = include_bytes!("../sniffbench/non-blind-v1-selection-policy.json");
const HISTORY: &[u8] = include_bytes!("../sniffbench/non-blind-v1-history-worksheet.json");
const BLIND_SEAL: &[u8] = include_bytes!("../sniffbench/blind-oss-v1-source-seal.json");
const PROTOCOL: &[u8] =
    include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-protocol.json");

fn protocol() -> ValidatedIntentionalBoundaryProtocol {
    super::super::validate_intentional_boundary_protocol(POLICY, HISTORY, BLIND_SEAL, PROTOCOL)
        .unwrap()
}

fn location(index: usize) -> IntentionalBoundarySemanticRange {
    let line = u32::try_from(index).unwrap();
    IntentionalBoundarySemanticRange {
        repository_path: "src/wrappers.rs".to_string(),
        start_line_zero_based: line,
        start_character_zero_based: 0,
        end_line_zero_based: line,
        end_character_zero_based: 10,
    }
}

fn fixture() -> (
    IntentionalBoundarySourceCensus,
    IntentionalBoundarySemanticCensus,
) {
    let parser_units = ["ibm-v1:first", "ibm-v1:second"];
    let symbols = ["rust fixture first", "rust fixture second"];
    let source = IntentionalBoundarySourceCensus {
        schema_version: 1,
        census_contract: "fixture".to_string(),
        repository: "github.com/example/candidates".to_string(),
        revision: "a".repeat(40),
        inventory_sha256: "b".repeat(64),
        tracked_entry_count: 1,
        source_files: vec![IntentionalBoundarySourceFile {
            repository_path: "src/wrappers.rs".to_string(),
            object_id: "c".repeat(40),
            byte_length: 64,
            source_sha256: "d".repeat(64),
            language: "rust".to_string(),
            methods: parser_units
                .iter()
                .enumerate()
                .map(
                    |(index, parser_unit_id)| IntentionalBoundaryMethodCensusEntry {
                        parser_unit_id: (*parser_unit_id).to_string(),
                        symbol_name: format!("public_wrapper_{index}"),
                        start_line: index + 1,
                        end_line: index + 1,
                        source_sha256: format!("{index}").repeat(64),
                        is_exported: true,
                    },
                )
                .collect(),
        }],
        source_file_count: 1,
        method_count: 2,
        census_sha256: "f".repeat(64),
    };
    let methods = parser_units
        .iter()
        .zip(symbols)
        .enumerate()
        .map(
            |(index, (parser_unit_id, symbol_id))| IntentionalBoundarySemanticMethod {
                parser_unit_id: (*parser_unit_id).to_string(),
                repository_path: "src/wrappers.rs".to_string(),
                symbol_name: format!("public_wrapper_{index}"),
                start_line: index + 1,
                end_line: index + 1,
                indexer: IntentionalBoundaryIndexerKind::Rust,
                status: IntentionalBoundarySemanticMethodStatus::Resolved {
                    symbol: Box::new(IntentionalBoundarySemanticSymbolFacts {
                        symbol_id: symbol_id.to_string(),
                        provider_identity: symbol_id.to_string(),
                        display_name: Some(format!("public_wrapper_{index}")),
                        category: IntentionalBoundarySemanticSymbolCategory::Callable,
                        provider_kind: "function".to_string(),
                        documentation: Vec::new(),
                        signature: Some(format!("fn public_wrapper_{index}()")),
                        signature_referenced_symbols: Vec::new(),
                        owner: None,
                        definitions: vec![location(index)],
                        visibility: IntentionalBoundarySemanticVisibility::Public,
                        surfaces: Vec::new(),
                        origin: IntentionalBoundarySemanticOrigin::Repository,
                        ambiguity_notes: Vec::new(),
                    }),
                    joined_definition: Some(location(index)),
                },
                occurrences: Vec::new(),
                calls: Vec::new(),
                relationships: Vec::new(),
                imports: Vec::new(),
                test_relationships: Vec::new(),
            },
        )
        .collect();
    let mut semantic = IntentionalBoundarySemanticCensus {
        schema_version: super::super::INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_SCHEMA_VERSION,
        semantic_contract: super::super::intentional_boundary_semantic::SEMANTIC_CENSUS_CONTRACT
            .to_string(),
        repository: source.repository.clone(),
        revision: source.revision.clone(),
        source_census_sha256: source.census_sha256.clone(),
        indexers: vec![IntentionalBoundarySemanticIndexerCensus {
            indexer: IntentionalBoundaryIndexerKind::Rust,
            tool_name: "fixture-indexer".to_string(),
            tool_version: Some("1.0.0".to_string()),
            semantic_facts_sha256: "1".repeat(64),
            diagnostic_count: 0,
            diagnostics_sha256: "2".repeat(64),
            document_count: 1,
            symbol_count: 2,
            relationship_count: 0,
            import_count: 0,
            call_count: 0,
            test_relationship_count: 0,
            unresolved_edge_count: 0,
        }],
        source_references: Vec::new(),
        methods,
        resolved_method_count: 2,
        compiler_excluded_method_count: 0,
        unresolved_method_count: 0,
        semantic_census_sha256: String::new(),
    };
    semantic.semantic_census_sha256 =
        super::super::intentional_boundary_semantic::compute_semantic_census_sha256(&semantic)
            .unwrap();
    (source, semantic)
}

fn evidence(
    source: &IntentionalBoundarySourceCensus,
    semantic: &IntentionalBoundarySemanticCensus,
    specifications: &[(
        usize,
        &str,
        BoundaryEvidenceKind,
        IntentionalBoundaryEvidenceProof,
    )],
) -> IntentionalBoundaryEvidenceCensus {
    let mut atoms = Vec::new();
    for (method_index, symbol_id, kind, proof) in specifications {
        super::super::intentional_boundary_compiler_evidence::push_typed_atom(
            &mut atoms,
            &semantic.methods[*method_index],
            symbol_id,
            *kind,
            *proof,
            vec![location(*method_index)],
            Vec::new(),
        )
        .unwrap();
    }
    super::super::intentional_boundary_compiler_evidence::finish_evidence_census(
        source,
        semantic,
        BTreeMap::from([(
            "compiler_semantic_index".to_string(),
            semantic.semantic_census_sha256.clone(),
        )]),
        atoms,
    )
    .unwrap()
}

fn exported_api() -> IntentionalBoundaryEvidenceProof {
    IntentionalBoundaryEvidenceProof::CompilerSemanticIndex(
        IntentionalBoundaryCompilerProofKind::PublicSymbol,
    )
}

fn published_api() -> IntentionalBoundaryEvidenceProof {
    IntentionalBoundaryEvidenceProof::ManifestContract(
        IntentionalBoundaryManifestProofKind::PublishedExport,
    )
}

#[test]
fn qualifies_only_complete_evidence_on_the_same_exact_symbol() {
    let (source, semantic) = fixture();
    let evidence = evidence(
        &source,
        &semantic,
        &[
            (
                0,
                "rust fixture first",
                BoundaryEvidenceKind::ExportedApiIdentity,
                exported_api(),
            ),
            (
                0,
                "rust fixture first",
                BoundaryEvidenceKind::PublishedApiContract,
                published_api(),
            ),
        ],
    );

    let census =
        qualify_intentional_boundary_candidates(&protocol(), &source, &semantic, &evidence)
            .unwrap();

    assert_eq!(census.candidates.len(), 1);
    assert_eq!(
        census.candidates[0].category,
        IntentionalBoundaryCategory::PublicWrapper
    );
    assert_eq!(
        census.candidates[0].exact_symbol_identity,
        "rust fixture first"
    );
}

#[test]
fn never_combines_evidence_across_symbols() {
    let (source, semantic) = fixture();
    let evidence = evidence(
        &source,
        &semantic,
        &[
            (
                0,
                "rust fixture first",
                BoundaryEvidenceKind::ExportedApiIdentity,
                exported_api(),
            ),
            (
                1,
                "rust fixture second",
                BoundaryEvidenceKind::PublishedApiContract,
                published_api(),
            ),
        ],
    );

    let census =
        qualify_intentional_boundary_candidates(&protocol(), &source, &semantic, &evidence)
            .unwrap();

    assert!(census.candidates.is_empty());
}

#[test]
fn rejects_evidence_claiming_a_different_symbol_for_a_parser_unit() {
    let (source, semantic) = fixture();
    let evidence = evidence(
        &source,
        &semantic,
        &[(
            0,
            "rust fixture forged",
            BoundaryEvidenceKind::ResolvedTestInjectionOrReplacement,
            IntentionalBoundaryEvidenceProof::SourceAst(
                IntentionalBoundaryAstProofKind::TestInjectionOrReplacement,
            ),
        )],
    );

    let error = qualify_intentional_boundary_candidates(&protocol(), &source, &semantic, &evidence)
        .unwrap_err();

    assert!(error.contains("changed the exact symbol"));
}

#[test]
fn candidate_identity_uses_only_the_frozen_identity_fields() {
    let (source, semantic) = fixture();
    let manifest_evidence = evidence(
        &source,
        &semantic,
        &[
            (
                0,
                "rust fixture first",
                BoundaryEvidenceKind::ExportedApiIdentity,
                exported_api(),
            ),
            (
                0,
                "rust fixture first",
                BoundaryEvidenceKind::PublishedApiContract,
                published_api(),
            ),
        ],
    );
    let consumer_evidence = evidence(
        &source,
        &semantic,
        &[
            (
                0,
                "rust fixture first",
                BoundaryEvidenceKind::ExportedApiIdentity,
                exported_api(),
            ),
            (
                0,
                "rust fixture first",
                BoundaryEvidenceKind::ResolvedConsumer,
                IntentionalBoundaryEvidenceProof::CompilerSemanticIndex(
                    IntentionalBoundaryCompilerProofKind::IncomingCall,
                ),
            ),
        ],
    );

    let manifest = qualify_intentional_boundary_candidates(
        &protocol(),
        &source,
        &semantic,
        &manifest_evidence,
    )
    .unwrap();
    let consumer = qualify_intentional_boundary_candidates(
        &protocol(),
        &source,
        &semantic,
        &consumer_evidence,
    )
    .unwrap();

    assert_eq!(
        manifest.candidates[0].candidate_id,
        consumer.candidates[0].candidate_id
    );
    assert_ne!(
        manifest.candidate_census_sha256,
        consumer.candidate_census_sha256
    );
}

#[test]
fn names_and_paths_cannot_create_candidates_without_typed_evidence() {
    let (source, semantic) = fixture();
    let evidence = evidence(&source, &semantic, &[]);

    let census =
        qualify_intentional_boundary_candidates(&protocol(), &source, &semantic, &evidence)
            .unwrap();

    assert!(census.candidates.is_empty());
}

#[test]
fn candidate_census_validation_rejects_tampering() {
    let (source, semantic) = fixture();
    let evidence = evidence(
        &source,
        &semantic,
        &[(
            0,
            "rust fixture first",
            BoundaryEvidenceKind::RuntimeOrPackageManifest,
            IntentionalBoundaryEvidenceProof::ManifestContract(
                IntentionalBoundaryManifestProofKind::RuntimeEntrypoint,
            ),
        )],
    );
    let protocol = protocol();
    let mut census =
        qualify_intentional_boundary_candidates(&protocol, &source, &semantic, &evidence).unwrap();
    census.candidates[0].repository_path = "src/other.rs".to_string();

    assert!(
        validate_intentional_boundary_candidate_census(
            &protocol, &source, &semantic, &evidence, &census,
        )
        .unwrap_err()
        .contains("changed")
    );
}
