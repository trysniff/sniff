use super::*;
use crate::semantic_index::{
    RepositoryPath, SemanticDocument, SemanticIndexProvenance, SemanticLocation,
    SemanticOccurrence, SemanticOccurrenceRole, SemanticPosition, SemanticPositionEncoding,
    SemanticSourceRange, SemanticSurface, SemanticSymbol, SemanticSymbolCategory, SemanticSymbolId,
    SemanticSymbolKind, SemanticSymbolOrigin, SemanticTextEncoding, SemanticVisibility,
};
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn commits_exact_compiler_facts_for_every_historical_method() {
    let fixture = fixture();
    let snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &fixture.indexes,
    )
    .unwrap();

    assert_eq!(snapshot.resolved_method_count, 1);
    assert_eq!(snapshot.compiler_excluded_method_count, 0);
    assert_eq!(snapshot.unresolved_method_count, 0);
    assert_eq!(snapshot.methods[0].parser_unit_id, "h2m-v1:fixture");
    assert_eq!(snapshot.indexers[0].tool_name, "fixture-indexer");
    assert_eq!(snapshot.public_symbol_count, 1);
    assert_eq!(
        snapshot.public_symbols[0].symbol.symbol_id,
        "rust fixture process"
    );
    validation::validate_snapshot("example/repo", &fixture.source, &snapshot).unwrap();
}

#[test]
fn generated_files_are_committed_but_not_required_from_the_compiler_index() {
    let mut fixture = fixture();
    let mut generated = fixture.source.source_files[0].clone();
    generated.repository_path = "public/angular.min.js".to_string();
    generated.language = "javascript".to_string();
    generated.semantic_coverage = HistoricalV2SourceSemanticCoverage::GeneratedPath;
    generated.methods[0].parser_unit_id = "h2m-v1:generated".to_string();
    fixture.source.source_files.push(generated);
    fixture.source.source_file_count += 1;
    fixture.source.method_count += 1;
    *fixture
        .source
        .method_counts_by_language
        .entry("javascript".to_string())
        .or_default() += 1;

    let snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &fixture.indexes,
    )
    .unwrap();

    assert_eq!(snapshot.methods.len(), 1);
    assert_eq!(snapshot.methods[0].parser_unit_id, "h2m-v1:fixture");
    validation::validate_snapshot("example/repo", &fixture.source, &snapshot).unwrap();
}

#[test]
fn semantic_validation_rejects_recommitted_invented_method() {
    let fixture = fixture();
    let mut snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &fixture.indexes,
    )
    .unwrap();
    snapshot.methods[0].parser_unit_id = "invented".to_string();
    snapshot.semantic_snapshot_sha256 = semantic_snapshot_sha256(&snapshot).unwrap();

    assert!(
        validation::validate_snapshot("example/repo", &fixture.source, &snapshot)
            .unwrap_err()
            .contains("invented")
    );
}

#[test]
fn semantic_census_requires_the_exact_language_indexer_set() {
    let fixture = fixture();
    let error = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &BTreeMap::new(),
    )
    .unwrap_err();

    assert!(error.contains("indexer set is incomplete"));
}

#[test]
fn semantic_validation_rejects_recommitted_fake_public_surface() {
    let fixture = fixture();
    let mut snapshot = build_semantic_snapshot(
        fixture.root.path(),
        &fixture.source,
        &fixture.files,
        &fixture.indexes,
    )
    .unwrap();
    snapshot.public_symbols[0].symbol.origin =
        super::super::IntentionalBoundarySemanticOrigin::External;
    snapshot.semantic_snapshot_sha256 = semantic_snapshot_sha256(&snapshot).unwrap();

    assert!(
        validation::validate_snapshot("example/repo", &fixture.source, &snapshot)
            .unwrap_err()
            .contains("public semantic symbol")
    );
}

#[test]
fn repository_rejection_becomes_hash_bound_terminal_evidence() {
    let detail = "rust-analyzer rejected the repository";
    let stdout = "compiler output";
    let stderr = "invalid manifest";
    let evidence = indexer_failure_evidence(
        HistoricalV2SemanticSnapshotSide::Base,
        &"a".repeat(40),
        SemanticIndexerRunFailure {
            kind: SemanticIndexerRunFailureKind::RepositoryRejected,
            phase: SemanticIndexerRunPhase::Execution,
            indexer: Some(SemanticIndexerKind::Rust),
            detail: detail.to_string(),
            process: Some(Box::new(SemanticIndexerProcessEvidence {
                status_code: Some(1),
                stdout: stdout.to_string(),
                stderr: stderr.to_string(),
                stdout_sha256: sha256(stdout.as_bytes()),
                stderr_sha256: sha256(stderr.as_bytes()),
                timed_out: false,
            })),
        },
    )
    .unwrap();
    let exclusion =
        seal_semantic_census_exclusion(&"b".repeat(64), &"c".repeat(64), vec![evidence]).unwrap();

    assert_eq!(
        exclusion.reasons,
        vec![HistoricalV2SemanticCensusExclusionReason::CompilerIndexerRejectedRepository]
    );
    assert_eq!(
        exclusion.failures[0].indexer,
        Some(IntentionalBoundaryIndexerKind::Rust)
    );
    assert_eq!(
        exclusion.failures[0]
            .process
            .as_ref()
            .unwrap()
            .stderr_sha256,
        sha256(stderr.as_bytes())
    );
    super::super::validate_historical_v2_semantic_census_exclusion(&exclusion).unwrap();
}

#[test]
fn infrastructure_failure_cannot_be_sealed_as_candidate_exclusion() {
    let error = indexer_failure_evidence(
        HistoricalV2SemanticSnapshotSide::Patched,
        &"a".repeat(40),
        SemanticIndexerRunFailure {
            kind: SemanticIndexerRunFailureKind::InfrastructureUnavailable,
            phase: SemanticIndexerRunPhase::InstallationVerification,
            indexer: Some(SemanticIndexerKind::Python),
            detail: "pinned scip-python installation is unavailable".to_string(),
            process: None,
        },
    )
    .unwrap_err();

    assert_eq!(error.stage, HistoricalV2SlotStage::SemanticCensus);
    assert_eq!(
        error.kind,
        HistoricalV2SlotStageErrorKind::InfrastructureUnavailable
    );
}

#[test]
fn semantic_exclusion_commits_all_sides_and_rejects_tampering() {
    let mut failures = Vec::new();
    let base = resolve_snapshot_build(
        HistoricalV2SemanticSnapshotSide::Base,
        &"a".repeat(40),
        Err("base compiler census omitted a method".to_string()),
        &mut failures,
    );
    let patched = resolve_snapshot_build(
        HistoricalV2SemanticSnapshotSide::Patched,
        &"b".repeat(40),
        Err("patched compiler census invented a symbol".to_string()),
        &mut failures,
    );
    assert!(base.is_none() && patched.is_none());
    let mut exclusion =
        seal_semantic_census_exclusion(&"c".repeat(64), &"d".repeat(64), failures).unwrap();
    assert_eq!(exclusion.failures.len(), 2);
    assert_eq!(
        exclusion.reasons,
        vec![HistoricalV2SemanticCensusExclusionReason::CompilerCensusIncomplete]
    );

    exclusion.failures[0].revision = "e".repeat(40);
    assert!(super::super::validate_historical_v2_semantic_census_exclusion(&exclusion).is_err());
}

#[test]
fn mixed_language_snapshot_retains_every_indexer_failure() {
    let mut failures = Vec::new();
    let mut stage_errors = Vec::new();
    let indexes = resolve_indexer_run(
        HistoricalV2SemanticSnapshotSide::Base,
        &"a".repeat(40),
        Ok(SemanticIndexerBatchOutcome {
            indexes: BTreeMap::new(),
            failures: vec![
                SemanticIndexerRunFailure {
                    kind: SemanticIndexerRunFailureKind::UnsupportedProjectShape,
                    phase: SemanticIndexerRunPhase::RepositoryValidation,
                    indexer: Some(SemanticIndexerKind::Kotlin),
                    detail: "Android Gradle module is unsupported".to_string(),
                    process: None,
                },
                SemanticIndexerRunFailure {
                    kind: SemanticIndexerRunFailureKind::IncompleteOutput,
                    phase: SemanticIndexerRunPhase::OutputValidation,
                    indexer: Some(SemanticIndexerKind::Rust),
                    detail: "rust-analyzer omitted a source document".to_string(),
                    process: Some(Box::new(SemanticIndexerProcessEvidence {
                        status_code: Some(0),
                        stdout: String::new(),
                        stderr: String::new(),
                        stdout_sha256: sha256(b""),
                        stderr_sha256: sha256(b""),
                        timed_out: false,
                    })),
                },
            ],
        }),
        &mut failures,
        &mut stage_errors,
    );

    assert!(indexes.is_none());
    assert!(stage_errors.is_empty());
    assert_eq!(failures.len(), 2);
    let exclusion =
        seal_semantic_census_exclusion(&"b".repeat(64), &"c".repeat(64), failures).unwrap();
    assert_eq!(
        exclusion.reasons,
        vec![
            HistoricalV2SemanticCensusExclusionReason::UnsupportedProjectShape,
            HistoricalV2SemanticCensusExclusionReason::CompilerCensusIncomplete,
        ]
    );
}

#[test]
fn one_infrastructure_failure_prevents_mixed_batch_exclusion() {
    let mut failures = Vec::new();
    let mut stage_errors = Vec::new();
    let indexes = resolve_indexer_run(
        HistoricalV2SemanticSnapshotSide::Patched,
        &"a".repeat(40),
        Ok(SemanticIndexerBatchOutcome {
            indexes: BTreeMap::new(),
            failures: vec![
                SemanticIndexerRunFailure {
                    kind: SemanticIndexerRunFailureKind::UnsupportedProjectShape,
                    phase: SemanticIndexerRunPhase::RepositoryValidation,
                    indexer: Some(SemanticIndexerKind::Kotlin),
                    detail: "unsupported project".to_string(),
                    process: None,
                },
                SemanticIndexerRunFailure {
                    kind: SemanticIndexerRunFailureKind::InfrastructureFailed,
                    phase: SemanticIndexerRunPhase::Cleanup,
                    indexer: Some(SemanticIndexerKind::Rust),
                    detail: "sandbox cleanup failed".to_string(),
                    process: None,
                },
            ],
        }),
        &mut failures,
        &mut stage_errors,
    );

    assert!(indexes.is_none());
    assert_eq!(failures.len(), 1);
    assert_eq!(stage_errors.len(), 1);
    assert_eq!(
        combine_stage_errors(stage_errors).kind,
        HistoricalV2SlotStageErrorKind::InfrastructureFailed
    );
}

struct Fixture {
    root: tempfile::TempDir,
    source: HistoricalV2SourceSnapshotCensus,
    files: Vec<FileRecord>,
    indexes: BTreeMap<SemanticIndexerKind, SemanticIndex>,
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("src")).unwrap();
    let source_text = "pub fn process(value: i32) -> i32 { value }\n";
    let absolute = root.path().join("src/lib.rs");
    std::fs::write(&absolute, source_text).unwrap();
    let files = vec![
        crate::parser::parse_source_checked(&absolute.to_string_lossy(), source_text.as_bytes())
            .unwrap(),
    ];
    let method = &files[0].methods[0];
    let source = HistoricalV2SourceSnapshotCensus {
        revision: "a".repeat(40),
        inventory_sha256: "b".repeat(64),
        parser_census_sha256: "c".repeat(64),
        tracked_entry_count: 1,
        source_files: vec![super::super::HistoricalV2SourceFile {
            repository_path: "src/lib.rs".to_string(),
            object_id: "d".repeat(40),
            byte_length: source_text.len() as u64,
            source_sha256: sha256(source_text.as_bytes()),
            non_whitespace_lines: 1,
            language: "rust".to_string(),
            semantic_coverage: HistoricalV2SourceSemanticCoverage::Required,
            methods: vec![super::super::HistoricalV2SourceMethod {
                parser_unit_id: "h2m-v1:fixture".to_string(),
                symbol_name: method.name.clone(),
                start_line: method.start_line,
                end_line: method.end_line,
                source_sha256: sha256(method.source.as_bytes()),
                is_exported: method.is_exported,
            }],
        }],
        source_file_count: 1,
        method_counts_by_language: BTreeMap::from([("rust".to_string(), 1)]),
        method_count: 1,
        snapshot_census_sha256: "e".repeat(64),
    };
    let document = RepositoryPath("src/lib.rs".to_string());
    let symbol_id = SemanticSymbolId("rust fixture process".to_string());
    let definition = SemanticLocation {
        document: document.clone(),
        range: range(0, 7, 14),
    };
    let symbol = SemanticSymbol {
        id: symbol_id.clone(),
        provider_identity: symbol_id.0.clone(),
        display_name: Some("process".to_string()),
        kind: SemanticSymbolKind {
            category: SemanticSymbolCategory::Callable,
            provider_name: "function".to_string(),
        },
        documentation: Vec::new(),
        signature: None,
        owner: None,
        definitions: BTreeSet::from([definition]),
        visibility: SemanticVisibility::Public,
        surfaces: BTreeSet::from([SemanticSurface::PublicApi]),
        origin: SemanticSymbolOrigin::Repository,
        ambiguity_notes: Vec::new(),
    };
    let index = SemanticIndex {
        format_version: 1,
        repository_root: root.path().to_string_lossy().replace('\\', "/"),
        provenance: SemanticIndexProvenance {
            format: "scip".to_string(),
            tool_name: "fixture-indexer".to_string(),
            tool_version: Some("1.0.0".to_string()),
            arguments: Vec::new(),
            source_text_encoding: Some(SemanticTextEncoding::Utf8),
            diagnostics: Vec::new(),
        },
        documents: BTreeMap::from([(
            document.clone(),
            SemanticDocument {
                path: document,
                language: "rust".to_string(),
                position_encoding: SemanticPositionEncoding::Utf8,
                embedded_text: None,
                occurrences: vec![SemanticOccurrence {
                    range: range(0, 7, 14),
                    symbol: Some(symbol_id.clone()),
                    roles: BTreeSet::from([SemanticOccurrenceRole::Definition]),
                    override_documentation: Vec::new(),
                }],
            },
        )]),
        symbols: BTreeMap::from([(symbol_id, symbol)]),
        relationships: BTreeSet::new(),
        imports: BTreeSet::new(),
        calls: BTreeSet::new(),
        test_relationships: BTreeSet::new(),
        unresolved_edges: BTreeSet::new(),
    };
    Fixture {
        root,
        source,
        files,
        indexes: BTreeMap::from([(SemanticIndexerKind::Rust, index)]),
    }
}

fn range(line: u32, start: u32, end: u32) -> SemanticSourceRange {
    SemanticSourceRange {
        start: SemanticPosition {
            line,
            character: start,
        },
        end: SemanticPosition {
            line,
            character: end,
        },
    }
}
