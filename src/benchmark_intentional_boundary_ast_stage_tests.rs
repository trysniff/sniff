use super::*;
use crate::benchmark::{
    BoundaryGitObjectFormat, IntentionalBoundaryAstCensus, IntentionalBoundaryLicenseCensusStage,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundarySemanticCensus,
    IntentionalBoundarySemanticCensusStage, IntentionalBoundarySourceCensus,
    IntentionalBoundarySourceFile,
};

const TASK: &[u8] =
    include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-frame-task.json");

fn derivation_error(
    kind: super::super::intentional_boundary_ast_outcome::AstDerivationErrorKind,
    language: &str,
    repository_path: Option<&str>,
    detail: &str,
) -> super::super::intentional_boundary_ast_outcome::AstDerivationError {
    super::super::intentional_boundary_ast_outcome::AstDerivationError {
        kind,
        language: language.to_string(),
        repository_path: repository_path.map(str::to_string),
        detail: detail.to_string(),
    }
}

fn ast_census(language: &str, digest: char) -> IntentionalBoundaryAstCensus {
    IntentionalBoundaryAstCensus {
        schema_version: 7,
        ast_contract: "fixture-ast".to_string(),
        repository: "owner/repository".to_string(),
        revision: "a".repeat(40),
        source_census_sha256: "b".repeat(64),
        semantic_census_sha256: "c".repeat(64),
        languages: vec![language.to_string()],
        methods: Vec::new(),
        method_count: 0,
        fact_count: 0,
        ast_census_sha256: digest.to_string().repeat(64),
    }
}

#[allow(clippy::type_complexity)]
fn fixture() -> (
    IntentionalBoundaryFrameTask,
    IntentionalBoundaryMaterialization,
    IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySourceCensusStage,
    IntentionalBoundaryLicenseCensusStage,
    IntentionalBoundarySemanticCensusStage,
) {
    let task: IntentionalBoundaryFrameTask = serde_json::from_slice(TASK).unwrap();
    let repository = task.repositories[0].repository.clone();
    let revision = "a".repeat(40);
    let inventory = IntentionalBoundaryRepositoryInventory {
        schema_version: 1,
        inventory_contract: "fixture-inventory".to_string(),
        repository: repository.clone(),
        revision: revision.clone(),
        git_object_format: BoundaryGitObjectFormat::Sha1,
        tracked_entries: Vec::new(),
        inventory_sha256: "b".repeat(64),
    };
    let materialization = IntentionalBoundaryMaterialization {
        schema_version: 1,
        materialization_contract: "fixture-materialization".to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        population_rank: 1,
        population_rank_sha256: task.repositories[0].population_rank_sha256.clone(),
        repository: repository.clone(),
        clone_url: format!("https://{repository}.git"),
        revision: revision.clone(),
        git_object_format: "sha1".to_string(),
        tree_oid: "c".repeat(40),
        materialization_sha256: "d".repeat(64),
    };
    let source_census = IntentionalBoundarySourceCensus {
        schema_version: 1,
        census_contract: "fixture-source".to_string(),
        repository: repository.clone(),
        revision: revision.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        tracked_entry_count: 0,
        source_files: vec![IntentionalBoundarySourceFile {
            repository_path: "src/lib.rs".to_string(),
            object_id: "4".repeat(40),
            byte_length: 0,
            source_sha256: "5".repeat(64),
            language: "rust".to_string(),
            methods: Vec::new(),
        }],
        source_file_count: 1,
        method_count: 0,
        census_sha256: "e".repeat(64),
    };
    let source_stage = IntentionalBoundarySourceCensusStage {
        schema_version: 1,
        stage_contract: "fixture-source-stage".to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        population_rank: 1,
        materialization_sha256: materialization.materialization_sha256.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        source_extension_contract: "fixture-extensions".to_string(),
        source_census,
        stage_sha256: "f".repeat(64),
    };
    let license_stage = IntentionalBoundaryLicenseCensusStage {
        schema_version: 1,
        stage_contract: "fixture-license-stage".to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        population_rank: 1,
        materialization_sha256: materialization.materialization_sha256.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        source_census_stage_sha256: source_stage.stage_sha256.clone(),
        filename_contract: "fixture-license-policy".to_string(),
        tracked_entry_count: 0,
        matched_candidate_count: 0,
        license_artifacts: Vec::new(),
        rejected_candidates: Vec::new(),
        stage_sha256: "1".repeat(64),
    };
    let semantic = IntentionalBoundarySemanticCensus {
        schema_version: 1,
        semantic_contract: "fixture-semantic".to_string(),
        repository,
        revision,
        source_census_sha256: source_stage.source_census.census_sha256.clone(),
        indexers: Vec::new(),
        source_references: Vec::new(),
        methods: Vec::new(),
        resolved_method_count: 0,
        compiler_excluded_method_count: 0,
        unresolved_method_count: 0,
        semantic_census_sha256: "2".repeat(64),
    };
    let semantic_stage = IntentionalBoundarySemanticCensusStage {
        schema_version: 1,
        stage_contract: "fixture-semantic-stage".to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        population_rank: 1,
        materialization_sha256: materialization.materialization_sha256.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        source_census_stage_sha256: source_stage.stage_sha256.clone(),
        license_census_stage_sha256: license_stage.stage_sha256.clone(),
        semantic_census: semantic,
        stage_sha256: "3".repeat(64),
    };
    (
        task,
        materialization,
        inventory,
        source_stage,
        license_stage,
        semantic_stage,
    )
}

#[test]
fn preserves_every_terminal_failure_in_canonical_order_with_complete_hashes() {
    use super::super::intentional_boundary_ast_outcome::AstDerivationErrorKind;

    let runs = vec![
        Err(derivation_error(
            AstDerivationErrorKind::SourceParserRejected,
            "typescript",
            Some("src/app.ts"),
            &"x".repeat(5_000),
        )),
        Err(derivation_error(
            AstDerivationErrorKind::CensusIncomplete,
            "go",
            Some("main.go"),
            "callable alignment changed",
        )),
    ];
    let resolved = resolve_ast_runs(runs).unwrap();
    let ResolvedAstRun::Excluded(failures) = resolved else {
        panic!("terminal producer failures must exclude");
    };

    assert_eq!(failures.len(), 2);
    assert_eq!(failures[0].language, "go");
    assert_eq!(failures[1].language, "typescript");
    assert_eq!(failures[1].detail_sha256.len(), 64);
    assert_eq!(failures[1].retained_detail.len(), 4 * 1024);
    assert!(failures[1].detail_truncated);
}

#[test]
fn repository_preflight_preserves_every_same_language_parser_failure() {
    let (_, _, _, mut source, _, semantic) = fixture();
    source.source_census.source_files = vec![
        IntentionalBoundarySourceFile {
            repository_path: "src/first.rs".to_string(),
            object_id: "4".repeat(40),
            byte_length: 0,
            source_sha256: "5".repeat(64),
            language: "rust".to_string(),
            methods: Vec::new(),
        },
        IntentionalBoundarySourceFile {
            repository_path: "src/second.rs".to_string(),
            object_id: "6".repeat(40),
            byte_length: 0,
            source_sha256: "7".repeat(64),
            language: "rust".to_string(),
            methods: Vec::new(),
        },
    ];
    let files = vec![
        crate::types::FileRecord {
            file_path: "ignored/absolute/first.rs".to_string(),
            source: "fn first(".to_string(),
            language: "rust".to_string(),
            methods: Vec::new(),
        },
        crate::types::FileRecord {
            file_path: "ignored/absolute/second.rs".to_string(),
            source: "fn second(".to_string(),
            language: "rust".to_string(),
            methods: Vec::new(),
        },
    ];

    let runs = derive_repository_ast_runs(&source.source_census, &semantic.semantic_census, &files);
    let resolved = resolve_ast_runs(runs).unwrap();
    let ResolvedAstRun::Excluded(failures) = resolved else {
        panic!("malformed sources must exclude the repository");
    };

    assert_eq!(failures.len(), 2);
    assert_eq!(failures[0].repository_path.as_deref(), Some("src/first.rs"));
    assert_eq!(
        failures[1].repository_path.as_deref(),
        Some("src/second.rs")
    );
}

#[test]
fn invalid_input_prevents_terminal_exclusion_without_reason_strings() {
    use super::super::intentional_boundary_ast_outcome::AstDerivationErrorKind;

    let runs = vec![
        Err(derivation_error(
            AstDerivationErrorKind::SourceParserRejected,
            "python",
            Some("app.py"),
            "terminal parser rejection",
        )),
        Err(derivation_error(
            AstDerivationErrorKind::InvalidInput,
            "rust",
            None,
            "semantic lineage changed",
        )),
    ];
    let error = resolve_ast_runs(runs).err().unwrap();

    assert_eq!(
        error.kind,
        IntentionalBoundaryAstCensusStageErrorKind::InvalidInput
    );
    assert_eq!(error.detail, "semantic lineage changed");
    assert!(!error.detail.contains("terminal parser rejection"));
}

#[test]
fn completion_sorts_languages_and_rejects_duplicate_censuses() {
    let resolved =
        resolve_ast_runs(vec![Ok(ast_census("rust", '4')), Ok(ast_census("go", '5'))]).unwrap();
    let ResolvedAstRun::Completed(censuses) = resolved else {
        panic!("valid AST runs must complete");
    };
    assert_eq!(censuses[0].languages, ["go"]);
    assert_eq!(censuses[1].languages, ["rust"]);

    let error = resolve_ast_runs(vec![Ok(ast_census("go", '6')), Ok(ast_census("go", '7'))])
        .err()
        .unwrap();
    assert_eq!(
        error.kind,
        IntentionalBoundaryAstCensusStageErrorKind::InvalidInput
    );
}

#[test]
fn seals_completed_and_excluded_lineage_and_exposes_tampering() {
    use super::super::intentional_boundary_ast_outcome::AstDerivationErrorKind;

    let (task, materialization, inventory, source, license, semantic) = fixture();
    let completed = finish_ast_stage(
        &task,
        &materialization,
        &inventory,
        &source,
        &license,
        &semantic,
        vec![Ok(ast_census("rust", '8'))],
    )
    .unwrap();
    let IntentionalBoundaryAstCensusStageOutcome::Completed(mut completed) = completed else {
        panic!("valid AST census must complete");
    };
    assert_eq!(
        completed.semantic_census_stage_sha256,
        semantic.stage_sha256
    );
    assert_eq!(completed.stage_sha256.len(), 64);
    completed.ast_censuses[0].ast_census_sha256 = "9".repeat(64);
    assert_ne!(completed.stage_sha256, stage_sha256(&completed).unwrap());

    let omitted = finish_ast_stage(
        &task,
        &materialization,
        &inventory,
        &source,
        &license,
        &semantic,
        Vec::new(),
    )
    .err()
    .unwrap();
    assert_eq!(
        omitted.kind,
        IntentionalBoundaryAstCensusStageErrorKind::InvalidInput
    );

    let excluded = finish_ast_stage(
        &task,
        &materialization,
        &inventory,
        &source,
        &license,
        &semantic,
        vec![Err(derivation_error(
            AstDerivationErrorKind::CensusIncomplete,
            "rust",
            Some("src/lib.rs"),
            "alignment changed",
        ))],
    )
    .unwrap();
    let IntentionalBoundaryAstCensusStageOutcome::Excluded(excluded) = excluded else {
        panic!("terminal AST failure must exclude");
    };
    assert_eq!(excluded.exclusion_sha256.len(), 64);
    assert_eq!(excluded.semantic_census_stage_sha256, semantic.stage_sha256);
}

#[test]
fn maps_typed_semantic_and_inventory_errors_exactly() {
    let semantic = map_semantic_error(IntentionalBoundarySemanticCensusStageError {
        kind: IntentionalBoundarySemanticCensusStageErrorKind::InfrastructureUnavailable,
        detail: "indexer unavailable".to_string(),
    });
    assert_eq!(
        semantic.kind,
        IntentionalBoundaryAstCensusStageErrorKind::InfrastructureUnavailable
    );

    let inventory = map_inventory_error(IntentionalBoundaryInventoryError {
        kind: IntentionalBoundaryInventoryErrorKind::InfrastructureFailed,
        detail: "git object read failed".to_string(),
    });
    assert_eq!(
        inventory.kind,
        IntentionalBoundaryAstCensusStageErrorKind::InfrastructureFailed
    );
}

#[test]
fn unknown_source_language_fails_closed_without_fallback() {
    let (_, _, _, mut source, _, semantic) = fixture();
    source
        .source_census
        .source_files
        .push(IntentionalBoundarySourceFile {
            repository_path: "src/app.unknown".to_string(),
            object_id: "a".repeat(40),
            byte_length: 0,
            language: "unknown".to_string(),
            source_sha256: "b".repeat(64),
            methods: Vec::new(),
        });
    let files = vec![
        crate::types::FileRecord {
            file_path: "ignored/absolute/lib.rs".to_string(),
            source: String::new(),
            language: "rust".to_string(),
            methods: Vec::new(),
        },
        crate::types::FileRecord {
            file_path: "ignored/absolute/app.unknown".to_string(),
            source: String::new(),
            language: "unknown".to_string(),
            methods: Vec::new(),
        },
    ];
    let runs = derive_repository_ast_runs(&source.source_census, &semantic.semantic_census, &files);
    let error = resolve_ast_runs(runs).err().unwrap();
    assert_eq!(
        error.kind,
        IntentionalBoundaryAstCensusStageErrorKind::InvalidInput
    );
    assert!(error.detail.contains("unsupported language unknown"));
}
