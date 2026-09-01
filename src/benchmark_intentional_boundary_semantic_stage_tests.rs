use super::*;
use crate::benchmark::{
    BoundaryGitObjectFormat, IntentionalBoundaryLicenseCensusStage,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundarySemanticCensusExclusionReason,
    IntentionalBoundarySourceCensus,
};
use crate::semantic_indexer_manifest::SemanticIndexerKind;
use crate::semantic_indexer_runner::{
    SemanticIndexerBatchOutcome, SemanticIndexerProcessEvidence, SemanticIndexerRunFailure,
    SemanticIndexerRunFailureKind, SemanticIndexerRunPhase,
};

const TASK: &[u8] =
    include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-frame-task.json");

fn failure(
    kind: SemanticIndexerRunFailureKind,
    indexer: Option<SemanticIndexerKind>,
    detail: &str,
) -> SemanticIndexerRunFailure {
    SemanticIndexerRunFailure {
        kind,
        phase: SemanticIndexerRunPhase::Execution,
        indexer,
        detail: detail.to_string(),
        process: None,
    }
}

fn fixture() -> (
    IntentionalBoundaryFrameTask,
    IntentionalBoundaryMaterialization,
    IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySourceCensusStage,
    IntentionalBoundaryLicenseCensusStage,
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
        repository,
        revision,
        inventory_sha256: inventory.inventory_sha256.clone(),
        tracked_entry_count: 0,
        source_files: Vec::new(),
        source_file_count: 0,
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
    (
        task,
        materialization,
        inventory,
        source_stage,
        license_stage,
    )
}

#[test]
fn preserves_every_terminal_indexer_failure_in_deterministic_order() {
    let run = SemanticIndexerBatchOutcome {
        indexes: Default::default(),
        failures: vec![
            failure(
                SemanticIndexerRunFailureKind::IncompleteOutput,
                Some(SemanticIndexerKind::Rust),
                "incomplete",
            ),
            failure(
                SemanticIndexerRunFailureKind::UnsupportedProjectShape,
                Some(SemanticIndexerKind::Go),
                "unsupported",
            ),
            failure(
                SemanticIndexerRunFailureKind::RepositoryRejected,
                Some(SemanticIndexerKind::Python),
                "rejected",
            ),
        ],
    };
    let resolved = resolve_semantic_run(Ok(run)).unwrap();
    let ResolvedSemanticRun::Excluded(failures) = resolved else {
        panic!("terminal failures must exclude");
    };

    assert_eq!(failures.len(), 3);
    assert_eq!(
        failures
            .iter()
            .map(|failure| failure.indexer)
            .collect::<Vec<_>>(),
        [
            Some(super::super::IntentionalBoundaryIndexerKind::Python),
            Some(super::super::IntentionalBoundaryIndexerKind::Go),
            Some(super::super::IntentionalBoundaryIndexerKind::Rust),
        ]
    );
}

#[test]
fn operational_failure_prevents_terminal_exclusion_without_reason_strings() {
    let run = SemanticIndexerBatchOutcome {
        indexes: Default::default(),
        failures: vec![
            failure(
                SemanticIndexerRunFailureKind::UnsupportedProjectShape,
                Some(SemanticIndexerKind::Go),
                "terminal",
            ),
            failure(
                SemanticIndexerRunFailureKind::InfrastructureUnavailable,
                Some(SemanticIndexerKind::Python),
                "runtime missing",
            ),
            failure(
                SemanticIndexerRunFailureKind::InfrastructureFailed,
                Some(SemanticIndexerKind::Rust),
                "sandbox failed",
            ),
            failure(
                SemanticIndexerRunFailureKind::InvalidInput,
                None,
                "lineage changed",
            ),
        ],
    };
    let error = resolve_semantic_run(Ok(run)).err().unwrap();

    assert_eq!(
        error.kind,
        IntentionalBoundarySemanticCensusStageErrorKind::InvalidInput
    );
    assert!(error.detail.contains("lineage changed"));
    assert!(!error.detail.contains("terminal"));
}

#[test]
fn retains_bounded_process_evidence_with_complete_hashes() {
    let stdout = "x".repeat(5_000);
    let stderr = "y".repeat(5_000);
    let mut run_failure = failure(
        SemanticIndexerRunFailureKind::RepositoryRejected,
        Some(SemanticIndexerKind::Rust),
        &"z".repeat(5_000),
    );
    run_failure.process = Some(Box::new(SemanticIndexerProcessEvidence {
        status_code: Some(2),
        stdout_sha256: sha256(stdout.as_bytes()),
        stderr_sha256: sha256(stderr.as_bytes()),
        stdout,
        stderr,
        timed_out: false,
        memory_limit_exceeded: false,
        process_limit_exceeded: false,
    }));
    let resolved = resolve_semantic_run(Err(run_failure)).unwrap();
    let ResolvedSemanticRun::Excluded(failures) = resolved else {
        panic!("repository rejection must exclude");
    };
    let evidence = &failures[0];
    let process = evidence.process.as_ref().unwrap();

    assert!(evidence.detail_truncated);
    assert_eq!(evidence.retained_detail.len(), 4 * 1024);
    assert!(process.stdout_truncated);
    assert!(process.stderr_truncated);
    assert_eq!(process.retained_stdout.len(), 4 * 1024);
    assert_eq!(process.retained_stderr.len(), 4 * 1024);
}

#[test]
fn seals_completed_and_excluded_lineage_and_exposes_tampering() {
    let (task, materialization, inventory, source, license) = fixture();
    let semantic = super::super::IntentionalBoundarySemanticCensus {
        schema_version: 1,
        semantic_contract: "fixture-semantic".to_string(),
        repository: materialization.repository.clone(),
        revision: materialization.revision.clone(),
        source_census_sha256: source.source_census.census_sha256.clone(),
        indexers: Vec::new(),
        source_references: Vec::new(),
        methods: Vec::new(),
        resolved_method_count: 0,
        compiler_excluded_method_count: 0,
        unresolved_method_count: 0,
        semantic_census_sha256: "2".repeat(64),
    };
    let mut completed = completion(
        &task,
        &materialization,
        &inventory,
        &source,
        &license,
        semantic,
    )
    .unwrap();
    assert_eq!(completed.source_census_stage_sha256, source.stage_sha256);
    assert_eq!(completed.license_census_stage_sha256, license.stage_sha256);
    assert_eq!(completed.stage_sha256.len(), 64);
    completed.semantic_census.semantic_census_sha256 = "3".repeat(64);
    assert_ne!(completed.stage_sha256, stage_sha256(&completed).unwrap());

    let excluded = exclusion(
        &task,
        &materialization,
        &inventory,
        &source,
        &license,
        vec![assembly_failure("assembly changed".to_string())],
    )
    .unwrap();
    assert_eq!(
        excluded.reasons,
        [IntentionalBoundarySemanticCensusExclusionReason::CompilerCensusIncomplete]
    );
    assert_eq!(excluded.exclusion_sha256.len(), 64);
}

#[test]
fn maps_typed_inventory_and_license_errors_exactly() {
    let inventory = map_inventory_error(IntentionalBoundaryInventoryError {
        kind: IntentionalBoundaryInventoryErrorKind::InfrastructureUnavailable,
        detail: "git unavailable".to_string(),
    });
    assert_eq!(
        inventory.kind,
        IntentionalBoundarySemanticCensusStageErrorKind::InfrastructureUnavailable
    );

    let license = map_license_error(IntentionalBoundaryLicenseCensusStageError {
        kind: IntentionalBoundaryLicenseCensusStageErrorKind::InfrastructureFailed,
        detail: "license replay failed".to_string(),
    });
    assert_eq!(
        license.kind,
        IntentionalBoundarySemanticCensusStageErrorKind::InfrastructureFailed
    );
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}
