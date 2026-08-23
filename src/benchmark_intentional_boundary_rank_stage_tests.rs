use super::*;
use crate::benchmark::{
    BoundaryGitObjectFormat, IntentionalBoundaryMaterialization,
    IntentionalBoundaryMaterializationExclusion,
    IntentionalBoundaryMaterializationExclusionEvidence,
    IntentionalBoundaryMaterializationExclusionReason, IntentionalBoundaryRepositoryInventory,
    prepare_intentional_boundary_frame_task,
};
use std::fs;

const POLICY: &[u8] = include_bytes!("../sniffbench/non-blind-v1-selection-policy.json");
const POPULATION: &[u8] = include_bytes!("../sniffbench/non-blind-v1-history-worksheet.json");
const BLIND_SEAL: &[u8] = include_bytes!("../sniffbench/blind-oss-v1-source-seal.json");
const PROTOCOL: &[u8] =
    include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-protocol.json");
const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn task() -> IntentionalBoundaryFrameTask {
    prepare_intentional_boundary_frame_task(POLICY, POPULATION, BLIND_SEAL, PROTOCOL).unwrap()
}

fn materialization(task: &IntentionalBoundaryFrameTask) -> IntentionalBoundaryMaterialization {
    IntentionalBoundaryMaterialization {
        schema_version: 1,
        materialization_contract: "fixture".to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        population_rank: 1,
        population_rank_sha256: task.repositories[0].population_rank_sha256.clone(),
        repository: task.repositories[0].repository.clone(),
        clone_url: "https://example.invalid/repository.git".to_string(),
        revision: "1".repeat(40),
        git_object_format: "sha1".to_string(),
        tree_oid: "2".repeat(40),
        materialization_sha256: HASH_A.to_string(),
    }
}

fn inventory(task: &IntentionalBoundaryFrameTask) -> IntentionalBoundaryRepositoryInventory {
    IntentionalBoundaryRepositoryInventory {
        schema_version: 1,
        inventory_contract: "fixture".to_string(),
        repository: task.repositories[0].repository.clone(),
        revision: "1".repeat(40),
        git_object_format: BoundaryGitObjectFormat::Sha1,
        tracked_entries: Vec::new(),
        inventory_sha256: HASH_B.to_string(),
    }
}

fn exclusion(task: &IntentionalBoundaryFrameTask) -> IntentionalBoundaryMaterializationExclusion {
    IntentionalBoundaryMaterializationExclusion {
        schema_version: 1,
        exclusion_contract: "fixture".to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        population_rank: 1,
        population_rank_sha256: task.repositories[0].population_rank_sha256.clone(),
        repository: task.repositories[0].repository.clone(),
        reason: IntentionalBoundaryMaterializationExclusionReason::RepositoryInaccessible,
        evidence: IntentionalBoundaryMaterializationExclusionEvidence::RepositoryProbe {
            url: "https://example.invalid/repository.git".to_string(),
            status: 404,
        },
        exclusion_sha256: HASH_A.to_string(),
    }
}

fn input<'a>(
    task: &'a IntentionalBoundaryFrameTask,
    stage: IntentionalBoundaryRankStage,
    artifact_kind: IntentionalBoundaryRankStageArtifactKind,
    excluded: bool,
) -> IntentionalBoundaryRankStageCheckpointInput<'a> {
    IntentionalBoundaryRankStageCheckpointInput {
        frame_task_sha256: &task.task_sha256,
        population_rank: 1,
        population_rank_sha256: &task.repositories[0].population_rank_sha256,
        repository: &task.repositories[0].repository,
        stage,
        artifact_kind,
        artifact_sha256: HASH_A,
        excluded,
    }
}

#[test]
fn checkpoint_history_requires_all_twelve_stages_in_exact_order() {
    let task = task();
    let stages = [
        (
            IntentionalBoundaryRankStage::Materialization,
            IntentionalBoundaryRankStageArtifactKind::Materialization,
        ),
        (
            IntentionalBoundaryRankStage::Inventory,
            IntentionalBoundaryRankStageArtifactKind::Inventory,
        ),
        (
            IntentionalBoundaryRankStage::SourceCensus,
            IntentionalBoundaryRankStageArtifactKind::SourceCensus,
        ),
        (
            IntentionalBoundaryRankStage::LicenseCensus,
            IntentionalBoundaryRankStageArtifactKind::LicenseCensus,
        ),
        (
            IntentionalBoundaryRankStage::SemanticCensus,
            IntentionalBoundaryRankStageArtifactKind::SemanticCensus,
        ),
        (
            IntentionalBoundaryRankStage::AstCensus,
            IntentionalBoundaryRankStageArtifactKind::AstCensus,
        ),
        (
            IntentionalBoundaryRankStage::Manifest,
            IntentionalBoundaryRankStageArtifactKind::Manifest,
        ),
        (
            IntentionalBoundaryRankStage::BaseEvidence,
            IntentionalBoundaryRankStageArtifactKind::BaseEvidence,
        ),
        (
            IntentionalBoundaryRankStage::ProjectModel,
            IntentionalBoundaryRankStageArtifactKind::ProjectModel,
        ),
        (
            IntentionalBoundaryRankStage::Generator,
            IntentionalBoundaryRankStageArtifactKind::Generator,
        ),
        (
            IntentionalBoundaryRankStage::Behavior,
            IntentionalBoundaryRankStageArtifactKind::Behavior,
        ),
        (
            IntentionalBoundaryRankStage::Candidate,
            IntentionalBoundaryRankStageArtifactKind::Candidate,
        ),
    ];
    let mut history = Vec::new();
    for (stage, kind) in stages {
        history.push(
            append_intentional_boundary_rank_stage_checkpoint(
                &history,
                input(&task, stage, kind, false),
            )
            .unwrap(),
        );
    }

    validate_intentional_boundary_rank_stage_history(&history).unwrap();
    assert_eq!(history.len(), 12);
    assert_eq!(
        next_intentional_boundary_rank_stage(&history).unwrap(),
        None
    );
    assert_eq!(
        history[11].previous_checkpoint_sha256.as_deref(),
        Some(history[10].checkpoint_sha256.as_str())
    );
}

#[test]
fn wrong_stage_kind_and_prior_hash_mutation_fail_closed() {
    let task = task();
    let wrong_order = append_intentional_boundary_rank_stage_checkpoint(
        &[],
        input(
            &task,
            IntentionalBoundaryRankStage::Inventory,
            IntentionalBoundaryRankStageArtifactKind::Inventory,
            false,
        ),
    )
    .unwrap_err();
    assert!(wrong_order.contains("out of order"));

    let wrong_kind = append_intentional_boundary_rank_stage_checkpoint(
        &[],
        input(
            &task,
            IntentionalBoundaryRankStage::Materialization,
            IntentionalBoundaryRankStageArtifactKind::Inventory,
            false,
        ),
    )
    .unwrap_err();
    assert!(wrong_kind.contains("outcome is invalid"));

    let mut history = vec![
        append_intentional_boundary_rank_stage_checkpoint(
            &[],
            input(
                &task,
                IntentionalBoundaryRankStage::Materialization,
                IntentionalBoundaryRankStageArtifactKind::Materialization,
                false,
            ),
        )
        .unwrap(),
    ];
    history[0].checkpoint_sha256 = HASH_B.to_string();
    assert!(validate_intentional_boundary_rank_stage_history(&history).is_err());
}

#[test]
fn terminal_exclusion_closes_rank_without_a_successor() {
    let task = task();
    let history = vec![
        append_intentional_boundary_rank_stage_checkpoint(
            &[],
            input(
                &task,
                IntentionalBoundaryRankStage::Materialization,
                IntentionalBoundaryRankStageArtifactKind::MaterializationExclusion,
                true,
            ),
        )
        .unwrap(),
    ];
    assert_eq!(
        next_intentional_boundary_rank_stage(&history).unwrap(),
        None
    );
    assert!(
        append_intentional_boundary_rank_stage_checkpoint(
            &history,
            input(
                &task,
                IntentionalBoundaryRankStage::Inventory,
                IntentionalBoundaryRankStageArtifactKind::Inventory,
                false,
            ),
        )
        .unwrap_err()
        .contains("terminal")
    );
}

#[test]
fn durable_journal_resumes_at_the_first_uncommitted_stage() {
    let task = task();
    let state = tempfile::tempdir().unwrap();
    {
        let mut journal =
            IntentionalBoundaryRankStageJournal::open(state.path(), &task, 1).unwrap();
        assert_eq!(
            journal.next_stage().unwrap(),
            Some(IntentionalBoundaryRankStage::Materialization)
        );
        journal
            .append(
                &task,
                &IntentionalBoundaryRankStageArtifact::Materialization(materialization(&task)),
            )
            .unwrap();
    }
    let mut resumed = IntentionalBoundaryRankStageJournal::open(state.path(), &task, 1).unwrap();
    assert_eq!(
        resumed.next_stage().unwrap(),
        Some(IntentionalBoundaryRankStage::Inventory)
    );
    resumed
        .append(
            &task,
            &IntentionalBoundaryRankStageArtifact::Inventory(inventory(&task)),
        )
        .unwrap();
    assert_eq!(
        resumed.next_stage().unwrap(),
        Some(IntentionalBoundaryRankStage::SourceCensus)
    );
}

#[test]
fn torn_staging_is_removed_but_committed_artifact_tampering_is_rejected() {
    let task = task();
    let state = tempfile::tempdir().unwrap();
    {
        let mut journal =
            IntentionalBoundaryRankStageJournal::open(state.path(), &task, 1).unwrap();
        journal
            .append(
                &task,
                &IntentionalBoundaryRankStageArtifact::Materialization(materialization(&task)),
            )
            .unwrap();
    }
    let staging = state.path().join(".rank-0001.incomplete");
    fs::create_dir(&staging).unwrap();
    fs::write(staging.join("partial"), b"torn").unwrap();
    drop(IntentionalBoundaryRankStageJournal::open(state.path(), &task, 1).unwrap());
    assert!(!staging.exists());

    let artifact = state
        .path()
        .join("rank-0001")
        .join("0001-materialization")
        .join("artifact.json");
    fs::write(&artifact, b"{}\n").unwrap();
    let error = IntentionalBoundaryRankStageJournal::open(state.path(), &task, 1).unwrap_err();
    assert_eq!(
        error.kind,
        IntentionalBoundaryRankStageErrorKind::InvalidInput
    );
}

#[test]
fn wrong_rank_artifact_and_active_lock_never_advance_history() {
    let task = task();
    let state = tempfile::tempdir().unwrap();
    let mut journal = IntentionalBoundaryRankStageJournal::open(state.path(), &task, 1).unwrap();
    let mut wrong = materialization(&task);
    wrong.population_rank = 2;
    let error = journal
        .append(
            &task,
            &IntentionalBoundaryRankStageArtifact::Materialization(wrong),
        )
        .unwrap_err();
    assert_eq!(
        error.kind,
        IntentionalBoundaryRankStageErrorKind::InvalidInput
    );
    assert!(journal.history().is_empty());

    let lock_error = IntentionalBoundaryRankStageJournal::open(state.path(), &task, 1).unwrap_err();
    assert_eq!(
        lock_error.kind,
        IntentionalBoundaryRankStageErrorKind::InfrastructureFailed
    );
}

#[test]
fn durable_terminal_exclusion_survives_resume() {
    let task = task();
    let state = tempfile::tempdir().unwrap();
    {
        let mut journal =
            IntentionalBoundaryRankStageJournal::open(state.path(), &task, 1).unwrap();
        journal
            .append(
                &task,
                &IntentionalBoundaryRankStageArtifact::MaterializationExclusion(exclusion(&task)),
            )
            .unwrap();
    }
    let resumed = IntentionalBoundaryRankStageJournal::open(state.path(), &task, 1).unwrap();
    assert_eq!(resumed.next_stage().unwrap(), None);
    assert!(matches!(
        resumed.history()[0].checkpoint.outcome,
        IntentionalBoundaryRankStageOutcome::Excluded { .. }
    ));
}
