use super::*;
use crate::benchmark::{
    IntentionalBoundaryFrameExclusionReason, IntentionalBoundaryMaterializationExclusion,
    IntentionalBoundaryMaterializationExclusionEvidence,
    IntentionalBoundaryMaterializationExclusionReason, IntentionalBoundaryRankRunDisposition,
    IntentionalBoundaryRankStageArtifact, IntentionalBoundaryRankStageErrorKind,
    IntentionalBoundaryRankStageJournal, IntentionalBoundaryRepositoryInventory,
    load_intentional_boundary_frame_ranks, prepare_intentional_boundary_excluded_rank,
    prepare_intentional_boundary_frame_task, reconcile_intentional_boundary_frame_rank,
    run_intentional_boundary_rank, run_intentional_boundary_rank_slice,
    validate_intentional_boundary_protocol,
};
use std::fs;
use std::num::NonZeroUsize;
use std::process::Command;

const POLICY: &[u8] = include_bytes!("../sniffbench/non-blind-v1-selection-policy.json");
const POPULATION: &[u8] = include_bytes!("../sniffbench/non-blind-v1-history-worksheet.json");
const BLIND_SEAL: &[u8] = include_bytes!("../sniffbench/blind-oss-v1-source-seal.json");
const PROTOCOL: &[u8] =
    include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-protocol.json");
const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_HASH: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[tokio::test]
async fn terminal_exclusion_reconciles_idempotently_before_checkout_cleanup() {
    let task = task();
    let protocol = protocol();
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let work = root.path().join("work");
    let frame = root.path().join("frame");
    let mut executor =
        IntentionalBoundaryProductionRankExecutor::new(&protocol, &state, &work, &frame, None)
            .unwrap();
    let checkout = work.join("rank-0001");
    fs::create_dir(&checkout).unwrap();
    fs::write(checkout.join("partial"), b"partial").unwrap();
    {
        let mut journal = IntentionalBoundaryRankStageJournal::open(&state, &task, 1).unwrap();
        journal
            .append(
                &task,
                &IntentionalBoundaryRankStageArtifact::MaterializationExclusion(exclusion(&task)),
            )
            .unwrap();
    }

    let first = run_intentional_boundary_rank(&state, &task, 1, &mut executor)
        .await
        .unwrap();
    assert!(matches!(
        first.disposition,
        IntentionalBoundaryRankRunDisposition::Excluded {
            stage: IntentionalBoundaryRankStage::Materialization,
            ..
        }
    ));
    assert!(!checkout.exists());
    let records = load_intentional_boundary_frame_ranks(&frame, &task).unwrap();
    assert_eq!(records.len(), 1);
    assert!(matches!(
        records[0].outcome,
        super::super::IntentionalBoundaryFrameRankOutcome::Excluded {
            reason: IntentionalBoundaryFrameExclusionReason::RepositoryInaccessible,
            ..
        }
    ));

    let replay = run_intentional_boundary_rank(&state, &task, 1, &mut executor)
        .await
        .unwrap();
    assert!(replay.executed_stages.is_empty());
    assert_eq!(
        load_intentional_boundary_frame_ranks(&frame, &task).unwrap(),
        records
    );
}

#[tokio::test]
async fn terminal_frame_conflict_preserves_checkout_and_committed_journal() {
    let task = task();
    let protocol = protocol();
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let work = root.path().join("work");
    let frame = root.path().join("frame");
    let mut executor =
        IntentionalBoundaryProductionRankExecutor::new(&protocol, &state, &work, &frame, None)
            .unwrap();
    let checkout = work.join("rank-0001");
    fs::create_dir(&checkout).unwrap();
    fs::write(checkout.join("sentinel"), b"preserve").unwrap();
    let conflicting = prepare_intentional_boundary_excluded_rank(
        &task,
        1,
        IntentionalBoundaryFrameExclusionReason::RepositoryInaccessible,
        OTHER_HASH,
    )
    .unwrap();
    reconcile_intentional_boundary_frame_rank(&frame, &task, &conflicting).unwrap();
    {
        let mut journal = IntentionalBoundaryRankStageJournal::open(&state, &task, 1).unwrap();
        journal
            .append(
                &task,
                &IntentionalBoundaryRankStageArtifact::MaterializationExclusion(exclusion(&task)),
            )
            .unwrap();
    }

    let error = run_intentional_boundary_rank(&state, &task, 1, &mut executor)
        .await
        .unwrap_err();

    assert_eq!(
        error.kind,
        IntentionalBoundaryRankStageErrorKind::InvalidInput
    );
    assert!(error.detail.contains("conflicts with its committed record"));
    assert_eq!(fs::read(checkout.join("sentinel")).unwrap(), b"preserve");
    let journal = IntentionalBoundaryRankStageJournal::open(&state, &task, 1).unwrap();
    assert_eq!(journal.history().len(), 1);
    assert_eq!(
        load_intentional_boundary_frame_ranks(&frame, &task).unwrap(),
        [conflicting]
    );
}

#[tokio::test]
async fn terminal_frame_io_failure_is_typed_and_preserves_checkout() {
    let task = task();
    let protocol = protocol();
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let work = root.path().join("work");
    let frame = root.path().join("frame");
    let mut executor =
        IntentionalBoundaryProductionRankExecutor::new(&protocol, &state, &work, &frame, None)
            .unwrap();
    let checkout = work.join("rank-0001");
    fs::create_dir(&checkout).unwrap();
    fs::write(checkout.join("sentinel"), b"preserve").unwrap();
    fs::remove_dir(&frame).unwrap();
    fs::write(&frame, b"not a directory").unwrap();
    {
        let mut journal = IntentionalBoundaryRankStageJournal::open(&state, &task, 1).unwrap();
        journal
            .append(
                &task,
                &IntentionalBoundaryRankStageArtifact::MaterializationExclusion(exclusion(&task)),
            )
            .unwrap();
    }

    let error = run_intentional_boundary_rank(&state, &task, 1, &mut executor)
        .await
        .unwrap_err();

    assert_eq!(
        error.kind,
        IntentionalBoundaryRankStageErrorKind::InfrastructureFailed
    );
    assert_eq!(fs::read(checkout.join("sentinel")).unwrap(), b"preserve");
    let journal = IntentionalBoundaryRankStageJournal::open(&state, &task, 1).unwrap();
    assert_eq!(journal.history().len(), 1);
}

#[tokio::test]
async fn committed_materialization_drives_the_real_inventory_stage_offline() {
    let task = task();
    let protocol = protocol();
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let work = root.path().join("work");
    let frame = root.path().join("frame");
    let mut executor =
        IntentionalBoundaryProductionRankExecutor::new(&protocol, &state, &work, &frame, None)
            .unwrap();
    let source = committed_repository();
    let destination = work.join("rank-0001");
    let materialized = super::super::intentional_boundary_materialization::
        materialize_intentional_boundary_repository_fixture(
            &task,
            1,
            &destination,
            source.path(),
        )
        .unwrap();
    let IntentionalBoundaryMaterializationOutcome::Completed(materialized) = materialized else {
        panic!("fixture repository must materialize");
    };
    {
        let mut journal = IntentionalBoundaryRankStageJournal::open(&state, &task, 1).unwrap();
        journal
            .append(
                &task,
                &IntentionalBoundaryRankStageArtifact::Materialization(
                    materialized.artifact.clone(),
                ),
            )
            .unwrap();
    }

    let summary =
        run_intentional_boundary_rank_slice(&state, &task, 1, &mut executor, NonZeroUsize::new(1))
            .await
            .unwrap();
    assert_eq!(
        summary.executed_stages,
        [IntentionalBoundaryRankStage::Inventory]
    );
    assert_eq!(
        summary.disposition,
        IntentionalBoundaryRankRunDisposition::Paused {
            next_stage: IntentionalBoundaryRankStage::SourceCensus,
        }
    );
    let journal = IntentionalBoundaryRankStageJournal::open(&state, &task, 1).unwrap();
    assert_eq!(journal.history().len(), 2);
    let IntentionalBoundaryRankStageArtifact::Inventory(IntentionalBoundaryRepositoryInventory {
        repository,
        revision,
        ..
    }) = &journal.history()[1].artifact
    else {
        panic!("second production artifact must be inventory");
    };
    assert_eq!(repository, &materialized.artifact.repository);
    assert_eq!(revision, &materialized.artifact.revision);
}

#[tokio::test]
async fn materialization_recovery_removes_only_the_exact_rank_checkout() {
    let task = task();
    let protocol = protocol();
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let work = root.path().join("work");
    let frame = root.path().join("frame");
    let mut executor =
        IntentionalBoundaryProductionRankExecutor::new(&protocol, &state, &work, &frame, None)
            .unwrap();
    let checkout = work.join("rank-0001");
    let sibling = work.join("keep");
    fs::create_dir(&checkout).unwrap();
    fs::create_dir(&sibling).unwrap();
    fs::write(checkout.join("partial"), b"partial").unwrap();
    fs::write(sibling.join("sentinel"), b"keep").unwrap();

    executor
        .recover(IntentionalBoundaryRankStageContext {
            task: &task,
            repository_task: &task.repositories[0],
            stage: IntentionalBoundaryRankStage::Materialization,
            history: &[],
        })
        .await
        .unwrap();

    assert!(!checkout.exists());
    assert_eq!(fs::read(sibling.join("sentinel")).unwrap(), b"keep");
}

#[test]
fn production_roots_reject_overlap_before_stage_execution() {
    let protocol = protocol();
    let root = tempfile::tempdir().unwrap();
    let shared = root.path().join("shared");
    let frame = root.path().join("frame");

    let error = match IntentionalBoundaryProductionRankExecutor::new(
        &protocol, &shared, &shared, &frame, None,
    ) {
        Ok(_) => panic!("overlapping production roots must fail"),
        Err(error) => error,
    };

    assert_eq!(
        error.kind,
        IntentionalBoundaryRankStageErrorKind::InvalidInput
    );
    assert!(error.detail.contains("must not overlap"));
    assert!(!shared.exists());
}

#[tokio::test]
async fn production_sweep_rejects_protocol_mismatch_before_creating_roots() {
    let task = task();
    let mut protocol = protocol();
    protocol.protocol_sha256 = OTHER_HASH.to_string();
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let work = root.path().join("work");
    let frame = root.path().join("frame");

    let error =
        run_intentional_boundary_production_sweep(IntentionalBoundaryProductionSweepInputs {
            protocol: &protocol,
            task: &task,
            state_root: &state,
            work_root: &work,
            frame_root: &frame,
            github_token: None,
            maximum_new_stages_per_rank: None,
            through_stage: None,
        })
        .await
        .unwrap_err();

    assert_eq!(
        error.kind,
        IntentionalBoundaryRankStageErrorKind::InvalidInput
    );
    assert!(error.detail.contains("does not match"));
    assert!(!state.exists());
    assert!(!work.exists());
    assert!(!frame.exists());
}

fn task() -> super::super::IntentionalBoundaryFrameTask {
    prepare_intentional_boundary_frame_task(POLICY, POPULATION, BLIND_SEAL, PROTOCOL).unwrap()
}

fn protocol() -> super::super::ValidatedIntentionalBoundaryProtocol {
    validate_intentional_boundary_protocol(POLICY, POPULATION, BLIND_SEAL, PROTOCOL).unwrap()
}

fn exclusion(
    task: &super::super::IntentionalBoundaryFrameTask,
) -> IntentionalBoundaryMaterializationExclusion {
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
        exclusion_sha256: HASH.to_string(),
    }
}

fn committed_repository() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    run_git(root.path(), &["init"]);
    run_git(
        root.path(),
        &["config", "user.email", "fixture@example.invalid"],
    );
    run_git(root.path(), &["config", "user.name", "Fixture"]);
    fs::create_dir(root.path().join("src")).unwrap();
    fs::write(root.path().join("LICENSE"), "MIT License\n").unwrap();
    fs::write(
        root.path().join("src/lib.rs"),
        "pub fn value() -> u8 { 1 }\n",
    )
    .unwrap();
    run_git(root.path(), &["add", "."]);
    run_git(root.path(), &["commit", "-m", "fixture"]);
    root
}

fn run_git(root: &std::path::Path, arguments: &[&str]) {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
