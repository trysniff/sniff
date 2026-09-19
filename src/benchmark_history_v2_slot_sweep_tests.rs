use super::super::history_v2_exclusions::seal_historical_v2_exclusion_manifest;
use super::super::history_v2_payload_commitment::{
    seal_historical_v2_selected_payload, seal_historical_v2_selected_payloads,
};
use super::*;
use crate::benchmark::{
    HISTORICAL_V2_EXCLUSION_MANIFEST_SCHEMA_VERSION, HISTORICAL_V2_FRAME_SCHEMA_VERSION,
    HISTORICAL_V2_SELECTED_PAYLOADS_SCHEMA_VERSION, HistoricalV2ExclusionArtifact,
    HistoricalV2ExclusionManifest, HistoricalV2ExecutionError, HistoricalV2Frame,
    HistoricalV2IdenticalTestExecutionRequest, HistoricalV2IdenticalTestExecutor,
    HistoricalV2PartitionExclusions, HistoricalV2ProjectedRow,
    HistoricalV2QualificationExclusionReason, HistoricalV2RawIdenticalTestExecution,
    HistoricalV2RecoverableTestExecutor, HistoricalV2SelectedPayload, HistoricalV2SelectedPayloads,
    HistoricalV2SlotStageCheckpointInput, HistoricalV2SlotStageErrorKind,
    HistoricalV2SlotStageJournal, HistoricalV2SlotStageOutcome, HistoricalV2StageArtifactKind,
    HistoricalV2TerminalExclusionReason, derive_historical_v2_frame_record,
    historical_v2_frame_sha256, select_historical_v2_slots,
};
use sha2::{Digest, Sha256};

const PROTOCOL: &[u8] = include_bytes!("../sniffbench/historical-v2-protocol.json");
const PARTITIONS: [&str; 6] = [
    "blind-oss-v1",
    "historical-v1",
    "intentional-boundary-v1",
    "slopcodebench",
    "synthetic-gold-v1",
    "trim",
];
const PATCH: &str = "diff --git a/src/app.py b/src/app.py\n--- a/src/app.py\n+++ b/src/app.py\n@@ -1,2 +1 @@\n-old_one = prepare()\n-old_two = finish(old_one)\n+result = finish(prepare())\n";
const RUST_PATCH: &str = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,2 +1 @@\n-let old_one = prepare();\n-let old_two = finish(old_one);\n+let result = finish(prepare());\n";

#[test]
fn quota_headroom_distinguishes_possible_from_impossible_without_replay() {
    let protocol = validate_historical_v2_protocol(PROTOCOL).unwrap();
    let slots = |excluded_count: usize| {
        (1..=128)
            .map(|slot_number| {
                let excluded = slot_number <= excluded_count;
                HistoricalV2SelectedSlotStateInspection {
                    language: "go".to_string(),
                    slot_number,
                    canonical_repository: format!("example/slot-{slot_number}"),
                    committed_stage_count: usize::from(excluded),
                    latest_committed_stage: excluded.then_some(HistoricalV2SlotStage::Qualification),
                    latest_committed_outcome: excluded.then(|| HistoricalV2SlotStageOutcome::Excluded {
                        reason: HistoricalV2TerminalExclusionReason::Qualification(vec![
                            HistoricalV2QualificationExclusionReason::RepositoryMethodCountAboveMaximum,
                        ]),
                        artifact_kind: HistoricalV2StageArtifactKind::Qualification,
                        artifact_sha256: "a".repeat(64),
                    }),
                    next_stage: (!excluded).then_some(HistoricalV2SlotStage::Payload),
                    incomplete_initialization: false,
                    incomplete_stage_transaction: false,
                    incomplete_rewind_transaction: false,
                }
            })
            .collect::<Vec<_>>()
    };

    let still_possible = quota_headroom(&protocol, &slots(88));
    let go = still_possible
        .iter()
        .find(|quota| quota.language == "go")
        .unwrap();
    assert_eq!(go.maximum_accepted_without_replay, 40);
    assert!(go.reachable_without_replay);

    let impossible = quota_headroom(&protocol, &slots(89));
    let go = impossible
        .iter()
        .find(|quota| quota.language == "go")
        .unwrap();
    assert_eq!(go.maximum_accepted_without_replay, 39);
    assert!(!go.reachable_without_replay);
}

#[test]
fn quota_headroom_counts_unfilled_slots_as_unavailable() {
    let protocol = validate_historical_v2_protocol(PROTOCOL).unwrap();
    let slots = (1..=126)
        .map(|slot_number| HistoricalV2SelectedSlotStateInspection {
            language: "go".to_string(),
            slot_number,
            canonical_repository: format!("example/slot-{slot_number}"),
            committed_stage_count: 1,
            latest_committed_stage: Some(HistoricalV2SlotStage::Qualification),
            latest_committed_outcome: (slot_number <= 125).then(|| {
                HistoricalV2SlotStageOutcome::Excluded {
                    reason: HistoricalV2TerminalExclusionReason::Qualification(vec![
                        HistoricalV2QualificationExclusionReason::RepositoryMethodCountAboveMaximum,
                    ]),
                    artifact_kind: HistoricalV2StageArtifactKind::Qualification,
                    artifact_sha256: "a".repeat(64),
                }
            }),
            next_stage: (slot_number == 126).then_some(HistoricalV2SlotStage::Payload),
            incomplete_initialization: false,
            incomplete_stage_transaction: false,
            incomplete_rewind_transaction: false,
        })
        .collect::<Vec<_>>();
    let headroom = quota_headroom(&protocol, &slots);
    let go = headroom
        .iter()
        .find(|quota| quota.language == "go")
        .unwrap();
    assert_eq!(go.fixed_slot_count, 128);
    assert_eq!(go.selected_slot_count, 126);
    assert_eq!(go.terminal_excluded_count, 125);
    assert_eq!(go.maximum_accepted_without_replay, 1);
    assert!(!go.reachable_without_replay);
}

#[test]
fn quota_headroom_does_not_settle_an_interrupted_rewind() {
    let protocol = validate_historical_v2_protocol(PROTOCOL).unwrap();
    let mut slots = (1..=128)
        .map(|slot_number| HistoricalV2SelectedSlotStateInspection {
            language: "go".to_string(),
            slot_number,
            canonical_repository: format!("example/slot-{slot_number}"),
            committed_stage_count: 1,
            latest_committed_stage: Some(HistoricalV2SlotStage::Qualification),
            latest_committed_outcome: Some(HistoricalV2SlotStageOutcome::Excluded {
                reason: HistoricalV2TerminalExclusionReason::Qualification(vec![
                    HistoricalV2QualificationExclusionReason::RepositoryMethodCountAboveMaximum,
                ]),
                artifact_kind: HistoricalV2StageArtifactKind::Qualification,
                artifact_sha256: "a".repeat(64),
            }),
            next_stage: None,
            incomplete_initialization: false,
            incomplete_stage_transaction: false,
            incomplete_rewind_transaction: false,
        })
        .collect::<Vec<_>>();
    slots[0].incomplete_rewind_transaction = true;

    let headroom = quota_headroom(&protocol, &slots);
    let go = headroom
        .iter()
        .find(|quota| quota.language == "go")
        .unwrap();
    assert_eq!(go.terminal_excluded_count, 127);
    assert_eq!(go.maximum_accepted_without_replay, 1);
}

#[tokio::test]
async fn one_stage_sweep_persists_every_selected_payload_without_external_execution() {
    let fixture = Fixture::new();
    let client = reqwest::Client::builder().build().unwrap();
    let mutable = tempfile::tempdir().unwrap();
    let state_root = mutable.path().join("state");
    let work_root = mutable.path().join("work");
    let harness = tempfile::tempdir().unwrap();
    let executor = ForbiddenExecutor;

    let summary = run_historical_v2_selected_slots_bounded(
        HistoricalV2SelectedSlotSweepInputs {
            client: &client,
            protocol_bytes: PROTOCOL,
            artifact_root: fixture.artifacts.path(),
            frame: &fixture.frame,
            exclusions: &fixture.exclusions,
            selection: &fixture.selection,
            payloads: &fixture.payloads,
            state_root: &state_root,
            work_root: &work_root,
            harness_repository_root: harness.path(),
            test_executor: &executor,
            through_stage: Some(HistoricalV2SlotStage::Payload),
        },
        1,
        None,
    )
    .await
    .unwrap();

    assert_eq!(summary.selected_slot_count, 1);
    assert_eq!(summary.newly_admitted_slot_count, 1);
    assert_eq!(summary.paused_count, 1);
    assert_eq!(summary.ready_for_review_count, 0);
    assert_eq!(summary.excluded_count, 0);
    assert_eq!(summary.slots[0].language, "python");
    assert!(matches!(
        summary.slots[0].run.disposition,
        HistoricalV2SlotRunDisposition::Paused {
            next_stage: HistoricalV2SlotStage::Materialization
        }
    ));
    let journal = HistoricalV2SlotStageJournal::open(&state_root, "python", 1).unwrap();
    assert_eq!(journal.history().len(), 1);
    assert_eq!(
        journal.history()[0].checkpoint.stage,
        HistoricalV2SlotStage::Payload
    );
    drop(journal);

    let resumed = run_historical_v2_selected_slots_bounded(
        HistoricalV2SelectedSlotSweepInputs {
            client: &client,
            protocol_bytes: PROTOCOL,
            artifact_root: fixture.artifacts.path(),
            frame: &fixture.frame,
            exclusions: &fixture.exclusions,
            selection: &fixture.selection,
            payloads: &fixture.payloads,
            state_root: &state_root,
            work_root: &work_root,
            harness_repository_root: harness.path(),
            test_executor: &executor,
            through_stage: Some(HistoricalV2SlotStage::Payload),
        },
        0,
        None,
    )
    .await
    .unwrap();
    assert_eq!(resumed.paused_count, 1);
    assert_eq!(resumed.newly_admitted_slot_count, 0);
    assert_eq!(resumed.slots[0].run.resumed_after_sequence, 1);
    assert!(resumed.slots[0].run.executed_stages.is_empty());
}

#[tokio::test]
async fn bounded_sweep_admits_only_the_declared_number_of_new_slots() {
    let fixture = Fixture::with_selected_count(2);
    let client = reqwest::Client::builder().build().unwrap();
    let mutable = tempfile::tempdir().unwrap();
    let state_root = mutable.path().join("state");
    let work_root = mutable.path().join("work");
    let harness = tempfile::tempdir().unwrap();
    let executor = ForbiddenExecutor;

    let run = || HistoricalV2SelectedSlotSweepInputs {
        client: &client,
        protocol_bytes: PROTOCOL,
        artifact_root: fixture.artifacts.path(),
        frame: &fixture.frame,
        exclusions: &fixture.exclusions,
        selection: &fixture.selection,
        payloads: &fixture.payloads,
        state_root: &state_root,
        work_root: &work_root,
        harness_repository_root: harness.path(),
        test_executor: &executor,
        through_stage: Some(HistoricalV2SlotStage::Payload),
    };

    let first = run_historical_v2_selected_slots_bounded(run(), 1, None)
        .await
        .unwrap();
    assert_eq!(first.selected_slot_count, 2);
    assert_eq!(first.newly_admitted_slot_count, 1);
    assert_eq!(first.paused_count, 2);
    assert_eq!(
        first
            .slots
            .iter()
            .map(|slot| slot.run.executed_stages.len())
            .sum::<usize>(),
        1
    );
    assert_eq!(persisted_slot_count(&state_root), 1);

    let resume_only = run_historical_v2_selected_slots_bounded(run(), 0, None)
        .await
        .unwrap();
    assert_eq!(resume_only.newly_admitted_slot_count, 0);
    assert_eq!(
        resume_only
            .slots
            .iter()
            .map(|slot| slot.run.executed_stages.len())
            .sum::<usize>(),
        0
    );
    assert_eq!(persisted_slot_count(&state_root), 1);

    let second = run_historical_v2_selected_slots_bounded(run(), 1, None)
        .await
        .unwrap();
    assert_eq!(second.newly_admitted_slot_count, 1);
    assert_eq!(
        second
            .slots
            .iter()
            .map(|slot| slot.run.executed_stages.len())
            .sum::<usize>(),
        1
    );
    assert_eq!(persisted_slot_count(&state_root), 2);
}

#[tokio::test]
async fn bounded_sweep_rejects_malformed_language_state_before_admitting_a_slot() {
    let fixture = Fixture::with_patches(&[PATCH, RUST_PATCH]);
    let client = reqwest::Client::builder().build().unwrap();
    let mutable = tempfile::tempdir().unwrap();
    let state_root = mutable.path().join("state");
    let work_root = mutable.path().join("work");
    let harness = tempfile::tempdir().unwrap();
    let executor = ForbiddenExecutor;
    fs::create_dir(&state_root).unwrap();
    fs::write(state_root.join("rust"), b"not a directory").unwrap();

    let error = run_historical_v2_selected_slots_bounded(
        HistoricalV2SelectedSlotSweepInputs {
            client: &client,
            protocol_bytes: PROTOCOL,
            artifact_root: fixture.artifacts.path(),
            frame: &fixture.frame,
            exclusions: &fixture.exclusions,
            selection: &fixture.selection,
            payloads: &fixture.payloads,
            state_root: &state_root,
            work_root: &work_root,
            harness_repository_root: harness.path(),
            test_executor: &executor,
            through_stage: Some(HistoricalV2SlotStage::Payload),
        },
        1,
        None,
    )
    .await
    .unwrap_err();

    assert_eq!(error.kind, HistoricalV2SlotStageErrorKind::InvalidInput);
    assert!(
        error
            .detail
            .contains("language state must be a plain directory")
    );
    assert!(!state_root.join("python").exists());
}

#[tokio::test]
async fn bounded_sweep_rejects_a_malformed_unadmitted_slot_marker() {
    let fixture = Fixture::with_selected_count(2);
    let client = reqwest::Client::builder().build().unwrap();
    let mutable = tempfile::tempdir().unwrap();
    let state_root = mutable.path().join("state");
    let work_root = mutable.path().join("work");
    let harness = tempfile::tempdir().unwrap();
    let executor = ForbiddenExecutor;
    fs::create_dir_all(state_root.join("python")).unwrap();
    fs::create_dir(state_root.join("python/slot-0002.lock")).unwrap();

    let error = run_historical_v2_selected_slots_bounded(
        HistoricalV2SelectedSlotSweepInputs {
            client: &client,
            protocol_bytes: PROTOCOL,
            artifact_root: fixture.artifacts.path(),
            frame: &fixture.frame,
            exclusions: &fixture.exclusions,
            selection: &fixture.selection,
            payloads: &fixture.payloads,
            state_root: &state_root,
            work_root: &work_root,
            harness_repository_root: harness.path(),
            test_executor: &executor,
            through_stage: Some(HistoricalV2SlotStage::Payload),
        },
        1,
        None,
    )
    .await
    .unwrap_err();

    assert_eq!(error.kind, HistoricalV2SlotStageErrorKind::InvalidInput);
    assert!(error.detail.contains("wrong entry type"));
    assert!(
        !state_root.join("python/slot-0001").exists(),
        "all selected slot markers must be validated before admission"
    );
}

fn persisted_slot_count(state_root: &Path) -> usize {
    fs::read_dir(state_root.join("python"))
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| {
            entry.file_type().unwrap().is_dir()
                && entry.file_name().to_string_lossy().starts_with("slot-")
        })
        .count()
}

#[tokio::test]
async fn state_inspection_reports_exact_committed_and_incomplete_progress() {
    let fixture = Fixture::new();
    let client = reqwest::Client::builder().build().unwrap();
    let mutable = tempfile::tempdir().unwrap();
    let state_root = mutable.path().join("state");
    let work_root = mutable.path().join("work");
    let harness = tempfile::tempdir().unwrap();
    let executor = ForbiddenExecutor;
    run_historical_v2_selected_slots_bounded(
        HistoricalV2SelectedSlotSweepInputs {
            client: &client,
            protocol_bytes: PROTOCOL,
            artifact_root: fixture.artifacts.path(),
            frame: &fixture.frame,
            exclusions: &fixture.exclusions,
            selection: &fixture.selection,
            payloads: &fixture.payloads,
            state_root: &state_root,
            work_root: &work_root,
            harness_repository_root: harness.path(),
            test_executor: &executor,
            through_stage: Some(HistoricalV2SlotStage::Payload),
        },
        1,
        None,
    )
    .await
    .unwrap();
    let payload = &fixture.payloads.records[0];
    let staging = state_root
        .join(&payload.language)
        .join(format!(".slot-{:04}.incomplete", payload.slot_number));
    fs::create_dir(&staging).unwrap();

    let summary =
        inspect_historical_v2_selected_slot_state(HistoricalV2SelectedSlotStateInspectionInputs {
            protocol_bytes: PROTOCOL,
            artifact_root: fixture.artifacts.path(),
            frame: &fixture.frame,
            exclusions: &fixture.exclusions,
            selection: &fixture.selection,
            payloads: &fixture.payloads,
            state_root: &state_root,
        })
        .unwrap();

    assert_eq!(summary.selected_slot_count, 1);
    assert_eq!(summary.started_slot_count, 1);
    assert_eq!(summary.terminal_slot_count, 0);
    assert_eq!(summary.incomplete_slot_count, 1);
    assert_eq!(summary.slots[0].committed_stage_count, 1);
    assert_eq!(
        summary.slots[0].latest_committed_stage,
        Some(HistoricalV2SlotStage::Payload)
    );
    assert_eq!(
        summary.slots[0].next_stage,
        Some(HistoricalV2SlotStage::Materialization)
    );
    assert!(summary.slots[0].incomplete_stage_transaction);
    assert!(staging.is_dir());
}

#[test]
fn state_inspection_reports_unstarted_selected_slots_without_creating_state() {
    let fixture = Fixture::new();
    let mutable = tempfile::tempdir().unwrap();
    let state_root = mutable.path().join("state");
    fs::create_dir(&state_root).unwrap();

    let summary =
        inspect_historical_v2_selected_slot_state(HistoricalV2SelectedSlotStateInspectionInputs {
            protocol_bytes: PROTOCOL,
            artifact_root: fixture.artifacts.path(),
            frame: &fixture.frame,
            exclusions: &fixture.exclusions,
            selection: &fixture.selection,
            payloads: &fixture.payloads,
            state_root: &state_root,
        })
        .unwrap();

    assert_eq!(summary.selected_slot_count, 1);
    assert_eq!(summary.started_slot_count, 0);
    assert_eq!(summary.incomplete_slot_count, 0);
    assert_eq!(summary.slots[0].committed_stage_count, 0);
    assert_eq!(
        summary.slots[0].next_stage,
        Some(HistoricalV2SlotStage::Payload)
    );
    assert_eq!(fs::read_dir(&state_root).unwrap().count(), 0);
}

#[test]
fn state_inspection_reports_interrupted_slot_initialization_without_mutation() {
    let fixture = Fixture::new();
    let mutable = tempfile::tempdir().unwrap();
    let state_root = mutable.path().join("state");
    let payload = &fixture.payloads.records[0];
    let language_root = state_root.join(&payload.language);
    fs::create_dir_all(&language_root).unwrap();
    let lock = language_root.join(format!("slot-{:04}.lock", payload.slot_number));
    fs::write(&lock, b"").unwrap();

    let summary =
        inspect_historical_v2_selected_slot_state(HistoricalV2SelectedSlotStateInspectionInputs {
            protocol_bytes: PROTOCOL,
            artifact_root: fixture.artifacts.path(),
            frame: &fixture.frame,
            exclusions: &fixture.exclusions,
            selection: &fixture.selection,
            payloads: &fixture.payloads,
            state_root: &state_root,
        })
        .unwrap();

    assert_eq!(summary.started_slot_count, 1);
    assert_eq!(summary.incomplete_slot_count, 1);
    assert!(summary.slots[0].incomplete_initialization);
    assert!(lock.is_file());
    assert!(!language_root.join("slot-0001").exists());
}

#[test]
fn state_inspection_rejects_a_slot_journal_without_its_lock() {
    let fixture = Fixture::new();
    let mutable = tempfile::tempdir().unwrap();
    let state_root = mutable.path().join("state");
    let payload = &fixture.payloads.records[0];
    fs::create_dir_all(
        state_root
            .join(&payload.language)
            .join(format!("slot-{:04}", payload.slot_number)),
    )
    .unwrap();

    let error =
        inspect_historical_v2_selected_slot_state(HistoricalV2SelectedSlotStateInspectionInputs {
            protocol_bytes: PROTOCOL,
            artifact_root: fixture.artifacts.path(),
            frame: &fixture.frame,
            exclusions: &fixture.exclusions,
            selection: &fixture.selection,
            payloads: &fixture.payloads,
            state_root: &state_root,
        })
        .unwrap_err();

    assert_eq!(error.kind, HistoricalV2SlotStageErrorKind::InvalidInput);
    assert!(error.detail.contains("impossible initialization shape"));
}

#[test]
fn sweep_rejects_overlapping_mutable_roots() {
    let root = tempfile::tempdir().unwrap();
    let shared = root.path().join("shared");
    let artifact = tempfile::tempdir().unwrap();
    let harness = tempfile::tempdir().unwrap();

    let error = SweepRoots::prepare(&shared, &shared, artifact.path(), harness.path()).unwrap_err();

    assert_eq!(error.kind, HistoricalV2SlotStageErrorKind::InvalidInput);
    assert!(
        error
            .detail
            .contains("state and work roots must not overlap")
    );
    assert!(!shared.exists());
}

#[test]
fn selected_slot_work_recovery_removes_only_proven_semantic_and_source_state() {
    let fixture = Fixture::new();
    let mutable = tempfile::tempdir().unwrap();
    let work_root = mutable.path().join("work");
    fs::create_dir(&work_root).unwrap();
    let payload = &fixture.payloads.records[0];
    let slot_root = work_root
        .join(&payload.language)
        .join(format!("slot-{:04}", payload.slot_number));
    let repository = slot_root.join("repository");
    let patched = slot_root.join("patched");
    for root in [&repository, &patched] {
        fs::create_dir_all(root).unwrap();
        crate::semantic_indexer_runner::install_test_semantic_recovery_marker(root).unwrap();
        fs::create_dir(root.join(".sniff-indexer-tmp")).unwrap();
        fs::write(root.join(".sniff-indexer-tmp/cache"), b"transient").unwrap();
    }
    let semantic_progress = slot_root.join("semantic-progress");
    for side in ["base", "patched"] {
        fs::create_dir_all(semantic_progress.join(side)).unwrap();
    }
    let interrupted_snapshot = semantic_progress.join("base/snapshot.json.tmp");
    fs::write(&interrupted_snapshot, b"partial").unwrap();
    let source_progress = slot_root.join("source-progress");
    for side in ["base", "patched"] {
        fs::create_dir_all(source_progress.join(side)).unwrap();
    }
    let interrupted_source = source_progress.join("patched/go-project-model.json.tmp");
    fs::write(&interrupted_source, b"partial").unwrap();
    fs::create_dir(slot_root.join("base-tested")).unwrap();

    let summary =
        recover_historical_v2_selected_slot_work(HistoricalV2SelectedSlotWorkRecoveryInputs {
            protocol_bytes: PROTOCOL,
            artifact_root: fixture.artifacts.path(),
            frame: &fixture.frame,
            exclusions: &fixture.exclusions,
            selection: &fixture.selection,
            payloads: &fixture.payloads,
            work_root: &work_root,
        })
        .unwrap();

    assert_eq!(summary.selected_slot_count, 1);
    assert_eq!(summary.materialized_semantic_root_count, 2);
    assert_eq!(summary.recovered_semantic_root_count, 2);
    assert!(summary.semantic_worlds.is_empty());
    assert!(summary.semantic_checkpoints.is_empty());
    for root in [&repository, &patched] {
        assert!(!root.join(".sniff-indexer-recovery.json").exists());
        assert!(!root.join(".sniff-indexer-tmp").exists());
    }
    assert!(semantic_progress.is_dir());
    assert!(!interrupted_snapshot.exists());
    assert!(source_progress.is_dir());
    assert!(!interrupted_source.exists());
    assert!(slot_root.join("base-tested").is_dir());
}

#[test]
fn selected_slot_work_recovery_rejects_unknown_layout_before_mutation() {
    let fixture = Fixture::new();
    let mutable = tempfile::tempdir().unwrap();
    let work_root = mutable.path().join("work");
    fs::create_dir(&work_root).unwrap();
    let payload = &fixture.payloads.records[0];
    let language_root = work_root.join(&payload.language);
    let repository = language_root
        .join(format!("slot-{:04}", payload.slot_number))
        .join("repository");
    fs::create_dir_all(&repository).unwrap();
    crate::semantic_indexer_runner::install_test_semantic_recovery_marker(&repository).unwrap();
    fs::create_dir(repository.join(".sniff-indexer-tmp")).unwrap();
    fs::create_dir(language_root.join("slot-9999")).unwrap();

    let error =
        recover_historical_v2_selected_slot_work(HistoricalV2SelectedSlotWorkRecoveryInputs {
            protocol_bytes: PROTOCOL,
            artifact_root: fixture.artifacts.path(),
            frame: &fixture.frame,
            exclusions: &fixture.exclusions,
            selection: &fixture.selection,
            payloads: &fixture.payloads,
            work_root: &work_root,
        })
        .unwrap_err();

    assert_eq!(error.stage, HistoricalV2SlotStage::SemanticCensus);
    assert_eq!(error.kind, HistoricalV2SlotStageErrorKind::InvalidInput);
    assert!(error.detail.contains("unselected slot"));
    assert!(repository.join(".sniff-indexer-recovery.json").is_file());
    assert!(repository.join(".sniff-indexer-tmp").is_dir());
}

#[test]
fn public_surface_replay_preserves_materializations_and_rewinds_only_stale_censuses() {
    let fixture = Fixture::new();
    let mutable = tempfile::tempdir().unwrap();
    let state_root = mutable.path().join("state");
    let work_root = mutable.path().join("work");
    fs::create_dir(&work_root).unwrap();
    let payload = &fixture.payloads.records[0];
    let canonical_repository = fixture
        .selection
        .slots
        .iter()
        .find_map(|slot| match &slot.outcome {
            HistoricalV2SlotOutcome::Selected {
                canonical_repository,
                ..
            } if slot.language == payload.language && slot.slot_number == payload.slot_number => {
                Some(canonical_repository.clone())
            }
            _ => None,
        })
        .unwrap();
    {
        let mut journal =
            HistoricalV2SlotStageJournal::open(&state_root, &payload.language, payload.slot_number)
                .unwrap();
        for (stage, artifact_kind) in [
            (
                HistoricalV2SlotStage::Payload,
                HistoricalV2StageArtifactKind::SelectedPayload,
            ),
            (
                HistoricalV2SlotStage::Materialization,
                HistoricalV2StageArtifactKind::Materialization,
            ),
            (
                HistoricalV2SlotStage::TestMaterialization,
                HistoricalV2StageArtifactKind::NoTestPatch,
            ),
            (
                HistoricalV2SlotStage::SourceCensus,
                HistoricalV2StageArtifactKind::SourceCensus,
            ),
            (
                HistoricalV2SlotStage::SemanticCensus,
                HistoricalV2StageArtifactKind::SemanticCensus,
            ),
        ] {
            journal
                .append(
                    HistoricalV2SlotStageCheckpointInput {
                        selection_sha256: &fixture.selection.selection_sha256,
                        language: &payload.language,
                        slot_number: payload.slot_number,
                        canonical_repository: &canonical_repository,
                        stage,
                        outcome: HistoricalV2SlotStageOutcome::Completed {
                            artifact_kind,
                            artifact_sha256: "a".repeat(64),
                        },
                    },
                    Some(&serde_json::json!({"stage": format!("{stage:?}")})),
                )
                .unwrap();
        }
    }
    let slot_root = work_root
        .join(&payload.language)
        .join(format!("slot-{:04}", payload.slot_number));
    for name in [
        "base-tested",
        "patched",
        "patched-tested",
        "repository",
        "semantic-progress",
        "source-progress",
    ] {
        fs::create_dir_all(slot_root.join(name)).unwrap();
    }
    fs::write(slot_root.join("semantic-progress/snapshot.json"), b"stale").unwrap();
    fs::write(slot_root.join("source-progress/inventory.json"), b"stale").unwrap();

    let summary =
        replay_historical_v2_public_surface_census(HistoricalV2PublicSurfaceReplayInputs {
            state_root: &state_root,
            work_root: &work_root,
            selection_sha256: &fixture.selection.selection_sha256,
            language: &payload.language,
            slot_number: payload.slot_number,
            canonical_repository: &canonical_repository,
        })
        .unwrap();

    assert_eq!(summary.removed_stage_count, 2);
    assert!(summary.removed_semantic_progress);
    assert!(summary.removed_source_progress);
    assert!(!slot_root.join("semantic-progress").exists());
    assert!(!slot_root.join("source-progress").exists());
    assert!(
        !slot_root
            .join(".semantic-progress.public-surface-replay")
            .exists()
    );
    assert!(
        !slot_root
            .join(".source-progress.public-surface-replay")
            .exists()
    );
    for name in ["base-tested", "patched", "patched-tested", "repository"] {
        assert!(slot_root.join(name).is_dir(), "{name}");
    }
    let journal = HistoricalV2SlotStageJournal::open_existing(
        &state_root,
        &payload.language,
        payload.slot_number,
    )
    .unwrap();
    assert_eq!(journal.history().len(), 3);
    assert_eq!(
        journal.history().last().unwrap().checkpoint.stage,
        HistoricalV2SlotStage::TestMaterialization
    );
}

#[test]
fn compiler_census_replay_reopens_only_the_proven_incomplete_terminal() {
    let fixture = Fixture::new();
    let mutable = tempfile::tempdir().unwrap();
    let state_root = mutable.path().join("state");
    let work_root = mutable.path().join("work");
    fs::create_dir(&work_root).unwrap();
    let payload = &fixture.payloads.records[0];
    let canonical_repository = fixture
        .selection
        .slots
        .iter()
        .find_map(|slot| match &slot.outcome {
            HistoricalV2SlotOutcome::Selected {
                canonical_repository,
                ..
            } if slot.language == payload.language && slot.slot_number == payload.slot_number => {
                Some(canonical_repository.clone())
            }
            _ => None,
        })
        .unwrap();
    {
        let mut journal =
            HistoricalV2SlotStageJournal::open(&state_root, &payload.language, payload.slot_number)
                .unwrap();
        for (stage, artifact_kind) in [
            (
                HistoricalV2SlotStage::Payload,
                HistoricalV2StageArtifactKind::SelectedPayload,
            ),
            (
                HistoricalV2SlotStage::Materialization,
                HistoricalV2StageArtifactKind::Materialization,
            ),
            (
                HistoricalV2SlotStage::TestMaterialization,
                HistoricalV2StageArtifactKind::NoTestPatch,
            ),
            (
                HistoricalV2SlotStage::SourceCensus,
                HistoricalV2StageArtifactKind::SourceCensus,
            ),
        ] {
            journal
                .append(
                    HistoricalV2SlotStageCheckpointInput {
                        selection_sha256: &fixture.selection.selection_sha256,
                        language: &payload.language,
                        slot_number: payload.slot_number,
                        canonical_repository: &canonical_repository,
                        stage,
                        outcome: HistoricalV2SlotStageOutcome::Completed {
                            artifact_kind,
                            artifact_sha256: "a".repeat(64),
                        },
                    },
                    Some(&serde_json::json!({"stage": format!("{stage:?}")})),
                )
                .unwrap();
        }
        journal
            .append(
                HistoricalV2SlotStageCheckpointInput {
                    selection_sha256: &fixture.selection.selection_sha256,
                    language: &payload.language,
                    slot_number: payload.slot_number,
                    canonical_repository: &canonical_repository,
                    stage: HistoricalV2SlotStage::SemanticCensus,
                    outcome: HistoricalV2SlotStageOutcome::Excluded {
                        reason: HistoricalV2TerminalExclusionReason::SemanticCensus(vec![
                            HistoricalV2SemanticCensusExclusionReason::CompilerCensusIncomplete,
                        ]),
                        artifact_kind: HistoricalV2StageArtifactKind::SemanticCensusExclusion,
                        artifact_sha256: "b".repeat(64),
                    },
                },
                Some(&serde_json::json!({"reason": "compiler_census_incomplete"})),
            )
            .unwrap();
    }
    let slot_root = work_root
        .join(&payload.language)
        .join(format!("slot-{:04}", payload.slot_number));
    for name in [
        "base-tested",
        "patched",
        "patched-tested",
        "repository",
        "semantic-progress",
        "source-progress",
    ] {
        fs::create_dir_all(slot_root.join(name)).unwrap();
    }
    fs::write(slot_root.join("semantic-progress/snapshot.json"), b"stale").unwrap();
    fs::write(slot_root.join("source-progress/inventory.json"), b"stale").unwrap();

    let error = replay_historical_v2_compiler_census(HistoricalV2CompilerCensusReplayInputs {
        state_root: &state_root,
        work_root: &work_root,
        selection_sha256: &fixture.selection.selection_sha256,
        language: &payload.language,
        slot_number: payload.slot_number,
        canonical_repository: &canonical_repository,
    })
    .unwrap_err();
    assert!(error.detail.contains("requires cleaned terminal slot work"));
    assert!(slot_root.join("semantic-progress/snapshot.json").is_file());
    let journal = HistoricalV2SlotStageJournal::open_existing(
        &state_root,
        &payload.language,
        payload.slot_number,
    )
    .unwrap();
    assert_eq!(journal.history().len(), 5);
    drop(journal);

    fs::remove_dir_all(&slot_root).unwrap();
    let summary = replay_historical_v2_compiler_census(HistoricalV2CompilerCensusReplayInputs {
        state_root: &state_root,
        work_root: &work_root,
        selection_sha256: &fixture.selection.selection_sha256,
        language: &payload.language,
        slot_number: payload.slot_number,
        canonical_repository: &canonical_repository,
    })
    .unwrap();

    assert_eq!(summary.removed_stage_count, 4);
    assert_eq!(summary.retained_stage, HistoricalV2SlotStage::Payload);
    assert!(!summary.removed_semantic_progress);
    assert!(!summary.removed_source_progress);
    assert!(!slot_root.join("semantic-progress").exists());
    assert!(!slot_root.join("source-progress").exists());
    let journal = HistoricalV2SlotStageJournal::open_existing(
        &state_root,
        &payload.language,
        payload.slot_number,
    )
    .unwrap();
    assert_eq!(journal.history().len(), 1);
}

#[test]
fn go_semantic_coverage_replay_removes_only_partial_semantic_progress() {
    let fixture = Fixture::new();
    let mutable = tempfile::tempdir().unwrap();
    let state_root = mutable.path().join("state");
    let work_root = mutable.path().join("work");
    fs::create_dir(&work_root).unwrap();
    let language = "go";
    let slot_number = 124;
    let canonical_repository = "example/go-semantic-coverage";
    {
        let mut journal =
            HistoricalV2SlotStageJournal::open(&state_root, language, slot_number).unwrap();
        for (stage, artifact_kind) in [
            (
                HistoricalV2SlotStage::Payload,
                HistoricalV2StageArtifactKind::SelectedPayload,
            ),
            (
                HistoricalV2SlotStage::Materialization,
                HistoricalV2StageArtifactKind::Materialization,
            ),
            (
                HistoricalV2SlotStage::TestMaterialization,
                HistoricalV2StageArtifactKind::NoTestPatch,
            ),
            (
                HistoricalV2SlotStage::SourceCensus,
                HistoricalV2StageArtifactKind::SourceCensus,
            ),
        ] {
            journal
                .append(
                    HistoricalV2SlotStageCheckpointInput {
                        selection_sha256: &fixture.selection.selection_sha256,
                        language,
                        slot_number,
                        canonical_repository,
                        stage,
                        outcome: HistoricalV2SlotStageOutcome::Completed {
                            artifact_kind,
                            artifact_sha256: "a".repeat(64),
                        },
                    },
                    Some(&serde_json::json!({"stage": format!("{stage:?}")})),
                )
                .unwrap();
        }
    }
    let slot_root = work_root
        .join(language)
        .join(format!("slot-{slot_number:04}"));
    for name in [
        "base-tested",
        "patched",
        "patched-tested",
        "repository",
        "semantic-progress",
        "source-progress",
    ] {
        fs::create_dir_all(slot_root.join(name)).unwrap();
    }
    fs::write(slot_root.join("semantic-progress/snapshot.json"), b"stale").unwrap();
    fs::write(
        slot_root.join("source-progress/inventory.json"),
        b"retained",
    )
    .unwrap();

    let summary =
        replay_historical_v2_go_semantic_coverage(HistoricalV2GoSemanticCoverageReplayInputs {
            state_root: &state_root,
            work_root: &work_root,
            selection_sha256: &fixture.selection.selection_sha256,
            language,
            slot_number,
            canonical_repository,
        })
        .unwrap();

    assert_eq!(summary.removed_stage_count, 0);
    assert_eq!(summary.retained_stage, HistoricalV2SlotStage::SourceCensus);
    assert!(summary.removed_semantic_progress);
    assert!(!summary.removed_source_progress);
    assert!(!slot_root.join("semantic-progress").exists());
    assert!(slot_root.join("source-progress/inventory.json").is_file());
    assert!(
        !slot_root
            .join(".semantic-progress.go-semantic-coverage-replay")
            .exists()
    );
    let journal =
        HistoricalV2SlotStageJournal::open_existing(&state_root, language, slot_number).unwrap();
    assert_eq!(journal.history().len(), 4);
    assert_eq!(
        journal.history().last().unwrap().checkpoint.stage,
        HistoricalV2SlotStage::SourceCensus
    );
}

#[test]
fn go_semantic_coverage_replay_rejects_other_languages() {
    let mutable = tempfile::tempdir().unwrap();
    let error =
        replay_historical_v2_go_semantic_coverage(HistoricalV2GoSemanticCoverageReplayInputs {
            state_root: mutable.path(),
            work_root: mutable.path(),
            selection_sha256: &"a".repeat(64),
            language: "python",
            slot_number: 1,
            canonical_repository: "example/project",
        })
        .unwrap_err();

    assert_eq!(
        error.detail,
        "historical-v2 Go semantic-coverage replay requires language go"
    );
}

#[test]
fn public_surface_replay_keeps_the_exact_legacy_layout_compatible() {
    let mutable = tempfile::tempdir().unwrap();
    let work_root = mutable.path().join("work");
    let slot_root = work_root.join("rust").join("slot-0001");
    for name in [
        "base-tested",
        "patched",
        "patched-tested",
        "repository",
        "semantic-progress",
    ] {
        fs::create_dir_all(slot_root.join(name)).unwrap();
    }
    let work_root = fs::canonicalize(&work_root).unwrap();
    let slot_root = work_root.join("rust").join("slot-0001");

    assert_eq!(
        exact_replay_slot_root(&work_root, "rust", 1).unwrap(),
        fs::canonicalize(&slot_root).unwrap()
    );
    fs::create_dir(slot_root.join("unexpected")).unwrap();
    assert!(
        exact_replay_slot_root(&work_root, "rust", 1)
            .unwrap_err()
            .detail
            .contains("work layout changed")
    );
}

struct Fixture {
    artifacts: tempfile::TempDir,
    frame: HistoricalV2Frame,
    exclusions: HistoricalV2ExclusionManifest,
    selection: super::super::HistoricalV2SlotSelection,
    payloads: HistoricalV2SelectedPayloads,
}

impl Fixture {
    fn new() -> Self {
        Self::with_selected_count(1)
    }

    fn with_selected_count(selected_count: usize) -> Self {
        Self::with_patches(&vec![PATCH; selected_count])
    }

    fn with_patches(patches: &[&str]) -> Self {
        let artifacts = tempfile::tempdir().unwrap();
        let protocol = validate_historical_v2_protocol(PROTOCOL).unwrap();
        let partitions = PARTITIONS
            .into_iter()
            .map(|partition| {
                let artifact_path = format!("{partition}.json");
                let bytes = format!("{{\"partition\":\"{partition}\"}}").into_bytes();
                fs::write(artifacts.path().join(&artifact_path), &bytes).unwrap();
                HistoricalV2PartitionExclusions {
                    partition: partition.to_string(),
                    artifacts: vec![HistoricalV2ExclusionArtifact {
                        artifact_path,
                        artifact_sha256: sha256(&bytes),
                    }],
                    repositories: Vec::new(),
                }
            })
            .collect();
        let exclusions = seal_historical_v2_exclusion_manifest(
            PROTOCOL,
            artifacts.path(),
            HistoricalV2ExclusionManifest {
                schema_version: HISTORICAL_V2_EXCLUSION_MANIFEST_SCHEMA_VERSION,
                protocol_sha256: protocol.protocol_sha256.clone(),
                partitions,
                repository_count: 0,
                manifest_sha256: String::new(),
            },
        )
        .unwrap();
        let rows = patches
            .iter()
            .enumerate()
            .map(|(index, patch)| HistoricalV2ProjectedRow {
                source_shard_index: 0,
                source_row_index: index,
                global_row_index: index,
                base_commit: format!("{:040x}", index + 1),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                instance_id: format!("owner__repository-{}", index + 1),
                license: "MIT".to_string(),
                patch: (*patch).to_string(),
                pull_number: (index + 1) as i64,
                repo: format!("Owner/Repository-{}", index + 1),
            })
            .collect::<Vec<_>>();
        let records = rows
            .iter()
            .cloned()
            .map(|row| {
                derive_historical_v2_frame_record(row, &protocol.protocol.selection.ranking_seed)
            })
            .collect::<Vec<_>>();
        let mut frame = HistoricalV2Frame {
            schema_version: HISTORICAL_V2_FRAME_SCHEMA_VERSION,
            protocol_sha256: protocol.protocol_sha256.clone(),
            dataset_revision: protocol.protocol.dataset.revision.clone(),
            ranking_seed: protocol.protocol.selection.ranking_seed.clone(),
            shards: Vec::new(),
            row_count: patches.len(),
            eligible_count: patches.len(),
            excluded_count: 0,
            records,
            frame_sha256: String::new(),
        };
        frame.frame_sha256 = historical_v2_frame_sha256(&frame).unwrap();
        let selection =
            select_historical_v2_slots(PROTOCOL, artifacts.path(), &frame, &exclusions).unwrap();
        let records = selection
            .slots
            .iter()
            .filter_map(|slot| match &slot.outcome {
                HistoricalV2SlotOutcome::Selected {
                    global_row_index,
                    instance_id,
                    ..
                } => Some((
                    slot.language.clone(),
                    slot.slot_number,
                    *global_row_index,
                    instance_id,
                )),
                HistoricalV2SlotOutcome::Unfilled => None,
            })
            .map(|(language, slot_number, global_row_index, instance_id)| {
                let row = &rows[global_row_index];
                seal_historical_v2_selected_payload(HistoricalV2SelectedPayload {
                    language,
                    slot_number,
                    source_shard_index: row.source_shard_index,
                    source_row_index: row.source_row_index,
                    global_row_index,
                    instance_id: instance_id.clone(),
                    patch: row.patch.clone(),
                    patch_sha256: sha256(row.patch.as_bytes()),
                    install_config: None,
                    install_config_sha256: None,
                    test_patch: None,
                    test_patch_sha256: None,
                    payload_sha256: String::new(),
                })
                .unwrap()
            })
            .collect::<Vec<_>>();
        let payloads = seal_historical_v2_selected_payloads(HistoricalV2SelectedPayloads {
            schema_version: HISTORICAL_V2_SELECTED_PAYLOADS_SCHEMA_VERSION,
            payload_contract: "sniffbench-historical-v2-selected-payloads-v1".to_string(),
            protocol_sha256: protocol.protocol_sha256,
            frame_sha256: frame.frame_sha256.clone(),
            exclusion_manifest_sha256: exclusions.manifest_sha256.clone(),
            selection_sha256: selection.selection_sha256.clone(),
            selected_count: records.len(),
            records,
            payloads_sha256: String::new(),
        })
        .unwrap();
        Self {
            artifacts,
            frame,
            exclusions,
            selection,
            payloads,
        }
    }
}

struct ForbiddenExecutor;

impl HistoricalV2IdenticalTestExecutor for ForbiddenExecutor {
    fn execute(
        &self,
        _request: &HistoricalV2IdenticalTestExecutionRequest<'_>,
    ) -> Result<HistoricalV2RawIdenticalTestExecution, HistoricalV2ExecutionError> {
        panic!("one-stage sweep must not execute repository tests")
    }
}

impl HistoricalV2RecoverableTestExecutor for ForbiddenExecutor {
    fn recover(
        &self,
        _plan: &super::super::HistoricalV2IdenticalTestPlan,
    ) -> Result<(), HistoricalV2ExecutionError> {
        panic!("one-stage sweep must not recover repository test resources")
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
