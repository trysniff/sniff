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
    HistoricalV2RawIdenticalTestExecution, HistoricalV2RecoverableTestExecutor,
    HistoricalV2SelectedPayload, HistoricalV2SelectedPayloads, HistoricalV2SlotStageErrorKind,
    HistoricalV2SlotStageJournal, derive_historical_v2_frame_record, historical_v2_frame_sha256,
    select_historical_v2_slots,
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
        NonZeroUsize::new(1).unwrap(),
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
        NonZeroUsize::new(1).unwrap(),
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

    let first =
        run_historical_v2_selected_slots_bounded(run(), NonZeroUsize::new(1).unwrap(), None)
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

    let second =
        run_historical_v2_selected_slots_bounded(run(), NonZeroUsize::new(1).unwrap(), None)
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
        NonZeroUsize::new(1).unwrap(),
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
        NonZeroUsize::new(1).unwrap(),
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
fn selected_slot_work_recovery_removes_only_marker_proven_semantic_state() {
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
    for root in [&repository, &patched] {
        assert!(!root.join(".sniff-indexer-recovery.json").exists());
        assert!(!root.join(".sniff-indexer-tmp").exists());
    }
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
