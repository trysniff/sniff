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

#[tokio::test]
async fn one_stage_sweep_persists_every_selected_payload_without_external_execution() {
    let fixture = Fixture::new();
    let client = reqwest::Client::builder().build().unwrap();
    let mutable = tempfile::tempdir().unwrap();
    let state_root = mutable.path().join("state");
    let work_root = mutable.path().join("work");
    let harness = tempfile::tempdir().unwrap();
    let executor = ForbiddenExecutor;

    let summary = run_historical_v2_selected_slots(
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
        },
        NonZeroUsize::new(1),
    )
    .await
    .unwrap();

    assert_eq!(summary.selected_slot_count, 1);
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

struct Fixture {
    artifacts: tempfile::TempDir,
    frame: HistoricalV2Frame,
    exclusions: HistoricalV2ExclusionManifest,
    selection: super::super::HistoricalV2SlotSelection,
    payloads: HistoricalV2SelectedPayloads,
}

impl Fixture {
    fn new() -> Self {
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
        let row = HistoricalV2ProjectedRow {
            source_shard_index: 0,
            source_row_index: 0,
            global_row_index: 0,
            base_commit: "1".repeat(40),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            instance_id: "owner__repository-1".to_string(),
            license: "MIT".to_string(),
            patch: PATCH.to_string(),
            pull_number: 1,
            repo: "Owner/Repository".to_string(),
        };
        let record = derive_historical_v2_frame_record(
            row.clone(),
            &protocol.protocol.selection.ranking_seed,
        );
        let mut frame = HistoricalV2Frame {
            schema_version: HISTORICAL_V2_FRAME_SCHEMA_VERSION,
            protocol_sha256: protocol.protocol_sha256.clone(),
            dataset_revision: protocol.protocol.dataset.revision.clone(),
            ranking_seed: protocol.protocol.selection.ranking_seed.clone(),
            shards: Vec::new(),
            row_count: 1,
            eligible_count: 1,
            excluded_count: 0,
            records: vec![record],
            frame_sha256: String::new(),
        };
        frame.frame_sha256 = historical_v2_frame_sha256(&frame).unwrap();
        let selection =
            select_historical_v2_slots(PROTOCOL, artifacts.path(), &frame, &exclusions).unwrap();
        let payload = seal_historical_v2_selected_payload(HistoricalV2SelectedPayload {
            language: "python".to_string(),
            slot_number: 1,
            source_shard_index: row.source_shard_index,
            source_row_index: row.source_row_index,
            global_row_index: row.global_row_index,
            instance_id: row.instance_id,
            patch: row.patch,
            patch_sha256: sha256(PATCH.as_bytes()),
            install_config: None,
            install_config_sha256: None,
            test_patch: None,
            test_patch_sha256: None,
            payload_sha256: String::new(),
        })
        .unwrap();
        let payloads = seal_historical_v2_selected_payloads(HistoricalV2SelectedPayloads {
            schema_version: HISTORICAL_V2_SELECTED_PAYLOADS_SCHEMA_VERSION,
            payload_contract: "sniffbench-historical-v2-selected-payloads-v1".to_string(),
            protocol_sha256: protocol.protocol_sha256,
            frame_sha256: frame.frame_sha256.clone(),
            exclusion_manifest_sha256: exclusions.manifest_sha256.clone(),
            selection_sha256: selection.selection_sha256.clone(),
            selected_count: 1,
            records: vec![payload],
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
