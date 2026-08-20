use super::super::history_v2_label_review::tests::ReviewFixture;
use super::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use tempfile::TempDir;

const PROTOCOL: &[u8] = include_bytes!("../sniffbench/historical-v2-protocol.json");
const PARTITIONS: [&str; 6] = [
    "blind-oss-v1",
    "historical-v1",
    "intentional-boundary-v1",
    "slopcodebench",
    "synthetic-gold-v1",
    "trim",
];

#[test]
fn empty_fixed_selection_is_auditable_but_underfilled() {
    let fixture = GateFixture::new(Vec::new());
    let evidence = fixture.build(&[]).unwrap();
    assert_eq!(evidence.fixed_slot_count, 768);
    assert_eq!(evidence.unfilled_slot_count, 768);
    assert_eq!(evidence.status, HistoricalV2ReleaseGateStatus::Underfilled);
    validate_historical_v2_release_evidence(&fixture.inputs(&[]), &evidence).unwrap();
    let error = require_historical_v2_release_gate(&fixture.inputs(&[]), &evidence).unwrap_err();
    assert!(error.contains("underfilled"), "{error}");

    let mut changed = evidence;
    changed.accepted_count = 1;
    let error =
        validate_historical_v2_release_evidence(&fixture.inputs(&[]), &changed).unwrap_err();
    assert!(error.contains("evidence changed"), "{error}");
}

#[test]
fn a_terminal_exclusion_closes_only_its_original_slot() {
    let fixture = GateFixture::new(vec![projected_record(0, "owner/one", 1, "go")]);
    append_excluded_journal(&fixture, "go", 1, "owner/one");
    let evidence = fixture.build(&[]).unwrap();
    assert_eq!(evidence.selected_slot_count, 1);
    assert_eq!(evidence.execution_excluded_count, 1);
    assert_eq!(evidence.accepted_count, 0);
    assert!(matches!(
        evidence.slots[0].outcome,
        HistoricalV2ReleaseSlotOutcome::Excluded {
            stage: HistoricalV2SlotStage::Materialization,
            ..
        }
    ));

    fs::create_dir(fixture.state.path().join("go").join("slot-0002")).unwrap();
    let error = fixture.build(&[]).unwrap_err();
    assert!(error.contains("replacement slots"), "{error}");
}

#[test]
fn a_ready_slot_cannot_pass_without_independent_final_review() {
    let fixture = GateFixture::new(vec![projected_record(0, "owner/one", 1, "go")]);
    append_ready_journal(&fixture, "go", 1, "owner/one");
    let error = fixture.build(&[]).unwrap_err();
    assert!(error.contains("no final independent review"), "{error}");
}

#[test]
fn existing_journal_reads_never_create_missing_slot_state() {
    let state = tempfile::tempdir().unwrap();
    let error = HistoricalV2SlotStageJournal::open_existing(state.path(), "python", 1).unwrap_err();
    assert!(error.detail.contains("language state"), "{}", error.detail);
    assert_eq!(fs::read_dir(state.path()).unwrap().count(), 0);
}

#[test]
fn accepted_and_closed_reviews_keep_exact_terminal_lineage() {
    let fixture = ReviewFixture::new();
    let selection = selection_with_hash(&fixture.bundle.selection_sha256);
    let accepted_worksheets = vec![
        fixture.accepted("reviewer-a", SlopPattern::NeedlessIndirection, ""),
        fixture.accepted("reviewer-b", SlopPattern::NeedlessIndirection, ""),
    ];
    let accepted_audit = fixture.audit(&accepted_worksheets);
    let accepted_resolution = prepare_historical_v2_label_resolution(
        &fixture.protocol,
        fixture.root.path(),
        &fixture.bundle,
        &accepted_worksheets,
        &accepted_audit,
    )
    .unwrap();
    let accepted_label = resolve_historical_v2_label(
        &fixture.protocol,
        fixture.root.path(),
        &fixture.bundle,
        &accepted_worksheets,
        &accepted_audit,
        &accepted_resolution,
    )
    .unwrap();
    let accepted = reviewed(
        &fixture,
        &accepted_worksheets,
        &accepted_audit,
        &accepted_resolution,
        &accepted_label,
    );
    assert!(matches!(
        validated_review_outcome(
            &fixture.protocol,
            &selection,
            &fixture.bundle.terminal_checkpoint_sha256,
            &accepted,
        )
        .unwrap(),
        HistoricalV2ReleaseSlotOutcome::Accepted { .. }
    ));

    let closed_worksheets = vec![
        fixture.rejected("reviewer-a"),
        fixture.rejected("reviewer-b"),
    ];
    let closed_audit = fixture.audit(&closed_worksheets);
    let closed_resolution = prepare_historical_v2_label_resolution(
        &fixture.protocol,
        fixture.root.path(),
        &fixture.bundle,
        &closed_worksheets,
        &closed_audit,
    )
    .unwrap();
    let closed_label = resolve_historical_v2_label(
        &fixture.protocol,
        fixture.root.path(),
        &fixture.bundle,
        &closed_worksheets,
        &closed_audit,
        &closed_resolution,
    )
    .unwrap();
    let closed = reviewed(
        &fixture,
        &closed_worksheets,
        &closed_audit,
        &closed_resolution,
        &closed_label,
    );
    assert!(matches!(
        validated_review_outcome(
            &fixture.protocol,
            &selection,
            &fixture.bundle.terminal_checkpoint_sha256,
            &closed,
        )
        .unwrap(),
        HistoricalV2ReleaseSlotOutcome::ReviewClosed { .. }
    ));
    let error = validated_review_outcome(&fixture.protocol, &selection, &"9".repeat(64), &accepted)
        .unwrap_err();
    assert!(error.contains("terminal slot"), "{error}");
}

#[test]
fn exactly_forty_accepted_cases_per_language_passes_the_gate_math() {
    let protocol = validate_historical_v2_protocol(PROTOCOL).unwrap();
    let selection = threshold_selection(&protocol);
    let slots = selection
        .slots
        .iter()
        .map(|slot| HistoricalV2ReleaseSlotEvidence {
            language: slot.language.clone(),
            slot_number: slot.slot_number,
            outcome: if slot.slot_number <= 40 {
                accepted_outcome(slot.slot_number)
            } else {
                HistoricalV2ReleaseSlotOutcome::Unfilled
            },
        })
        .collect();
    let evidence = summarize_historical_v2_release(&protocol, &selection, slots).unwrap();
    assert_eq!(evidence.accepted_count, 240);
    assert_eq!(evidence.status, HistoricalV2ReleaseGateStatus::Passed);
    assert!(evidence.languages.iter().all(|language| language.passes));
}

fn reviewed<'a>(
    fixture: &'a ReviewFixture,
    worksheets: &'a [HistoricalV2LabelWorksheet],
    audit: &'a HistoricalV2LabelAudit,
    resolution: &'a HistoricalV2ResolutionWorksheet,
    final_label: &'a HistoricalV2FinalLabel,
) -> HistoricalV2ReviewedSlotArtifacts<'a> {
    HistoricalV2ReviewedSlotArtifacts {
        language: &fixture.bundle.language,
        slot_number: 1,
        bundle_root: fixture.root.path(),
        bundle: &fixture.bundle,
        worksheets,
        audit,
        resolution,
        final_label,
    }
}

fn append_excluded_journal(
    fixture: &GateFixture,
    language: &str,
    slot_number: usize,
    repository: &str,
) {
    let mut journal =
        HistoricalV2SlotStageJournal::open(fixture.state.path(), language, slot_number).unwrap();
    append(
        &mut journal,
        &fixture.selection.selection_sha256,
        language,
        slot_number,
        repository,
        HistoricalV2SlotStage::Payload,
        HistoricalV2SlotStageOutcome::Completed {
            artifact_kind: HistoricalV2StageArtifactKind::SelectedPayload,
            artifact_sha256: "1".repeat(64),
        },
        Some(&json!({"payload": true})),
    );
    append(
        &mut journal,
        &fixture.selection.selection_sha256,
        language,
        slot_number,
        repository,
        HistoricalV2SlotStage::Materialization,
        HistoricalV2SlotStageOutcome::Excluded {
            reason: HistoricalV2TerminalExclusionReason::Materialization(
                HistoricalV2MaterializationExclusionReason::RepositoryUnavailable,
            ),
            artifact_kind: HistoricalV2StageArtifactKind::MaterializationExclusion,
            artifact_sha256: "2".repeat(64),
        },
        Some(&json!({"excluded": true})),
    );
}

fn append_ready_journal(
    fixture: &GateFixture,
    language: &str,
    slot_number: usize,
    repository: &str,
) {
    let mut journal =
        HistoricalV2SlotStageJournal::open(fixture.state.path(), language, slot_number).unwrap();
    let stages = [
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
        (
            HistoricalV2SlotStage::AssessmentIdentity,
            HistoricalV2StageArtifactKind::AssessmentIdentity,
        ),
        (
            HistoricalV2SlotStage::Qualification,
            HistoricalV2StageArtifactKind::Qualification,
        ),
        (
            HistoricalV2SlotStage::TestRecipe,
            HistoricalV2StageArtifactKind::TestRecipe,
        ),
        (
            HistoricalV2SlotStage::IdenticalTests,
            HistoricalV2StageArtifactKind::IdenticalTestExecution,
        ),
    ];
    for (index, (stage, artifact_kind)) in stages.into_iter().enumerate() {
        append(
            &mut journal,
            &fixture.selection.selection_sha256,
            language,
            slot_number,
            repository,
            stage,
            HistoricalV2SlotStageOutcome::Completed {
                artifact_kind,
                artifact_sha256: format!("{:064x}", index + 1),
            },
            Some(&json!({"stage": index + 1})),
        );
    }
    append::<serde_json::Value>(
        &mut journal,
        &fixture.selection.selection_sha256,
        language,
        slot_number,
        repository,
        HistoricalV2SlotStage::ReadyForReview,
        HistoricalV2SlotStageOutcome::ReadyForReview,
        None,
    );
}

#[allow(clippy::too_many_arguments)]
fn append<T: serde::Serialize>(
    journal: &mut HistoricalV2SlotStageJournal,
    selection_sha256: &str,
    language: &str,
    slot_number: usize,
    repository: &str,
    stage: HistoricalV2SlotStage,
    outcome: HistoricalV2SlotStageOutcome,
    artifact: Option<&T>,
) {
    journal
        .append(
            HistoricalV2SlotStageCheckpointInput {
                selection_sha256,
                language,
                slot_number,
                canonical_repository: repository,
                stage,
                outcome,
            },
            artifact,
        )
        .unwrap();
}

struct GateFixture {
    artifacts: TempDir,
    state: TempDir,
    frame: HistoricalV2Frame,
    manifest: HistoricalV2ExclusionManifest,
    selection: HistoricalV2SlotSelection,
}

impl GateFixture {
    fn new(records: Vec<HistoricalV2FrameRecord>) -> Self {
        let artifacts = tempfile::tempdir().unwrap();
        let manifest = exclusion_manifest(artifacts.path());
        let frame = committed_frame(records);
        let selection =
            select_historical_v2_slots(PROTOCOL, artifacts.path(), &frame, &manifest).unwrap();
        Self {
            artifacts,
            state: tempfile::tempdir().unwrap(),
            frame,
            manifest,
            selection,
        }
    }

    fn inputs<'a>(
        &'a self,
        reviewed_slots: &'a [HistoricalV2ReviewedSlotArtifacts<'a>],
    ) -> HistoricalV2ReleaseGateInputs<'a> {
        HistoricalV2ReleaseGateInputs {
            protocol_bytes: PROTOCOL,
            artifact_root: self.artifacts.path(),
            frame: &self.frame,
            exclusions: &self.manifest,
            selection: &self.selection,
            state_root: self.state.path(),
            reviewed_slots,
        }
    }

    fn build(
        &self,
        reviewed_slots: &[HistoricalV2ReviewedSlotArtifacts<'_>],
    ) -> Result<HistoricalV2ReleaseEvidence, String> {
        build_historical_v2_release_evidence(&self.inputs(reviewed_slots))
    }
}

fn exclusion_manifest(root: &std::path::Path) -> HistoricalV2ExclusionManifest {
    let protocol = validate_historical_v2_protocol(PROTOCOL).unwrap();
    let mut partitions = Vec::new();
    for partition in PARTITIONS {
        let artifact_path = format!("{partition}.json");
        let bytes = format!("{{\"partition\":\"{partition}\"}}").into_bytes();
        fs::write(root.join(&artifact_path), &bytes).unwrap();
        partitions.push(HistoricalV2PartitionExclusions {
            partition: partition.to_string(),
            artifacts: vec![HistoricalV2ExclusionArtifact {
                artifact_path,
                artifact_sha256: sha256(&bytes),
            }],
            repositories: Vec::new(),
        });
    }
    let mut manifest = HistoricalV2ExclusionManifest {
        schema_version: HISTORICAL_V2_EXCLUSION_MANIFEST_SCHEMA_VERSION,
        protocol_sha256: protocol.protocol_sha256,
        partitions,
        repository_count: 0,
        manifest_sha256: String::new(),
    };
    manifest.manifest_sha256 = sha256(
        &serde_json::to_vec(&(
            manifest.schema_version,
            &manifest.protocol_sha256,
            &manifest.partitions,
            manifest.repository_count,
        ))
        .unwrap(),
    );
    manifest
}

fn committed_frame(records: Vec<HistoricalV2FrameRecord>) -> HistoricalV2Frame {
    let protocol = validate_historical_v2_protocol(PROTOCOL).unwrap();
    let mut frame = HistoricalV2Frame {
        schema_version: HISTORICAL_V2_FRAME_SCHEMA_VERSION,
        protocol_sha256: protocol.protocol_sha256,
        dataset_revision: protocol.protocol.dataset.revision,
        ranking_seed: protocol.protocol.selection.ranking_seed,
        shards: Vec::new(),
        row_count: records.len(),
        eligible_count: records.len(),
        excluded_count: 0,
        records,
        frame_sha256: String::new(),
    };
    frame.frame_sha256 = historical_v2_frame_sha256(&frame).unwrap();
    frame
}

fn projected_record(
    global_row_index: usize,
    repository: &str,
    pull_number: u64,
    language: &str,
) -> HistoricalV2FrameRecord {
    let protocol = validate_historical_v2_protocol(PROTOCOL).unwrap();
    derive_historical_v2_frame_record(
        HistoricalV2ProjectedRow {
            source_shard_index: 0,
            source_row_index: global_row_index,
            global_row_index,
            base_commit: format!("{pull_number:040x}"),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            instance_id: format!("{repository}#{pull_number}"),
            license: "MIT".to_string(),
            patch: format!(
                "diff --git a/src/file.{language} b/src/file.{language}\n--- a/src/file.{language}\n+++ b/src/file.{language}\n@@ -1,2 +1 @@\n-old one\n-old two\n+new\n"
            ),
            pull_number: i64::try_from(pull_number).unwrap(),
            repo: repository.to_string(),
        },
        &protocol.protocol.selection.ranking_seed,
    )
}

fn selection_with_hash(selection_sha256: &str) -> HistoricalV2SlotSelection {
    let protocol = validate_historical_v2_protocol(PROTOCOL).unwrap();
    let mut selection = threshold_selection(&protocol);
    selection.selection_sha256 = selection_sha256.to_string();
    selection
}

fn threshold_selection(protocol: &ValidatedHistoricalV2Protocol) -> HistoricalV2SlotSelection {
    let mut slots = Vec::new();
    for language in &protocol.protocol.selection.supported_languages {
        for slot_number in 1..=protocol.protocol.selection.slots_per_language {
            slots.push(HistoricalV2Slot {
                language: language.clone(),
                slot_number,
                outcome: if slot_number <= 40 {
                    HistoricalV2SlotOutcome::Selected {
                        global_row_index: slots.len(),
                        instance_id: format!("{language}-{slot_number}"),
                        canonical_repository: format!("owner/{language}-{slot_number}"),
                        pull_number: u64::try_from(slot_number).unwrap(),
                        base_revision: format!("{slot_number:040x}"),
                        patch_sha256: format!("{slot_number:064x}"),
                        rank_sha256: format!("{:064x}", slot_number + 1000),
                    }
                } else {
                    HistoricalV2SlotOutcome::Unfilled
                },
            });
        }
    }
    HistoricalV2SlotSelection {
        schema_version: HISTORICAL_V2_SLOT_SELECTION_SCHEMA_VERSION,
        selection_contract: "test".to_string(),
        protocol_sha256: protocol.protocol_sha256.clone(),
        frame_sha256: "1".repeat(64),
        exclusion_manifest_sha256: "2".repeat(64),
        ranking_seed: "test".to_string(),
        ranking_contract: "test".to_string(),
        slots_per_language: 128,
        candidate_decisions: Vec::new(),
        slots,
        selected_count: 240,
        unfilled_slot_count: 528,
        excluded_partition_count: 0,
        repository_collision_count: 0,
        language_capacity_count: 0,
        selection_sha256: "3".repeat(64),
    }
}

fn accepted_outcome(slot_number: usize) -> HistoricalV2ReleaseSlotOutcome {
    HistoricalV2ReleaseSlotOutcome::Accepted {
        terminal_checkpoint_sha256: format!("{slot_number:064x}"),
        review_item_id: format!("review-{slot_number}"),
        source_bundle_sha256: "4".repeat(64),
        label_audit_sha256: "5".repeat(64),
        final_label_sha256: "6".repeat(64),
        basis: HistoricalV2FinalLabelBasis::ReviewerConsensus,
        pattern: SlopPattern::NeedlessIndirection,
        other_pattern: String::new(),
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
