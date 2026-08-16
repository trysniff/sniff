use super::*;
use crate::benchmark::{
    HistoricalV2MaterializationExclusionReason, HistoricalV2QualificationExclusionReason,
};
use serde_json::json;
use std::fs;

const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn history_requires_exact_order_and_hash_chain() {
    let mut history = Vec::new();
    for (stage, artifact_kind) in completed_stages() {
        history.push(append(&history, stage, completed(artifact_kind)).unwrap());
    }
    history.push(
        append(
            &history,
            HistoricalV2SlotStage::ReadyForReview,
            HistoricalV2SlotStageOutcome::ReadyForReview,
        )
        .unwrap(),
    );

    validate_historical_v2_slot_stage_history(&history).unwrap();
    assert_eq!(history.last().unwrap().sequence, 10);
    assert_eq!(
        history
            .last()
            .unwrap()
            .previous_checkpoint_sha256
            .as_deref(),
        Some(history[8].checkpoint_sha256.as_str())
    );
}

#[test]
fn terminal_exclusion_closes_the_fixed_slot() {
    let mut history = vec![
        append(
            &[],
            HistoricalV2SlotStage::Payload,
            completed(HistoricalV2StageArtifactKind::SelectedPayload),
        )
        .unwrap(),
    ];
    history.push(
        append(
            &history,
            HistoricalV2SlotStage::Materialization,
            HistoricalV2SlotStageOutcome::Excluded {
                reason: HistoricalV2TerminalExclusionReason::Materialization(
                    HistoricalV2MaterializationExclusionReason::HistoricalPatchDoesNotApply,
                ),
                artifact_kind: HistoricalV2StageArtifactKind::MaterializationExclusion,
                artifact_sha256: HASH_A.to_string(),
            },
        )
        .unwrap(),
    );

    let error = append(
        &history,
        HistoricalV2SlotStage::TestMaterialization,
        completed(HistoricalV2StageArtifactKind::NoTestPatch),
    )
    .unwrap_err();
    assert!(error.contains("terminal"));
}

#[test]
fn exclusions_cannot_be_attached_to_an_unrelated_stage() {
    let history = vec![
        append(
            &[],
            HistoricalV2SlotStage::Payload,
            completed(HistoricalV2StageArtifactKind::SelectedPayload),
        )
        .unwrap(),
    ];
    let error = append(
        &history,
        HistoricalV2SlotStage::Materialization,
        HistoricalV2SlotStageOutcome::Excluded {
            reason: HistoricalV2TerminalExclusionReason::Qualification(vec![
                HistoricalV2QualificationExclusionReason::NoNetProductionReduction,
            ]),
            artifact_kind: HistoricalV2StageArtifactKind::Qualification,
            artifact_sha256: HASH_A.to_string(),
        },
    )
    .unwrap_err();
    assert!(error.contains("wrong stage"));
}

#[test]
fn qualification_exclusions_must_be_nonempty_sorted_and_unique() {
    let history = completed_through_assessment_identity();
    let repeated = HistoricalV2SlotStageOutcome::Excluded {
        reason: HistoricalV2TerminalExclusionReason::Qualification(vec![
            HistoricalV2QualificationExclusionReason::NoNetProductionReduction,
            HistoricalV2QualificationExclusionReason::NoNetProductionReduction,
        ]),
        artifact_kind: HistoricalV2StageArtifactKind::Qualification,
        artifact_sha256: HASH_A.to_string(),
    };
    assert!(
        append(&history, HistoricalV2SlotStage::Qualification, repeated)
            .unwrap_err()
            .contains("canonical")
    );
}

#[test]
fn mutation_of_any_prior_checkpoint_breaks_the_chain() {
    let mut history = vec![
        append(
            &[],
            HistoricalV2SlotStage::Payload,
            completed(HistoricalV2StageArtifactKind::SelectedPayload),
        )
        .unwrap(),
    ];
    history.push(
        append(
            &history,
            HistoricalV2SlotStage::Materialization,
            completed(HistoricalV2StageArtifactKind::Materialization),
        )
        .unwrap(),
    );
    history[0].checkpoint_sha256 = HASH_B.to_string();
    assert!(validate_historical_v2_slot_stage_history(&history).is_err());
}

#[test]
fn durable_journal_round_trips_each_completed_artifact() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    {
        let mut journal = HistoricalV2SlotStageJournal::open(&state, "rust", 1).unwrap();
        journal
            .append(
                checkpoint_input(
                    HistoricalV2SlotStage::Payload,
                    completed(HistoricalV2StageArtifactKind::SelectedPayload),
                ),
                Some(&json!({"payload_sha256": HASH_A})),
            )
            .unwrap();
    }

    let mut resumed = HistoricalV2SlotStageJournal::open(&state, "rust", 1).unwrap();
    assert_eq!(resumed.history().len(), 1);
    assert_eq!(
        resumed.history()[0].artifact,
        Some(json!({"payload_sha256": HASH_A}))
    );
    resumed
        .append(
            checkpoint_input(
                HistoricalV2SlotStage::Materialization,
                completed(HistoricalV2StageArtifactKind::Materialization),
            ),
            Some(&json!({"materialization_sha256": HASH_A})),
        )
        .unwrap();
    assert_eq!(resumed.history().len(), 2);
}

#[test]
fn durable_journal_recovers_torn_staging_but_rejects_committed_tampering() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    {
        let mut journal = HistoricalV2SlotStageJournal::open(&state, "rust", 1).unwrap();
        journal
            .append(
                checkpoint_input(
                    HistoricalV2SlotStage::Payload,
                    completed(HistoricalV2StageArtifactKind::SelectedPayload),
                ),
                Some(&json!({"payload_sha256": HASH_A})),
            )
            .unwrap();
    }
    let staging = state.join("rust").join(".slot-0001.incomplete");
    fs::create_dir(&staging).unwrap();
    fs::write(staging.join("partial"), b"torn").unwrap();
    drop(HistoricalV2SlotStageJournal::open(&state, "rust", 1).unwrap());
    assert!(!staging.exists());

    let transaction = state.join("rust").join("slot-0001").join("0001-payload");
    fs::write(transaction.join("unexpected.json"), b"{}\n").unwrap();
    let error = HistoricalV2SlotStageJournal::open(&state, "rust", 1).unwrap_err();
    assert_eq!(error.kind, HistoricalV2SlotStageErrorKind::InvalidInput);
}

#[test]
fn durable_journal_lock_is_crash_releasing_and_nonblocking() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    let active = HistoricalV2SlotStageJournal::open(&state, "rust", 1).unwrap();
    let error = HistoricalV2SlotStageJournal::open(&state, "rust", 1).unwrap_err();
    assert_eq!(
        error.kind,
        HistoricalV2SlotStageErrorKind::InfrastructureFailed
    );
    drop(active);
    HistoricalV2SlotStageJournal::open(&state, "rust", 1).unwrap();
}

#[test]
fn durable_journal_never_commits_an_infrastructure_error() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    let mut journal = HistoricalV2SlotStageJournal::open(&state, "rust", 1).unwrap();
    let error = journal
        .append::<serde_json::Value>(
            checkpoint_input(
                HistoricalV2SlotStage::Payload,
                completed(HistoricalV2StageArtifactKind::SelectedPayload),
            ),
            None,
        )
        .unwrap_err();
    assert_eq!(error.kind, HistoricalV2SlotStageErrorKind::InvalidInput);
    assert!(journal.history().is_empty());
}

#[test]
fn durable_terminal_exclusion_survives_resume_and_cannot_be_extended() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    {
        let mut journal = HistoricalV2SlotStageJournal::open(&state, "rust", 1).unwrap();
        journal
            .append(
                checkpoint_input(
                    HistoricalV2SlotStage::Payload,
                    completed(HistoricalV2StageArtifactKind::SelectedPayload),
                ),
                Some(&json!({"payload_sha256": HASH_A})),
            )
            .unwrap();
        journal
            .append::<serde_json::Value>(
                checkpoint_input(
                    HistoricalV2SlotStage::Materialization,
                    HistoricalV2SlotStageOutcome::Excluded {
                        reason: HistoricalV2TerminalExclusionReason::Materialization(
                            HistoricalV2MaterializationExclusionReason::RepositoryUnavailable,
                        ),
                        artifact_kind: HistoricalV2StageArtifactKind::MaterializationExclusion,
                        artifact_sha256: HASH_A.to_string(),
                    },
                ),
                Some(&json!({
                    "reason": "repository_unavailable",
                    "evidence_sha256": HASH_A
                })),
            )
            .unwrap();
    }

    let mut resumed = HistoricalV2SlotStageJournal::open(&state, "rust", 1).unwrap();
    assert!(matches!(
        resumed.history()[1].checkpoint.outcome,
        HistoricalV2SlotStageOutcome::Excluded { .. }
    ));
    let error = resumed
        .append(
            checkpoint_input(
                HistoricalV2SlotStage::TestMaterialization,
                completed(HistoricalV2StageArtifactKind::NoTestPatch),
            ),
            Some(&json!({"test_patch": null})),
        )
        .unwrap_err();
    assert_eq!(error.kind, HistoricalV2SlotStageErrorKind::InvalidInput);
    assert!(error.detail.contains("terminal"));
}

fn completed_through_assessment_identity() -> Vec<HistoricalV2SlotStageCheckpoint> {
    let mut history = Vec::new();
    for (stage, artifact_kind) in completed_stages().into_iter().take(6) {
        history.push(append(&history, stage, completed(artifact_kind)).unwrap());
    }
    history
}

fn completed_stages() -> [(HistoricalV2SlotStage, HistoricalV2StageArtifactKind); 9] {
    [
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
    ]
}

fn completed(artifact_kind: HistoricalV2StageArtifactKind) -> HistoricalV2SlotStageOutcome {
    HistoricalV2SlotStageOutcome::Completed {
        artifact_kind,
        artifact_sha256: HASH_A.to_string(),
    }
}

fn append(
    history: &[HistoricalV2SlotStageCheckpoint],
    stage: HistoricalV2SlotStage,
    outcome: HistoricalV2SlotStageOutcome,
) -> Result<HistoricalV2SlotStageCheckpoint, String> {
    append_historical_v2_slot_stage_checkpoint(history, checkpoint_input(stage, outcome))
}

fn checkpoint_input(
    stage: HistoricalV2SlotStage,
    outcome: HistoricalV2SlotStageOutcome,
) -> HistoricalV2SlotStageCheckpointInput<'static> {
    HistoricalV2SlotStageCheckpointInput {
        selection_sha256: HASH_A,
        language: "rust",
        slot_number: 1,
        canonical_repository: "github.com/example/repository",
        stage,
        outcome,
    }
}
