use super::*;
use crate::benchmark::{
    HISTORICAL_V2_SLOT_STAGE_CHECKPOINT_SCHEMA_VERSION, HistoricalV2MaterializationExclusionReason,
    HistoricalV2SlotRunDisposition, HistoricalV2SlotRunIdentity, HistoricalV2SlotStageCheckpoint,
    HistoricalV2SlotStageErrorKind, HistoricalV2StoredSlotStage,
    HistoricalV2TerminalExclusionReason,
};
use serde_json::json;

#[test]
fn invalid_slot_identity_is_rejected_before_creating_any_language_path() {
    let root = tempfile::tempdir().unwrap();
    let work_root = root.path().join("work");
    let escaped = root.path().join("escaped");

    let error = canonical_work_root(&work_root, "../escaped", 1).unwrap_err();

    assert_eq!(error.kind, HistoricalV2SlotStageErrorKind::InvalidInput);
    assert!(!work_root.exists());
    assert!(!escaped.exists());
}

#[test]
fn materialization_recovery_removes_only_the_exact_slot() {
    let root = tempfile::tempdir().unwrap();
    let work_root = canonical_work_root(&root.path().join("work"), "rust", 1).unwrap();
    let language_root = work_root.join("rust");
    let target = language_root.join("slot-0001");
    let sibling = language_root.join("slot-0002");
    fs::create_dir(&target).unwrap();
    fs::create_dir(&sibling).unwrap();
    fs::write(target.join("partial"), b"partial").unwrap();
    fs::write(sibling.join("committed"), b"committed").unwrap();

    remove_interrupted_materialization(&work_root, "rust", 1).unwrap();

    assert!(!target.exists());
    assert_eq!(fs::read(sibling.join("committed")).unwrap(), b"committed");
}

#[test]
fn materialization_recovery_refuses_a_file_at_the_slot_path() {
    let root = tempfile::tempdir().unwrap();
    let work_root = canonical_work_root(&root.path().join("work"), "rust", 1).unwrap();
    let target = work_root.join("rust").join("slot-0001");
    fs::write(&target, b"not a directory").unwrap();

    let error = remove_interrupted_materialization(&work_root, "rust", 1).unwrap_err();

    assert_eq!(error.kind, HistoricalV2SlotStageErrorKind::InvalidInput);
    assert_eq!(fs::read(target).unwrap(), b"not a directory");
}

#[test]
fn terminal_reconciliation_discards_only_excluded_slot_work() {
    let root = tempfile::tempdir().unwrap();
    let work_root = canonical_work_root(&root.path().join("work"), "rust", 1).unwrap();
    let language_root = work_root.join("rust");
    for slot in 1..=3 {
        let slot_root = language_root.join(format!("slot-{slot:04}"));
        fs::create_dir(&slot_root).unwrap();
        fs::write(slot_root.join("retained"), slot.to_string()).unwrap();
    }

    reconcile_terminal_slot_work(
        &work_root,
        "rust",
        1,
        &HistoricalV2SlotRunDisposition::Excluded {
            stage: HistoricalV2SlotStage::Materialization,
            reason: HistoricalV2TerminalExclusionReason::Materialization(
                HistoricalV2MaterializationExclusionReason::RepositoryUnavailable,
            ),
        },
    )
    .unwrap();
    reconcile_terminal_slot_work(
        &work_root,
        "rust",
        2,
        &HistoricalV2SlotRunDisposition::Paused {
            next_stage: HistoricalV2SlotStage::SemanticCensus,
        },
    )
    .unwrap();
    reconcile_terminal_slot_work(
        &work_root,
        "rust",
        3,
        &HistoricalV2SlotRunDisposition::ReadyForReview,
    )
    .unwrap();

    assert!(!language_root.join("slot-0001").exists());
    assert_eq!(
        fs::read_to_string(language_root.join("slot-0002/retained")).unwrap(),
        "2"
    );
    assert_eq!(
        fs::read_to_string(language_root.join("slot-0003/retained")).unwrap(),
        "3"
    );
}

#[test]
fn prerequisite_artifacts_fail_closed_when_missing_or_malformed() {
    let identity = HistoricalV2SlotRunIdentity {
        selection_sha256: &"a".repeat(64),
        language: "rust",
        slot_number: 1,
        canonical_repository: "example/repository",
    };
    let empty = HistoricalV2SlotStageContext {
        identity,
        stage: HistoricalV2SlotStage::Materialization,
        history: &[],
    };
    assert_eq!(
        artifact::<String>(empty, 0).unwrap_err().kind,
        HistoricalV2SlotStageErrorKind::InvalidInput
    );

    let history = [stored(json!({"unexpected": true}))];
    let malformed = HistoricalV2SlotStageContext {
        identity,
        stage: HistoricalV2SlotStage::Materialization,
        history: &history,
    };
    assert_eq!(
        artifact::<String>(malformed, 0).unwrap_err().kind,
        HistoricalV2SlotStageErrorKind::InvalidInput
    );
}

#[test]
fn execution_error_mapping_preserves_all_three_typed_classes() {
    for (source, expected) in [
        (
            HistoricalV2ExecutionErrorKind::InvalidInput,
            HistoricalV2SlotStageErrorKind::InvalidInput,
        ),
        (
            HistoricalV2ExecutionErrorKind::InfrastructureUnavailable,
            HistoricalV2SlotStageErrorKind::InfrastructureUnavailable,
        ),
        (
            HistoricalV2ExecutionErrorKind::InfrastructureFailed,
            HistoricalV2SlotStageErrorKind::InfrastructureFailed,
        ),
    ] {
        let error = slot_execution_error(HistoricalV2ExecutionError {
            kind: source,
            detail: "fixture".to_string(),
        });
        assert_eq!(error.stage, HistoricalV2SlotStage::IdenticalTests);
        assert_eq!(error.kind, expected);
        assert_eq!(error.detail, "fixture");
    }
}

#[test]
fn operation_identity_rejects_the_wrong_canonical_repository() {
    let selection_sha256 = "a".repeat(64);
    let context = HistoricalV2SlotStageContext {
        identity: HistoricalV2SlotRunIdentity {
            selection_sha256: &selection_sha256,
            language: "rust",
            slot_number: 1,
            canonical_repository: "wrong/repository",
        },
        stage: HistoricalV2SlotStage::Payload,
        history: &[],
    };

    let error =
        require_operation_identity(context, &selection_sha256, "rust", 1, "example/repository")
            .unwrap_err();

    assert_eq!(error.kind, HistoricalV2SlotStageErrorKind::InvalidInput);
    assert!(error.detail.contains("crossed the runner identity"));
}

#[test]
fn prepared_outcomes_keep_the_typed_reason_and_exact_artifact() {
    let artifact = json!({"proof": "exact"});
    let prepared = excluded(
        HistoricalV2TerminalExclusionReason::Materialization(
            HistoricalV2MaterializationExclusionReason::RepositoryUnavailable,
        ),
        HistoricalV2StageArtifactKind::MaterializationExclusion,
        &"b".repeat(64),
        &artifact,
        HistoricalV2SlotStage::Materialization,
    )
    .unwrap();

    assert_eq!(prepared.artifact, Some(artifact));
    assert!(matches!(
        prepared.outcome,
        HistoricalV2SlotStageOutcome::Excluded {
            reason: HistoricalV2TerminalExclusionReason::Materialization(
                HistoricalV2MaterializationExclusionReason::RepositoryUnavailable
            ),
            artifact_kind: HistoricalV2StageArtifactKind::MaterializationExclusion,
            ..
        }
    ));
}

fn stored(artifact: serde_json::Value) -> HistoricalV2StoredSlotStage {
    HistoricalV2StoredSlotStage {
        checkpoint: HistoricalV2SlotStageCheckpoint {
            schema_version: HISTORICAL_V2_SLOT_STAGE_CHECKPOINT_SCHEMA_VERSION,
            checkpoint_contract: "fixture".to_string(),
            selection_sha256: "a".repeat(64),
            language: "rust".to_string(),
            slot_number: 1,
            canonical_repository: "example/repository".to_string(),
            sequence: 1,
            previous_checkpoint_sha256: None,
            stage: HistoricalV2SlotStage::Payload,
            outcome: HistoricalV2SlotStageOutcome::Completed {
                artifact_kind: HistoricalV2StageArtifactKind::SelectedPayload,
                artifact_sha256: "b".repeat(64),
            },
            checkpoint_sha256: "c".repeat(64),
        },
        artifact: Some(artifact),
    }
}
