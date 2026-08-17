use super::*;
use crate::benchmark::{
    HistoricalV2SourceCensusExclusionReason, HistoricalV2StageArtifactKind,
    HistoricalV2TerminalExclusionReason,
};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::num::NonZeroUsize;

struct RecordingExecutor {
    recovered: RefCell<Vec<HistoricalV2SlotStage>>,
    executed: RefCell<Vec<HistoricalV2SlotStage>>,
    recover_fail_at: Option<HistoricalV2SlotStage>,
    fail_at: Option<HistoricalV2SlotStage>,
    exclude_at: Option<HistoricalV2SlotStage>,
}

impl RecordingExecutor {
    fn clean() -> Self {
        Self {
            recovered: RefCell::new(Vec::new()),
            executed: RefCell::new(Vec::new()),
            recover_fail_at: None,
            fail_at: None,
            exclude_at: None,
        }
    }
}

impl HistoricalV2SlotStageExecutor for RecordingExecutor {
    fn recover<'a>(
        &'a mut self,
        context: HistoricalV2SlotStageContext<'a>,
    ) -> crate::benchmark::HistoricalV2SlotStageFuture<'a, ()> {
        self.recovered.borrow_mut().push(context.stage);
        let fail = self.recover_fail_at == Some(context.stage);
        Box::pin(async move {
            if fail {
                Err(HistoricalV2SlotStageError::infrastructure(
                    context.stage,
                    "injected recovery failure",
                ))
            } else {
                Ok(())
            }
        })
    }

    fn execute<'a>(
        &'a mut self,
        context: HistoricalV2SlotStageContext<'a>,
    ) -> crate::benchmark::HistoricalV2SlotStageFuture<'a, HistoricalV2PreparedStage> {
        self.executed.borrow_mut().push(context.stage);
        let fail = self.fail_at == Some(context.stage);
        let exclude = self.exclude_at == Some(context.stage);
        Box::pin(async move {
            if fail {
                return Err(HistoricalV2SlotStageError::infrastructure(
                    context.stage,
                    "injected stage failure",
                ));
            }
            Ok(if exclude {
                exclusion(context.stage)
            } else {
                completed(context.stage)
            })
        })
    }
}

#[tokio::test]
async fn fresh_run_commits_every_stage_in_exact_order() {
    let root = tempfile::tempdir().unwrap();
    let mut executor = RecordingExecutor::clean();

    let summary = run_historical_v2_slot(root.path(), identity(), &mut executor)
        .await
        .unwrap();

    assert_eq!(summary.resumed_after_sequence, 0);
    assert_eq!(summary.executed_stages, stages());
    assert_eq!(
        summary.disposition,
        HistoricalV2SlotRunDisposition::ReadyForReview
    );
    assert_eq!(*executor.recovered.borrow(), stages());
    assert_eq!(*executor.executed.borrow(), stages());
}

#[tokio::test]
async fn restart_begins_at_the_first_uncommitted_stage() {
    let root = tempfile::tempdir().unwrap();
    let mut first = RecordingExecutor::clean();
    let partial =
        run_historical_v2_slot_slice(root.path(), identity(), &mut first, NonZeroUsize::new(4))
            .await
            .unwrap();
    assert_eq!(
        partial.disposition,
        HistoricalV2SlotRunDisposition::Paused {
            next_stage: HistoricalV2SlotStage::SemanticCensus,
        }
    );

    let mut resumed = RecordingExecutor::clean();
    let summary = run_historical_v2_slot(root.path(), identity(), &mut resumed)
        .await
        .unwrap();

    assert_eq!(summary.resumed_after_sequence, 4);
    assert_eq!(summary.executed_stages, stages()[4..]);
    assert_eq!(*resumed.recovered.borrow(), stages()[4..]);
    assert_eq!(*resumed.executed.borrow(), stages()[4..]);
}

#[tokio::test]
async fn stage_ceiling_is_stable_across_restarts() {
    let root = tempfile::tempdir().unwrap();
    let mut first = RecordingExecutor::clean();
    let partial = run_historical_v2_slot_slice_through(
        root.path(),
        identity(),
        &mut first,
        None,
        Some(HistoricalV2SlotStage::SourceCensus),
    )
    .await
    .unwrap();
    assert_eq!(partial.executed_stages, stages()[..4]);
    assert_eq!(
        partial.disposition,
        HistoricalV2SlotRunDisposition::Paused {
            next_stage: HistoricalV2SlotStage::SemanticCensus,
        }
    );

    let mut resumed = RecordingExecutor::clean();
    let replay = run_historical_v2_slot_slice_through(
        root.path(),
        identity(),
        &mut resumed,
        None,
        Some(HistoricalV2SlotStage::SourceCensus),
    )
    .await
    .unwrap();
    assert_eq!(replay.resumed_after_sequence, 4);
    assert!(replay.executed_stages.is_empty());
    assert!(resumed.recovered.borrow().is_empty());
    assert!(resumed.executed.borrow().is_empty());
}

#[tokio::test]
async fn infrastructure_failure_is_not_checkpointed_or_reclassified() {
    let root = tempfile::tempdir().unwrap();
    let mut failing = RecordingExecutor {
        fail_at: Some(HistoricalV2SlotStage::SourceCensus),
        ..RecordingExecutor::clean()
    };
    let error = run_historical_v2_slot(root.path(), identity(), &mut failing)
        .await
        .unwrap_err();
    assert_eq!(
        error.kind,
        crate::benchmark::HistoricalV2SlotStageErrorKind::InfrastructureFailed
    );

    let mut resumed = RecordingExecutor::clean();
    let summary = run_historical_v2_slot(root.path(), identity(), &mut resumed)
        .await
        .unwrap();
    assert_eq!(summary.resumed_after_sequence, 3);
    assert_eq!(
        summary.executed_stages[0],
        HistoricalV2SlotStage::SourceCensus
    );
}

#[tokio::test]
async fn recovery_failure_does_not_execute_or_advance_the_stage() {
    let root = tempfile::tempdir().unwrap();
    let mut failing = RecordingExecutor {
        recover_fail_at: Some(HistoricalV2SlotStage::Payload),
        ..RecordingExecutor::clean()
    };
    let error = run_historical_v2_slot(root.path(), identity(), &mut failing)
        .await
        .unwrap_err();
    assert_eq!(
        error.kind,
        crate::benchmark::HistoricalV2SlotStageErrorKind::InfrastructureFailed
    );
    assert!(failing.executed.borrow().is_empty());

    let mut resumed = RecordingExecutor::clean();
    let summary = run_historical_v2_slot(root.path(), identity(), &mut resumed)
        .await
        .unwrap();
    assert_eq!(summary.resumed_after_sequence, 0);
    assert_eq!(summary.executed_stages, stages());
}

#[tokio::test]
async fn terminal_exclusion_is_permanent_and_does_not_call_executor_on_resume() {
    let root = tempfile::tempdir().unwrap();
    let mut first = RecordingExecutor {
        exclude_at: Some(HistoricalV2SlotStage::SourceCensus),
        ..RecordingExecutor::clean()
    };
    let excluded = run_historical_v2_slot(root.path(), identity(), &mut first)
        .await
        .unwrap();
    assert!(matches!(
        excluded.disposition,
        HistoricalV2SlotRunDisposition::Excluded {
            stage: HistoricalV2SlotStage::SourceCensus,
            ..
        }
    ));

    let mut resumed = RecordingExecutor::clean();
    let replay = run_historical_v2_slot(root.path(), identity(), &mut resumed)
        .await
        .unwrap();
    assert_eq!(replay.resumed_after_sequence, 4);
    assert!(replay.executed_stages.is_empty());
    assert!(resumed.recovered.borrow().is_empty());
    assert!(resumed.executed.borrow().is_empty());
}

#[tokio::test]
async fn resume_rejects_a_different_slot_identity() {
    let root = tempfile::tempdir().unwrap();
    let mut first = RecordingExecutor::clean();
    run_historical_v2_slot_slice(root.path(), identity(), &mut first, NonZeroUsize::new(1))
        .await
        .unwrap();

    let mut resumed = RecordingExecutor::clean();
    let mut changed = identity();
    changed.canonical_repository = "example/changed";
    let error = run_historical_v2_slot(root.path(), changed, &mut resumed)
        .await
        .unwrap_err();
    assert!(error.detail.contains("identity changed"));
    assert!(resumed.executed.borrow().is_empty());
}

fn identity() -> HistoricalV2SlotRunIdentity<'static> {
    HistoricalV2SlotRunIdentity {
        selection_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        language: "rust",
        slot_number: 1,
        canonical_repository: "example/repository",
    }
}

fn stages() -> Vec<HistoricalV2SlotStage> {
    vec![
        HistoricalV2SlotStage::Payload,
        HistoricalV2SlotStage::Materialization,
        HistoricalV2SlotStage::TestMaterialization,
        HistoricalV2SlotStage::SourceCensus,
        HistoricalV2SlotStage::SemanticCensus,
        HistoricalV2SlotStage::AssessmentIdentity,
        HistoricalV2SlotStage::Qualification,
        HistoricalV2SlotStage::TestRecipe,
        HistoricalV2SlotStage::IdenticalTests,
        HistoricalV2SlotStage::ReadyForReview,
    ]
}

fn completed(stage: HistoricalV2SlotStage) -> HistoricalV2PreparedStage {
    if stage == HistoricalV2SlotStage::ReadyForReview {
        return HistoricalV2PreparedStage {
            outcome: HistoricalV2SlotStageOutcome::ReadyForReview,
            artifact: None,
        };
    }
    let (artifact_kind, marker) = match stage {
        HistoricalV2SlotStage::Payload => {
            (HistoricalV2StageArtifactKind::SelectedPayload, "payload")
        }
        HistoricalV2SlotStage::Materialization => (
            HistoricalV2StageArtifactKind::Materialization,
            "materialization",
        ),
        HistoricalV2SlotStage::TestMaterialization => (
            HistoricalV2StageArtifactKind::NoTestPatch,
            "test_materialization",
        ),
        HistoricalV2SlotStage::SourceCensus => {
            (HistoricalV2StageArtifactKind::SourceCensus, "source_census")
        }
        HistoricalV2SlotStage::SemanticCensus => (
            HistoricalV2StageArtifactKind::SemanticCensus,
            "semantic_census",
        ),
        HistoricalV2SlotStage::AssessmentIdentity => (
            HistoricalV2StageArtifactKind::AssessmentIdentity,
            "assessment_identity",
        ),
        HistoricalV2SlotStage::Qualification => (
            HistoricalV2StageArtifactKind::Qualification,
            "qualification",
        ),
        HistoricalV2SlotStage::TestRecipe => {
            (HistoricalV2StageArtifactKind::TestRecipe, "test_recipe")
        }
        HistoricalV2SlotStage::IdenticalTests => (
            HistoricalV2StageArtifactKind::IdenticalTestExecution,
            "identical_tests",
        ),
        HistoricalV2SlotStage::ReadyForReview => unreachable!(),
    };
    HistoricalV2PreparedStage {
        outcome: HistoricalV2SlotStageOutcome::Completed {
            artifact_kind,
            artifact_sha256: hash(marker),
        },
        artifact: Some(serde_json::json!({ "stage": marker })),
    }
}

fn exclusion(stage: HistoricalV2SlotStage) -> HistoricalV2PreparedStage {
    assert_eq!(stage, HistoricalV2SlotStage::SourceCensus);
    HistoricalV2PreparedStage {
        outcome: HistoricalV2SlotStageOutcome::Excluded {
            reason: HistoricalV2TerminalExclusionReason::SourceCensus(vec![
                HistoricalV2SourceCensusExclusionReason::SupportedSourceIsNotUtf8,
            ]),
            artifact_kind: HistoricalV2StageArtifactKind::SourceCensusExclusion,
            artifact_sha256: hash("source_exclusion"),
        },
        artifact: Some(serde_json::json!({ "stage": "source_exclusion" })),
    }
}

fn hash(marker: &str) -> String {
    format!("{:x}", Sha256::digest(marker.as_bytes()))
}
