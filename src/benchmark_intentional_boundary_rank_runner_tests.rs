use super::*;
use crate::benchmark::{
    BoundaryGitObjectFormat, IntentionalBoundaryMaterialization,
    IntentionalBoundaryMaterializationExclusion,
    IntentionalBoundaryMaterializationExclusionEvidence,
    IntentionalBoundaryMaterializationExclusionReason, IntentionalBoundaryRankStageArtifact,
    IntentionalBoundaryRankStageErrorKind, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundaryStoredRankStage, prepare_intentional_boundary_frame_task,
};
use std::cell::RefCell;
use std::num::NonZeroUsize;

const POLICY: &[u8] = include_bytes!("../sniffbench/non-blind-v1-selection-policy.json");
const POPULATION: &[u8] = include_bytes!("../sniffbench/non-blind-v1-history-worksheet.json");
const BLIND_SEAL: &[u8] = include_bytes!("../sniffbench/blind-oss-v1-source-seal.json");
const PROTOCOL: &[u8] =
    include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-protocol.json");
const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct RecordingExecutor {
    recovered: RefCell<Vec<IntentionalBoundaryRankStage>>,
    executed: RefCell<Vec<IntentionalBoundaryRankStage>>,
    recover_fail_at: Option<IntentionalBoundaryRankStage>,
    fail_at: Option<IntentionalBoundaryRankStage>,
    exclude_materialization: bool,
    return_wrong_stage: bool,
}

impl RecordingExecutor {
    fn clean() -> Self {
        Self {
            recovered: RefCell::new(Vec::new()),
            executed: RefCell::new(Vec::new()),
            recover_fail_at: None,
            fail_at: None,
            exclude_materialization: false,
            return_wrong_stage: false,
        }
    }
}

impl IntentionalBoundaryRankStageExecutor for RecordingExecutor {
    fn recover<'a>(
        &'a mut self,
        context: IntentionalBoundaryRankStageContext<'a>,
    ) -> crate::benchmark::IntentionalBoundaryRankStageFuture<'a, ()> {
        self.recovered.borrow_mut().push(context.stage);
        let fail = self.recover_fail_at == Some(context.stage);
        Box::pin(async move {
            if fail {
                Err(IntentionalBoundaryRankStageError::infrastructure(
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
        context: IntentionalBoundaryRankStageContext<'a>,
    ) -> crate::benchmark::IntentionalBoundaryRankStageFuture<
        'a,
        IntentionalBoundaryRankStageArtifact,
    > {
        self.executed.borrow_mut().push(context.stage);
        let fail = self.fail_at == Some(context.stage);
        let exclude = self.exclude_materialization;
        let wrong = self.return_wrong_stage;
        Box::pin(async move {
            if fail {
                return Err(IntentionalBoundaryRankStageError::infrastructure(
                    context.stage,
                    "injected execution failure",
                ));
            }
            if wrong {
                return Ok(inventory_artifact(context));
            }
            match context.stage {
                IntentionalBoundaryRankStage::Materialization if exclude => {
                    Ok(exclusion_artifact(context))
                }
                IntentionalBoundaryRankStage::Materialization => {
                    Ok(materialization_artifact(context))
                }
                IntentionalBoundaryRankStage::Inventory => Ok(inventory_artifact(context)),
                _ => panic!("fixture executor reached an unconfigured stage"),
            }
        })
    }
}

#[tokio::test]
async fn rank_pauses_and_resumes_at_the_first_uncommitted_stage() {
    let task = task();
    let state = tempfile::tempdir().unwrap();
    let mut first = RecordingExecutor::clean();
    let partial = run_intentional_boundary_rank_slice(
        state.path(),
        &task,
        1,
        &mut first,
        NonZeroUsize::new(1),
    )
    .await
    .unwrap();
    assert_eq!(
        partial.disposition,
        IntentionalBoundaryRankRunDisposition::Paused {
            next_stage: IntentionalBoundaryRankStage::Inventory,
        }
    );

    let mut resumed = RecordingExecutor::clean();
    let second = run_intentional_boundary_rank_slice(
        state.path(),
        &task,
        1,
        &mut resumed,
        NonZeroUsize::new(1),
    )
    .await
    .unwrap();
    assert_eq!(second.resumed_after_sequence, 1);
    assert_eq!(
        second.executed_stages,
        [IntentionalBoundaryRankStage::Inventory]
    );
    assert_eq!(
        second.disposition,
        IntentionalBoundaryRankRunDisposition::Paused {
            next_stage: IntentionalBoundaryRankStage::SourceCensus,
        }
    );
}

#[tokio::test]
async fn operational_failure_never_advances_the_journal() {
    let task = task();
    let state = tempfile::tempdir().unwrap();
    let mut first = RecordingExecutor::clean();
    run_intentional_boundary_rank_slice(state.path(), &task, 1, &mut first, NonZeroUsize::new(1))
        .await
        .unwrap();

    let mut failing = RecordingExecutor {
        fail_at: Some(IntentionalBoundaryRankStage::Inventory),
        ..RecordingExecutor::clean()
    };
    let error = run_intentional_boundary_rank(state.path(), &task, 1, &mut failing)
        .await
        .unwrap_err();
    assert_eq!(
        error.kind,
        IntentionalBoundaryRankStageErrorKind::InfrastructureFailed
    );

    let journal = IntentionalBoundaryRankStageJournal::open(state.path(), &task, 1).unwrap();
    assert_eq!(journal.history().len(), 1);
    assert_eq!(
        journal.next_stage().unwrap(),
        Some(IntentionalBoundaryRankStage::Inventory)
    );
}

#[tokio::test]
async fn recovery_failure_and_wrong_stage_artifact_never_commit() {
    let task = task();
    let recovery_state = tempfile::tempdir().unwrap();
    let mut recovery_failure = RecordingExecutor {
        recover_fail_at: Some(IntentionalBoundaryRankStage::Materialization),
        ..RecordingExecutor::clean()
    };
    run_intentional_boundary_rank(recovery_state.path(), &task, 1, &mut recovery_failure)
        .await
        .unwrap_err();
    assert!(recovery_failure.executed.borrow().is_empty());
    assert!(
        IntentionalBoundaryRankStageJournal::open(recovery_state.path(), &task, 1)
            .unwrap()
            .history()
            .is_empty()
    );

    let wrong_state = tempfile::tempdir().unwrap();
    let mut wrong = RecordingExecutor {
        return_wrong_stage: true,
        ..RecordingExecutor::clean()
    };
    let error = run_intentional_boundary_rank(wrong_state.path(), &task, 1, &mut wrong)
        .await
        .unwrap_err();
    assert_eq!(
        error.kind,
        IntentionalBoundaryRankStageErrorKind::InvalidInput
    );
    assert!(
        IntentionalBoundaryRankStageJournal::open(wrong_state.path(), &task, 1)
            .unwrap()
            .history()
            .is_empty()
    );
}

#[tokio::test]
async fn terminal_exclusion_is_stable_and_never_reexecutes() {
    let task = task();
    let state = tempfile::tempdir().unwrap();
    let mut excluding = RecordingExecutor {
        exclude_materialization: true,
        ..RecordingExecutor::clean()
    };
    let first = run_intentional_boundary_rank(state.path(), &task, 1, &mut excluding)
        .await
        .unwrap();
    assert!(matches!(
        first.disposition,
        IntentionalBoundaryRankRunDisposition::Excluded {
            stage: IntentionalBoundaryRankStage::Materialization,
            ..
        }
    ));

    let mut resumed = RecordingExecutor::clean();
    let second = run_intentional_boundary_rank(state.path(), &task, 1, &mut resumed)
        .await
        .unwrap();
    assert_eq!(second.resumed_after_sequence, 1);
    assert!(second.executed_stages.is_empty());
    assert!(resumed.recovered.borrow().is_empty());
    assert!(resumed.executed.borrow().is_empty());
}

fn task() -> IntentionalBoundaryFrameTask {
    prepare_intentional_boundary_frame_task(POLICY, POPULATION, BLIND_SEAL, PROTOCOL).unwrap()
}

fn materialization_artifact(
    context: IntentionalBoundaryRankStageContext<'_>,
) -> IntentionalBoundaryRankStageArtifact {
    IntentionalBoundaryRankStageArtifact::Materialization(IntentionalBoundaryMaterialization {
        schema_version: 1,
        materialization_contract: "fixture".to_string(),
        frame_task_sha256: context.task.task_sha256.clone(),
        population_rank: context.repository_task.population_rank,
        population_rank_sha256: context.repository_task.population_rank_sha256.clone(),
        repository: context.repository_task.repository.clone(),
        clone_url: "https://example.invalid/repository.git".to_string(),
        revision: "1".repeat(40),
        git_object_format: "sha1".to_string(),
        tree_oid: "2".repeat(40),
        materialization_sha256: HASH_A.to_string(),
    })
}

fn inventory_artifact(
    context: IntentionalBoundaryRankStageContext<'_>,
) -> IntentionalBoundaryRankStageArtifact {
    let revision = committed_materialization(context.history)
        .map(|materialization| materialization.revision.clone())
        .unwrap_or_else(|| "1".repeat(40));
    IntentionalBoundaryRankStageArtifact::Inventory(IntentionalBoundaryRepositoryInventory {
        schema_version: 1,
        inventory_contract: "fixture".to_string(),
        repository: context.repository_task.repository.clone(),
        revision,
        git_object_format: BoundaryGitObjectFormat::Sha1,
        tracked_entries: Vec::new(),
        inventory_sha256: HASH_B.to_string(),
    })
}

fn committed_materialization(
    history: &[IntentionalBoundaryStoredRankStage],
) -> Option<&IntentionalBoundaryMaterialization> {
    match history.first().map(|stored| &stored.artifact) {
        Some(IntentionalBoundaryRankStageArtifact::Materialization(materialization)) => {
            Some(materialization)
        }
        _ => None,
    }
}

fn exclusion_artifact(
    context: IntentionalBoundaryRankStageContext<'_>,
) -> IntentionalBoundaryRankStageArtifact {
    IntentionalBoundaryRankStageArtifact::MaterializationExclusion(
        IntentionalBoundaryMaterializationExclusion {
            schema_version: 1,
            exclusion_contract: "fixture".to_string(),
            frame_task_sha256: context.task.task_sha256.clone(),
            population_rank: context.repository_task.population_rank,
            population_rank_sha256: context.repository_task.population_rank_sha256.clone(),
            repository: context.repository_task.repository.clone(),
            reason: IntentionalBoundaryMaterializationExclusionReason::RepositoryInaccessible,
            evidence: IntentionalBoundaryMaterializationExclusionEvidence::RepositoryProbe {
                url: "https://example.invalid/repository.git".to_string(),
                status: 404,
            },
            exclusion_sha256: HASH_A.to_string(),
        },
    )
}
