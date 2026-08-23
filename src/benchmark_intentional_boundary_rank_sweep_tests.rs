use super::*;
use crate::benchmark::{
    IntentionalBoundaryMaterializationExclusion,
    IntentionalBoundaryMaterializationExclusionEvidence,
    IntentionalBoundaryMaterializationExclusionReason, IntentionalBoundaryRankStageArtifact,
    IntentionalBoundaryRankStageContext, IntentionalBoundaryRankStageErrorKind,
    IntentionalBoundaryRankStageFuture, IntentionalBoundaryRankStageJournal,
    prepare_intentional_boundary_frame_task,
};

const POLICY: &[u8] = include_bytes!("../sniffbench/non-blind-v1-selection-policy.json");
const POPULATION: &[u8] = include_bytes!("../sniffbench/non-blind-v1-history-worksheet.json");
const BLIND_SEAL: &[u8] = include_bytes!("../sniffbench/blind-oss-v1-source-seal.json");
const PROTOCOL: &[u8] =
    include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-protocol.json");
const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct ExcludingExecutor {
    calls: Vec<usize>,
    fail_once_at: Option<usize>,
}

impl IntentionalBoundaryRankStageExecutor for ExcludingExecutor {
    fn execute<'a>(
        &'a mut self,
        context: IntentionalBoundaryRankStageContext<'a>,
    ) -> IntentionalBoundaryRankStageFuture<'a, IntentionalBoundaryRankStageArtifact> {
        let rank = context.repository_task.population_rank;
        self.calls.push(rank);
        let fail = self.fail_once_at.take_if(|value| *value == rank).is_some();
        Box::pin(async move {
            if fail {
                return Err(IntentionalBoundaryRankStageError::infrastructure(
                    context.stage,
                    "injected sweep interruption",
                ));
            }
            assert_eq!(context.stage, IntentionalBoundaryRankStage::Materialization);
            Ok(IntentionalBoundaryRankStageArtifact::MaterializationExclusion(
                IntentionalBoundaryMaterializationExclusion {
                    schema_version: 1,
                    exclusion_contract: "fixture".to_string(),
                    frame_task_sha256: context.task.task_sha256.clone(),
                    population_rank: rank,
                    population_rank_sha256: context
                        .repository_task
                        .population_rank_sha256
                        .clone(),
                    repository: context.repository_task.repository.clone(),
                    reason:
                        IntentionalBoundaryMaterializationExclusionReason::RepositoryInaccessible,
                    evidence: IntentionalBoundaryMaterializationExclusionEvidence::RepositoryProbe {
                        url: "https://example.invalid/repository.git".to_string(),
                        status: 404,
                    },
                    exclusion_sha256: HASH.to_string(),
                },
            ))
        })
    }
}

#[tokio::test]
async fn frozen_six_hundred_rank_sweep_resumes_after_interruption_without_replay() {
    let task =
        prepare_intentional_boundary_frame_task(POLICY, POPULATION, BLIND_SEAL, PROTOCOL).unwrap();
    assert_eq!(task.repositories.len(), 600);
    let state = tempfile::tempdir().unwrap();
    let mut interrupted = ExcludingExecutor {
        calls: Vec::new(),
        fail_once_at: Some(301),
    };
    let error =
        run_intentional_boundary_rank_sweep(state.path(), &task, &mut interrupted, None, None)
            .await
            .unwrap_err();
    assert_eq!(
        error.kind,
        IntentionalBoundaryRankStageErrorKind::InfrastructureFailed
    );
    assert_eq!(interrupted.calls, (1..=301).collect::<Vec<_>>());

    let rank_300 = IntentionalBoundaryRankStageJournal::open(state.path(), &task, 300).unwrap();
    assert_eq!(rank_300.history().len(), 1);
    drop(rank_300);
    let rank_301 = IntentionalBoundaryRankStageJournal::open(state.path(), &task, 301).unwrap();
    assert!(rank_301.history().is_empty());
    drop(rank_301);

    let mut resumed = ExcludingExecutor {
        calls: Vec::new(),
        fail_once_at: None,
    };
    let summary =
        run_intentional_boundary_rank_sweep(state.path(), &task, &mut resumed, None, None)
            .await
            .unwrap();
    assert_eq!(summary.rank_count, 600);
    assert_eq!(summary.excluded_count, 600);
    assert_eq!(summary.completed_count, 0);
    assert_eq!(summary.paused_count, 0);
    assert_eq!(resumed.calls, (301..=600).collect::<Vec<_>>());
    assert_eq!(summary.ranks[0].resumed_after_sequence, 1);
    assert_eq!(summary.ranks[300].resumed_after_sequence, 0);

    let mut replay = ExcludingExecutor {
        calls: Vec::new(),
        fail_once_at: None,
    };
    let replayed =
        run_intentional_boundary_rank_sweep(state.path(), &task, &mut replay, None, None)
            .await
            .unwrap();
    assert_eq!(replayed.excluded_count, 600);
    assert!(replay.calls.is_empty());
    assert!(
        replayed
            .ranks
            .iter()
            .all(|rank| rank.executed_stages.is_empty())
    );
}

#[tokio::test]
async fn sweep_rejects_a_task_that_allows_model_access() {
    let mut task =
        prepare_intentional_boundary_frame_task(POLICY, POPULATION, BLIND_SEAL, PROTOCOL).unwrap();
    task.model_access_forbidden = false;
    let state = tempfile::tempdir().unwrap();
    let mut executor = ExcludingExecutor {
        calls: Vec::new(),
        fail_once_at: None,
    };

    let error = run_intentional_boundary_rank_sweep(state.path(), &task, &mut executor, None, None)
        .await
        .unwrap_err();

    assert_eq!(
        error.kind,
        IntentionalBoundaryRankStageErrorKind::InvalidInput
    );
    assert!(error.detail.contains("safety policy"));
    assert!(executor.calls.is_empty());
}
