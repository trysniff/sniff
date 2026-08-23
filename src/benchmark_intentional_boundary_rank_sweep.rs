use super::{
    IntentionalBoundaryFrameTask, IntentionalBoundaryRankRunDisposition,
    IntentionalBoundaryRankStage, IntentionalBoundaryRankStageError,
    IntentionalBoundaryRankStageExecutor, IntentionalBoundaryRankSweepSummary,
    run_intentional_boundary_rank_slice_through,
};
use std::num::NonZeroUsize;
use std::path::Path;

pub async fn run_intentional_boundary_rank_sweep<E: IntentionalBoundaryRankStageExecutor>(
    state_root: &Path,
    task: &IntentionalBoundaryFrameTask,
    executor: &mut E,
    maximum_new_stages_per_rank: Option<NonZeroUsize>,
    through_stage: Option<IntentionalBoundaryRankStage>,
) -> Result<IntentionalBoundaryRankSweepSummary, IntentionalBoundaryRankStageError> {
    if task.repositories.len() != 600 {
        return Err(IntentionalBoundaryRankStageError::invalid(
            IntentionalBoundaryRankStage::Materialization,
            "intentional-boundary frame task must contain exactly 600 population ranks",
        ));
    }
    if !task.no_fallbacks || !task.model_access_forbidden || !task.sniff_output_access_forbidden {
        return Err(IntentionalBoundaryRankStageError::invalid(
            IntentionalBoundaryRankStage::Materialization,
            "intentional-boundary frame task safety policy changed",
        ));
    }
    let mut ranks = Vec::with_capacity(task.repositories.len());
    for expected_rank in 1..=task.repositories.len() {
        let repository = &task.repositories[expected_rank - 1];
        if repository.population_rank != expected_rank {
            return Err(IntentionalBoundaryRankStageError::invalid(
                IntentionalBoundaryRankStage::Materialization,
                "intentional-boundary frame task rank sequence changed",
            ));
        }
        ranks.push(
            run_intentional_boundary_rank_slice_through(
                state_root,
                task,
                expected_rank,
                executor,
                maximum_new_stages_per_rank,
                through_stage,
            )
            .await?,
        );
    }
    let completed_count = ranks
        .iter()
        .filter(|rank| {
            matches!(
                rank.disposition,
                IntentionalBoundaryRankRunDisposition::Completed
            )
        })
        .count();
    let excluded_count = ranks
        .iter()
        .filter(|rank| {
            matches!(
                rank.disposition,
                IntentionalBoundaryRankRunDisposition::Excluded { .. }
            )
        })
        .count();
    let paused_count = ranks.len() - completed_count - excluded_count;
    Ok(IntentionalBoundaryRankSweepSummary {
        rank_count: ranks.len(),
        completed_count,
        excluded_count,
        paused_count,
        ranks,
    })
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_rank_sweep_tests.rs"]
mod tests;
