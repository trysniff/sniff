use super::{
    IntentionalBoundaryFrameTask, IntentionalBoundaryRankRunDisposition,
    IntentionalBoundaryRankStage, IntentionalBoundaryRankStageError,
    IntentionalBoundaryRankStageExecutor, IntentionalBoundaryRankStageJournal,
    IntentionalBoundaryRankSweepSummary, run_intentional_boundary_rank,
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
    run_sweep(
        state_root,
        task,
        executor,
        None,
        maximum_new_stages_per_rank,
        through_stage,
    )
    .await
}

pub async fn run_intentional_boundary_rank_sweep_limit<E: IntentionalBoundaryRankStageExecutor>(
    state_root: &Path,
    task: &IntentionalBoundaryFrameTask,
    executor: &mut E,
    maximum_new_ranks: NonZeroUsize,
) -> Result<IntentionalBoundaryRankSweepSummary, IntentionalBoundaryRankStageError> {
    run_sweep(
        state_root,
        task,
        executor,
        Some(maximum_new_ranks),
        None,
        None,
    )
    .await
}

async fn run_sweep<E: IntentionalBoundaryRankStageExecutor>(
    state_root: &Path,
    task: &IntentionalBoundaryFrameTask,
    executor: &mut E,
    maximum_new_ranks: Option<NonZeroUsize>,
    maximum_new_stages_per_rank: Option<NonZeroUsize>,
    through_stage: Option<IntentionalBoundaryRankStage>,
) -> Result<IntentionalBoundaryRankSweepSummary, IntentionalBoundaryRankStageError> {
    validate_intentional_boundary_rank_sweep_task(task)?;
    if maximum_new_ranks.is_some()
        && (maximum_new_stages_per_rank.is_some() || through_stage.is_some())
    {
        return Err(IntentionalBoundaryRankStageError::invalid(
            IntentionalBoundaryRankStage::Materialization,
            "intentional-boundary rank limits require terminal per-rank execution",
        ));
    }
    let mut ranks = Vec::with_capacity(task.repositories.len());
    let mut new_rank_count = 0usize;
    for expected_rank in 1..=task.repositories.len() {
        if maximum_new_ranks.is_some_and(|limit| new_rank_count >= limit.get()) {
            break;
        }
        let had_pending_stage = if maximum_new_ranks.is_some() {
            let journal =
                IntentionalBoundaryRankStageJournal::open(state_root, task, expected_rank)?;
            journal.next_stage()?.is_some()
        } else {
            true
        };
        let summary = if maximum_new_ranks.is_some() {
            run_intentional_boundary_rank(state_root, task, expected_rank, executor).await?
        } else {
            run_intentional_boundary_rank_slice_through(
                state_root,
                task,
                expected_rank,
                executor,
                maximum_new_stages_per_rank,
                through_stage,
            )
            .await?
        };
        if had_pending_stage {
            new_rank_count += 1;
        }
        ranks.push(summary);
    }
    Ok(summarize(ranks))
}

pub(crate) fn validate_intentional_boundary_rank_sweep_task(
    task: &IntentionalBoundaryFrameTask,
) -> Result<(), IntentionalBoundaryRankStageError> {
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
    if task
        .repositories
        .iter()
        .enumerate()
        .any(|(index, repository)| repository.population_rank != index + 1)
    {
        return Err(IntentionalBoundaryRankStageError::invalid(
            IntentionalBoundaryRankStage::Materialization,
            "intentional-boundary frame task rank sequence changed",
        ));
    }
    Ok(())
}

fn summarize(
    ranks: Vec<super::IntentionalBoundaryRankRunSummary>,
) -> IntentionalBoundaryRankSweepSummary {
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
    IntentionalBoundaryRankSweepSummary {
        rank_count: ranks.len(),
        completed_count,
        excluded_count,
        paused_count,
        ranks,
    }
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_rank_sweep_tests.rs"]
mod tests;
