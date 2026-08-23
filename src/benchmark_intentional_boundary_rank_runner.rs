use super::{
    IntentionalBoundaryFrameTask, IntentionalBoundaryRankRunDisposition,
    IntentionalBoundaryRankRunSummary, IntentionalBoundaryRankStage,
    IntentionalBoundaryRankStageContext, IntentionalBoundaryRankStageError,
    IntentionalBoundaryRankStageExecutor, IntentionalBoundaryRankStageJournal,
    IntentionalBoundaryRankStageOutcome,
};
use std::num::NonZeroUsize;
use std::path::Path;

pub async fn run_intentional_boundary_rank<E: IntentionalBoundaryRankStageExecutor>(
    state_root: &Path,
    task: &IntentionalBoundaryFrameTask,
    population_rank: usize,
    executor: &mut E,
) -> Result<IntentionalBoundaryRankRunSummary, IntentionalBoundaryRankStageError> {
    run_intentional_boundary_rank_slice(state_root, task, population_rank, executor, None).await
}

pub async fn run_intentional_boundary_rank_slice<E: IntentionalBoundaryRankStageExecutor>(
    state_root: &Path,
    task: &IntentionalBoundaryFrameTask,
    population_rank: usize,
    executor: &mut E,
    maximum_new_stages: Option<NonZeroUsize>,
) -> Result<IntentionalBoundaryRankRunSummary, IntentionalBoundaryRankStageError> {
    run_intentional_boundary_rank_slice_through(
        state_root,
        task,
        population_rank,
        executor,
        maximum_new_stages,
        None,
    )
    .await
}

pub async fn run_intentional_boundary_rank_slice_through<
    E: IntentionalBoundaryRankStageExecutor,
>(
    state_root: &Path,
    task: &IntentionalBoundaryFrameTask,
    population_rank: usize,
    executor: &mut E,
    maximum_new_stages: Option<NonZeroUsize>,
    through_stage: Option<IntentionalBoundaryRankStage>,
) -> Result<IntentionalBoundaryRankRunSummary, IntentionalBoundaryRankStageError> {
    let repository_task = task
        .repositories
        .get(population_rank.saturating_sub(1))
        .filter(|repository| repository.population_rank == population_rank)
        .ok_or_else(|| {
            IntentionalBoundaryRankStageError::invalid(
                IntentionalBoundaryRankStage::Materialization,
                format!("intentional-boundary rank {population_rank} is outside its frame task"),
            )
        })?;
    let mut journal = IntentionalBoundaryRankStageJournal::open(state_root, task, population_rank)?;
    let resumed_after_sequence = journal.history().len();
    let mut executed_stages = Vec::new();

    loop {
        let Some(stage) = journal.next_stage()? else {
            return terminal_summary(&journal, resumed_after_sequence, executed_stages);
        };
        if through_stage.is_some_and(|last_stage| stage > last_stage)
            || maximum_new_stages.is_some_and(|limit| executed_stages.len() >= limit.get())
        {
            return Ok(IntentionalBoundaryRankRunSummary {
                population_rank,
                repository: repository_task.repository.clone(),
                resumed_after_sequence,
                executed_stages,
                terminal_checkpoint_sha256: None,
                disposition: IntentionalBoundaryRankRunDisposition::Paused { next_stage: stage },
            });
        }

        executor
            .recover(IntentionalBoundaryRankStageContext {
                task,
                repository_task,
                stage,
                history: journal.history(),
            })
            .await?;
        let artifact = executor
            .execute(IntentionalBoundaryRankStageContext {
                task,
                repository_task,
                stage,
                history: journal.history(),
            })
            .await?;
        journal.append(task, &artifact)?;
        executed_stages.push(stage);
    }
}

fn terminal_summary(
    journal: &IntentionalBoundaryRankStageJournal,
    resumed_after_sequence: usize,
    executed_stages: Vec<IntentionalBoundaryRankStage>,
) -> Result<IntentionalBoundaryRankRunSummary, IntentionalBoundaryRankStageError> {
    let last = journal.history().last().ok_or_else(|| {
        IntentionalBoundaryRankStageError::invalid(
            IntentionalBoundaryRankStage::Materialization,
            "intentional-boundary rank has no next stage or terminal checkpoint",
        )
    })?;
    let disposition = match last.checkpoint.outcome {
        IntentionalBoundaryRankStageOutcome::Excluded { artifact_kind, .. } => {
            IntentionalBoundaryRankRunDisposition::Excluded {
                stage: last.checkpoint.stage,
                artifact_kind,
            }
        }
        IntentionalBoundaryRankStageOutcome::Completed { .. }
            if last.checkpoint.stage == IntentionalBoundaryRankStage::Candidate =>
        {
            IntentionalBoundaryRankRunDisposition::Completed
        }
        IntentionalBoundaryRankStageOutcome::Completed { .. } => {
            return Err(IntentionalBoundaryRankStageError::invalid(
                last.checkpoint.stage,
                "intentional-boundary rank has a nonterminal completed history",
            ));
        }
    };
    Ok(IntentionalBoundaryRankRunSummary {
        population_rank: last.checkpoint.population_rank,
        repository: last.checkpoint.repository.clone(),
        resumed_after_sequence,
        executed_stages,
        terminal_checkpoint_sha256: Some(last.checkpoint.checkpoint_sha256.clone()),
        disposition,
    })
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_rank_runner_tests.rs"]
mod tests;
