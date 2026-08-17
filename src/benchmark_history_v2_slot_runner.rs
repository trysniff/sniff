use super::{
    HistoricalV2PreparedStage, HistoricalV2SlotRunDisposition, HistoricalV2SlotRunIdentity,
    HistoricalV2SlotRunSummary, HistoricalV2SlotStage, HistoricalV2SlotStageCheckpointInput,
    HistoricalV2SlotStageContext, HistoricalV2SlotStageError, HistoricalV2SlotStageExecutor,
    HistoricalV2SlotStageJournal, HistoricalV2SlotStageOutcome,
};
use std::num::NonZeroUsize;
use std::path::Path;

pub async fn run_historical_v2_slot<E: HistoricalV2SlotStageExecutor>(
    state_root: &Path,
    identity: HistoricalV2SlotRunIdentity<'_>,
    executor: &mut E,
) -> Result<HistoricalV2SlotRunSummary, HistoricalV2SlotStageError> {
    run_historical_v2_slot_slice(state_root, identity, executor, None).await
}

pub async fn run_historical_v2_slot_slice<E: HistoricalV2SlotStageExecutor>(
    state_root: &Path,
    identity: HistoricalV2SlotRunIdentity<'_>,
    executor: &mut E,
    maximum_new_stages: Option<NonZeroUsize>,
) -> Result<HistoricalV2SlotRunSummary, HistoricalV2SlotStageError> {
    run_historical_v2_slot_slice_through(state_root, identity, executor, maximum_new_stages, None)
        .await
}

pub async fn run_historical_v2_slot_slice_through<E: HistoricalV2SlotStageExecutor>(
    state_root: &Path,
    identity: HistoricalV2SlotRunIdentity<'_>,
    executor: &mut E,
    maximum_new_stages: Option<NonZeroUsize>,
    through_stage: Option<HistoricalV2SlotStage>,
) -> Result<HistoricalV2SlotRunSummary, HistoricalV2SlotStageError> {
    let mut journal =
        HistoricalV2SlotStageJournal::open(state_root, identity.language, identity.slot_number)?;
    validate_existing_identity(&journal, identity)?;
    let resumed_after_sequence = journal.history().len();
    let mut executed_stages = Vec::new();

    loop {
        if let Some(summary) =
            terminal_summary(&journal, resumed_after_sequence, executed_stages.clone())?
        {
            return Ok(summary);
        }
        let stage = next_stage(&journal)?;
        if through_stage.is_some_and(|last_stage| stage > last_stage) {
            return Ok(HistoricalV2SlotRunSummary {
                resumed_after_sequence,
                executed_stages,
                terminal_checkpoint_sha256: None,
                disposition: HistoricalV2SlotRunDisposition::Paused { next_stage: stage },
            });
        }
        if maximum_new_stages.is_some_and(|limit| executed_stages.len() >= limit.get()) {
            return Ok(HistoricalV2SlotRunSummary {
                resumed_after_sequence,
                executed_stages,
                terminal_checkpoint_sha256: None,
                disposition: HistoricalV2SlotRunDisposition::Paused { next_stage: stage },
            });
        }

        executor
            .recover(HistoricalV2SlotStageContext {
                identity,
                stage,
                history: journal.history(),
            })
            .await?;
        let prepared = executor
            .execute(HistoricalV2SlotStageContext {
                identity,
                stage,
                history: journal.history(),
            })
            .await?;
        append_prepared_stage(&mut journal, identity, stage, prepared)?;
        executed_stages.push(stage);
    }
}

fn append_prepared_stage(
    journal: &mut HistoricalV2SlotStageJournal,
    identity: HistoricalV2SlotRunIdentity<'_>,
    stage: HistoricalV2SlotStage,
    prepared: HistoricalV2PreparedStage,
) -> Result<(), HistoricalV2SlotStageError> {
    journal.append(
        HistoricalV2SlotStageCheckpointInput {
            selection_sha256: identity.selection_sha256,
            language: identity.language,
            slot_number: identity.slot_number,
            canonical_repository: identity.canonical_repository,
            stage,
            outcome: prepared.outcome,
        },
        prepared.artifact.as_ref(),
    )?;
    Ok(())
}

fn validate_existing_identity(
    journal: &HistoricalV2SlotStageJournal,
    identity: HistoricalV2SlotRunIdentity<'_>,
) -> Result<(), HistoricalV2SlotStageError> {
    let Some(first) = journal.history().first() else {
        return Ok(());
    };
    let checkpoint = &first.checkpoint;
    if checkpoint.selection_sha256 != identity.selection_sha256
        || checkpoint.language != identity.language
        || checkpoint.slot_number != identity.slot_number
        || checkpoint.canonical_repository != identity.canonical_repository
    {
        return Err(HistoricalV2SlotStageError::invalid(
            checkpoint.stage,
            "historical-v2 runner identity changed across resume",
        ));
    }
    Ok(())
}

fn next_stage(
    journal: &HistoricalV2SlotStageJournal,
) -> Result<HistoricalV2SlotStage, HistoricalV2SlotStageError> {
    super::history_v2_slot_stage::expected_historical_v2_slot_stage(journal.history().len())
        .ok_or_else(|| {
            HistoricalV2SlotStageError::invalid(
                HistoricalV2SlotStage::ReadyForReview,
                "historical-v2 runner found a nonterminal complete stage history",
            )
        })
}

fn terminal_summary(
    journal: &HistoricalV2SlotStageJournal,
    resumed_after_sequence: usize,
    executed_stages: Vec<HistoricalV2SlotStage>,
) -> Result<Option<HistoricalV2SlotRunSummary>, HistoricalV2SlotStageError> {
    let Some(last) = journal.history().last() else {
        return Ok(None);
    };
    let disposition = match &last.checkpoint.outcome {
        HistoricalV2SlotStageOutcome::Excluded { reason, .. } => {
            HistoricalV2SlotRunDisposition::Excluded {
                stage: last.checkpoint.stage,
                reason: reason.clone(),
            }
        }
        HistoricalV2SlotStageOutcome::ReadyForReview => {
            HistoricalV2SlotRunDisposition::ReadyForReview
        }
        HistoricalV2SlotStageOutcome::Completed { .. } => return Ok(None),
    };
    Ok(Some(HistoricalV2SlotRunSummary {
        resumed_after_sequence,
        executed_stages,
        terminal_checkpoint_sha256: Some(last.checkpoint.checkpoint_sha256.clone()),
        disposition,
    }))
}

#[cfg(test)]
#[path = "benchmark_history_v2_slot_runner_tests.rs"]
mod tests;
