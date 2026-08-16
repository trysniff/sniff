use super::{
    HistoricalV2AssessmentIdentity, HistoricalV2AssessmentIdentityInputs,
    HistoricalV2IdenticalTestExecution, HistoricalV2IdenticalTestOutcome,
    HistoricalV2IdenticalTestPlan, HistoricalV2Qualification, HistoricalV2QualificationOutcome,
    HistoricalV2SlotStage, HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageCheckpointInput,
    HistoricalV2SlotStageError, HistoricalV2SlotStageJournal, HistoricalV2SlotStageOutcome,
    HistoricalV2StageArtifactKind, HistoricalV2TerminalExclusionReason, HistoricalV2TestRecipe,
    HistoricalV2TestRecipeOutcome, validate_historical_v2_identical_test_execution,
    validate_historical_v2_qualification_commitment, validate_historical_v2_test_recipe,
};
use serde::Serialize;

pub fn checkpoint_historical_v2_qualification(
    journal: &mut HistoricalV2SlotStageJournal,
    inputs: &HistoricalV2AssessmentIdentityInputs<'_>,
    identity: &HistoricalV2AssessmentIdentity,
    qualification: &HistoricalV2Qualification,
) -> Result<HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageError> {
    let stage = HistoricalV2SlotStage::Qualification;
    validate_historical_v2_qualification_commitment(inputs, identity, qualification)
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    append_same_slot(
        journal,
        stage,
        qualification_outcome(qualification),
        Some(qualification),
    )
}

pub fn checkpoint_historical_v2_test_recipe(
    journal: &mut HistoricalV2SlotStageJournal,
    inputs: &HistoricalV2AssessmentIdentityInputs<'_>,
    identity: &HistoricalV2AssessmentIdentity,
    qualification: &HistoricalV2Qualification,
    recipe: &HistoricalV2TestRecipe,
) -> Result<HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageError> {
    let stage = HistoricalV2SlotStage::TestRecipe;
    validate_historical_v2_test_recipe(inputs, identity, qualification, recipe)
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    append_same_slot(journal, stage, test_recipe_outcome(recipe), Some(recipe))
}

pub fn checkpoint_historical_v2_identical_test_execution(
    journal: &mut HistoricalV2SlotStageJournal,
    plan: &HistoricalV2IdenticalTestPlan,
    execution: &HistoricalV2IdenticalTestExecution,
) -> Result<HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageError> {
    let stage = HistoricalV2SlotStage::IdenticalTests;
    validate_historical_v2_identical_test_execution(plan, execution)
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    append_same_slot(
        journal,
        stage,
        identical_test_outcome(execution),
        Some(execution),
    )
}

pub fn checkpoint_historical_v2_ready_for_review(
    journal: &mut HistoricalV2SlotStageJournal,
    plan: &HistoricalV2IdenticalTestPlan,
    execution: &HistoricalV2IdenticalTestExecution,
) -> Result<HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageError> {
    let stage = HistoricalV2SlotStage::ReadyForReview;
    validate_historical_v2_identical_test_execution(plan, execution)
        .map_err(|detail| HistoricalV2SlotStageError::invalid(stage, detail))?;
    if !matches!(execution.outcome, HistoricalV2IdenticalTestOutcome::Passed) {
        return Err(HistoricalV2SlotStageError::invalid(
            stage,
            "historical-v2 excluded execution cannot become ready for review",
        ));
    }
    append_same_slot::<serde_json::Value>(
        journal,
        stage,
        HistoricalV2SlotStageOutcome::ReadyForReview,
        None,
    )
}

fn append_same_slot<T: Serialize>(
    journal: &mut HistoricalV2SlotStageJournal,
    stage: HistoricalV2SlotStage,
    outcome: HistoricalV2SlotStageOutcome,
    artifact: Option<&T>,
) -> Result<HistoricalV2SlotStageCheckpoint, HistoricalV2SlotStageError> {
    let first = journal.history().first().ok_or_else(|| {
        HistoricalV2SlotStageError::invalid(
            stage,
            "historical-v2 slot journal has no payload identity",
        )
    })?;
    let selection_sha256 = first.checkpoint.selection_sha256.clone();
    let language = first.checkpoint.language.clone();
    let slot_number = first.checkpoint.slot_number;
    let canonical_repository = first.checkpoint.canonical_repository.clone();
    journal.append(
        HistoricalV2SlotStageCheckpointInput {
            selection_sha256: &selection_sha256,
            language: &language,
            slot_number,
            canonical_repository: &canonical_repository,
            stage,
            outcome,
        },
        artifact,
    )
}

fn qualification_outcome(
    qualification: &HistoricalV2Qualification,
) -> HistoricalV2SlotStageOutcome {
    match &qualification.outcome {
        HistoricalV2QualificationOutcome::Qualified => HistoricalV2SlotStageOutcome::Completed {
            artifact_kind: HistoricalV2StageArtifactKind::Qualification,
            artifact_sha256: qualification.qualification_sha256.clone(),
        },
        HistoricalV2QualificationOutcome::Excluded { reasons } => {
            HistoricalV2SlotStageOutcome::Excluded {
                reason: HistoricalV2TerminalExclusionReason::Qualification(reasons.clone()),
                artifact_kind: HistoricalV2StageArtifactKind::Qualification,
                artifact_sha256: qualification.qualification_sha256.clone(),
            }
        }
    }
}

fn test_recipe_outcome(recipe: &HistoricalV2TestRecipe) -> HistoricalV2SlotStageOutcome {
    match &recipe.outcome {
        HistoricalV2TestRecipeOutcome::Selected { .. } => HistoricalV2SlotStageOutcome::Completed {
            artifact_kind: HistoricalV2StageArtifactKind::TestRecipe,
            artifact_sha256: recipe.test_recipe_sha256.clone(),
        },
        HistoricalV2TestRecipeOutcome::Excluded { reason } => {
            HistoricalV2SlotStageOutcome::Excluded {
                reason: HistoricalV2TerminalExclusionReason::TestRecipe(*reason),
                artifact_kind: HistoricalV2StageArtifactKind::TestRecipe,
                artifact_sha256: recipe.test_recipe_sha256.clone(),
            }
        }
    }
}

fn identical_test_outcome(
    execution: &HistoricalV2IdenticalTestExecution,
) -> HistoricalV2SlotStageOutcome {
    match &execution.outcome {
        HistoricalV2IdenticalTestOutcome::Passed => HistoricalV2SlotStageOutcome::Completed {
            artifact_kind: HistoricalV2StageArtifactKind::IdenticalTestExecution,
            artifact_sha256: execution.execution_sha256.clone(),
        },
        HistoricalV2IdenticalTestOutcome::Excluded { reason } => {
            HistoricalV2SlotStageOutcome::Excluded {
                reason: HistoricalV2TerminalExclusionReason::IdenticalTests(reason.clone()),
                artifact_kind: HistoricalV2StageArtifactKind::IdenticalTestExecution,
                artifact_sha256: execution.execution_sha256.clone(),
            }
        }
    }
}

#[cfg(test)]
#[path = "benchmark_history_v2_stage_adapters_tests.rs"]
mod tests;
