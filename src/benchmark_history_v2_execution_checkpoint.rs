use super::{
    HISTORICAL_V2_EXECUTION_CHECKPOINT_SCHEMA_VERSION, HistoricalV2AssessmentIdentity,
    HistoricalV2AssessmentIdentityInputs, HistoricalV2CheckpointedExecution,
    HistoricalV2ExecutionCheckpoint, HistoricalV2ExecutionCheckpointDisposition,
    HistoricalV2ExecutionError, HistoricalV2IdenticalTestExecution,
    HistoricalV2IdenticalTestExecutor, HistoricalV2IdenticalTestOutcome,
    HistoricalV2IdenticalTestPlan, HistoricalV2Qualification, HistoricalV2TestRecipe,
    execute_historical_v2_identical_tests, prepare_historical_v2_identical_test_plan,
    validate_historical_v2_identical_test_execution,
};
use sha2::{Digest, Sha256};
use std::path::Path;

#[path = "benchmark_history_v2_execution_checkpoint_store.rs"]
mod store;

use store::{ExecutionSlotStore, StoredExecution};

const CHECKPOINT_CONTRACT: &str = "sniffbench-historical-v2-execution-checkpoint-v1";

pub struct HistoricalV2ExecutionCheckpointInputs<'a> {
    pub assessment_inputs: &'a HistoricalV2AssessmentIdentityInputs<'a>,
    pub identity: &'a HistoricalV2AssessmentIdentity,
    pub qualification: &'a HistoricalV2Qualification,
    pub recipe: &'a HistoricalV2TestRecipe,
    pub harness_repository_root: &'a Path,
    pub state_root: &'a Path,
}

pub fn run_historical_v2_identical_tests_checkpointed<E: HistoricalV2IdenticalTestExecutor>(
    inputs: &HistoricalV2ExecutionCheckpointInputs<'_>,
    executor: &E,
) -> Result<HistoricalV2CheckpointedExecution, HistoricalV2ExecutionError> {
    let plan = prepare_historical_v2_identical_test_plan(
        inputs.assessment_inputs,
        inputs.identity,
        inputs.qualification,
        inputs.recipe,
        inputs.harness_repository_root,
    )
    .map_err(HistoricalV2ExecutionError::invalid)?;
    let store = ExecutionSlotStore::open(
        inputs.state_root,
        &inputs.identity.language,
        inputs.identity.slot_number,
    )
    .map_err(HistoricalV2ExecutionError::infrastructure)?;
    if let Some(stored) = store.load().map_err(HistoricalV2ExecutionError::invalid)? {
        return validated_bundle(inputs, &plan, stored, true)
            .map_err(HistoricalV2ExecutionError::invalid);
    }

    let execution = execute_historical_v2_identical_tests(
        inputs.assessment_inputs,
        inputs.identity,
        inputs.qualification,
        inputs.recipe,
        inputs.harness_repository_root,
        &plan,
        executor,
    )?;
    let checkpoint =
        checkpoint(inputs, &plan, &execution).map_err(HistoricalV2ExecutionError::invalid)?;
    store
        .publish(&checkpoint, &plan, &execution)
        .map_err(HistoricalV2ExecutionError::infrastructure)?;
    let stored = store
        .load()
        .map_err(HistoricalV2ExecutionError::invalid)?
        .ok_or_else(|| {
            HistoricalV2ExecutionError::infrastructure(
                "published historical-v2 execution checkpoint disappeared",
            )
        })?;
    validated_bundle(inputs, &plan, stored, false).map_err(HistoricalV2ExecutionError::invalid)
}

pub fn load_historical_v2_execution_checkpoint(
    inputs: &HistoricalV2ExecutionCheckpointInputs<'_>,
) -> Result<Option<HistoricalV2CheckpointedExecution>, HistoricalV2ExecutionError> {
    let plan = prepare_historical_v2_identical_test_plan(
        inputs.assessment_inputs,
        inputs.identity,
        inputs.qualification,
        inputs.recipe,
        inputs.harness_repository_root,
    )
    .map_err(HistoricalV2ExecutionError::invalid)?;
    let store = ExecutionSlotStore::open(
        inputs.state_root,
        &inputs.identity.language,
        inputs.identity.slot_number,
    )
    .map_err(HistoricalV2ExecutionError::infrastructure)?;
    store
        .load()
        .map_err(HistoricalV2ExecutionError::invalid)?
        .map(|stored| validated_bundle(inputs, &plan, stored, true))
        .transpose()
        .map_err(HistoricalV2ExecutionError::invalid)
}

fn checkpoint(
    inputs: &HistoricalV2ExecutionCheckpointInputs<'_>,
    plan: &HistoricalV2IdenticalTestPlan,
    execution: &HistoricalV2IdenticalTestExecution,
) -> Result<HistoricalV2ExecutionCheckpoint, String> {
    validate_historical_v2_identical_test_execution(plan, execution)?;
    seal_checkpoint(HistoricalV2ExecutionCheckpoint {
        schema_version: HISTORICAL_V2_EXECUTION_CHECKPOINT_SCHEMA_VERSION,
        checkpoint_contract: CHECKPOINT_CONTRACT.to_string(),
        selection_sha256: inputs.assessment_inputs.selection.selection_sha256.clone(),
        assessment_identity_sha256: inputs.identity.assessment_identity_sha256.clone(),
        language: inputs.identity.language.clone(),
        slot_number: inputs.identity.slot_number,
        canonical_repository: inputs.identity.canonical_repository.clone(),
        qualification_sha256: inputs.qualification.qualification_sha256.clone(),
        test_recipe_sha256: inputs.recipe.test_recipe_sha256.clone(),
        plan_sha256: plan.plan_sha256.clone(),
        execution_sha256: execution.execution_sha256.clone(),
        disposition: disposition(&execution.outcome),
        checkpoint_sha256: String::new(),
    })
}

fn validated_bundle(
    inputs: &HistoricalV2ExecutionCheckpointInputs<'_>,
    expected_plan: &HistoricalV2IdenticalTestPlan,
    stored: StoredExecution,
    resumed: bool,
) -> Result<HistoricalV2CheckpointedExecution, String> {
    if stored.plan != *expected_plan {
        return Err("historical-v2 checkpoint plan changed".to_string());
    }
    validate_historical_v2_identical_test_execution(&stored.plan, &stored.execution)?;
    let expected_checkpoint = checkpoint(inputs, &stored.plan, &stored.execution)?;
    if stored.checkpoint != expected_checkpoint {
        return Err("historical-v2 execution checkpoint changed".to_string());
    }
    Ok(HistoricalV2CheckpointedExecution {
        checkpoint: stored.checkpoint,
        plan: stored.plan,
        execution: stored.execution,
        resumed,
    })
}

fn disposition(
    outcome: &HistoricalV2IdenticalTestOutcome,
) -> HistoricalV2ExecutionCheckpointDisposition {
    match outcome {
        HistoricalV2IdenticalTestOutcome::Passed => {
            HistoricalV2ExecutionCheckpointDisposition::ReadyForReview
        }
        HistoricalV2IdenticalTestOutcome::Excluded { .. } => {
            HistoricalV2ExecutionCheckpointDisposition::IdenticalTestsExcluded
        }
    }
}

fn seal_checkpoint(
    mut checkpoint: HistoricalV2ExecutionCheckpoint,
) -> Result<HistoricalV2ExecutionCheckpoint, String> {
    checkpoint.checkpoint_sha256 = checkpoint_sha256(&checkpoint)?;
    Ok(checkpoint)
}

fn checkpoint_sha256(checkpoint: &HistoricalV2ExecutionCheckpoint) -> Result<String, String> {
    let mut committed = checkpoint.clone();
    committed.checkpoint_sha256.clear();
    serde_json::to_vec(&committed)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to commit historical-v2 checkpoint: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "benchmark_history_v2_execution_checkpoint_tests.rs"]
mod tests;
