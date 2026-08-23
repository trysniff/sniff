use super::super::{HistoricalTestRecipeDiscovery, HistoricalTestRecipeStatus};
use super::{IntentionalBoundaryBehaviorExecution, count_tests, is_sha256, runtime};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub(super) fn validate_execution(
    execution: &IntentionalBoundaryBehaviorExecution,
    expected_revision: &str,
) -> Result<(), String> {
    if execution.execution_id != runtime::compute_execution_id(execution)?
        || execution.revision != expected_revision
        || execution.provider != execution.selector.provider()
        || !is_sha256(&execution.recipe_sha256)
        || execution.command.is_empty()
        || execution
            .command
            .iter()
            .any(|argument| argument.is_empty() || argument.contains('\0'))
        || !is_sha256(&execution.runtime_identity_sha256)
        || execution.network_enabled
        || !is_sha256(&execution.stdout_sha256)
        || !is_sha256(&execution.stderr_sha256)
        || !is_sha256(&execution.raw_result_sha256)
        || (!execution.test_executed
            && (execution.executed_test_count != 0 || execution.matched_test_count != 0))
        || execution.matched_test_count > execution.executed_test_count
    {
        return Err("intentional-boundary behavior execution changed".to_string());
    }
    let recipe: HistoricalTestRecipeDiscovery = serde_json::from_str(&execution.recipe_json)
        .map_err(|_| "intentional-boundary behavior recipe receipt changed".to_string())?;
    if recipe.status != HistoricalTestRecipeStatus::Selected
        || sha256(execution.recipe_json.as_bytes()) != execution.recipe_sha256
    {
        return Err("intentional-boundary behavior recipe receipt changed".to_string());
    }
    let (preparation, command) = runtime::targeted_command(&execution.selector, &recipe)
        .map_err(|_| "intentional-boundary behavior targeted recipe changed".to_string())?;
    if command != execution.command {
        return Err("intentional-boundary behavior targeted command changed".to_string());
    }
    validate_raw_receipt(execution, &preparation)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExecutionReceipt {
    schema_version: u32,
    revision: String,
    runtime_identity: String,
    network_enabled: bool,
    preparation: Vec<RawStepReceipt>,
    test: Option<RawStepReceipt>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStepReceipt {
    stage: String,
    logical_command: Vec<String>,
    launcher_kind: String,
    status_code: Option<i32>,
    timed_out: bool,
    network_enabled: bool,
    stdout_complete_sha256: String,
    stderr_complete_sha256: String,
    stdout_bounded_sanitized: String,
    stderr_bounded_sanitized: String,
}

fn validate_raw_receipt(
    execution: &IntentionalBoundaryBehaviorExecution,
    expected_preparation: &[Vec<String>],
) -> Result<(), String> {
    if sha256(execution.raw_result_json.as_bytes()) != execution.raw_result_sha256 {
        return Err("intentional-boundary behavior raw receipt hash changed".to_string());
    }
    let raw: RawExecutionReceipt = serde_json::from_str(&execution.raw_result_json)
        .map_err(|_| "intentional-boundary behavior raw receipt changed".to_string())?;
    if raw.schema_version != 1
        || raw.revision != execution.revision
        || sha256(raw.runtime_identity.as_bytes()) != execution.runtime_identity_sha256
        || raw.network_enabled
        || raw.preparation.len() != expected_preparation.len()
    {
        return Err("intentional-boundary behavior raw receipt changed".to_string());
    }
    for (index, (step, expected)) in raw.preparation.iter().zip(expected_preparation).enumerate() {
        if step.stage != format!("preparation_{}", index + 1)
            || step.logical_command != *expected
            || step.launcher_kind.trim().is_empty()
            || step.network_enabled
            || !is_sha256(&step.stdout_complete_sha256)
            || !is_sha256(&step.stderr_complete_sha256)
        {
            return Err("intentional-boundary behavior preparation receipt changed".to_string());
        }
    }
    if execution.test_executed != raw.test.is_some() {
        return Err("intentional-boundary behavior test receipt changed".to_string());
    }
    if let Some(test) = &raw.test
        && (test.stage != "test"
            || test.logical_command != execution.command
            || test.launcher_kind.trim().is_empty()
            || test.network_enabled)
    {
        return Err("intentional-boundary behavior test receipt changed".to_string());
    }
    let representative = raw
        .test
        .as_ref()
        .or_else(|| raw.preparation.last())
        .ok_or_else(|| "intentional-boundary behavior receipt has no process result".to_string())?;
    if representative.status_code != execution.status_code
        || representative.timed_out != execution.timed_out
        || representative.stdout_complete_sha256 != execution.stdout_sha256
        || representative.stderr_complete_sha256 != execution.stderr_sha256
    {
        return Err("intentional-boundary behavior terminal result changed".to_string());
    }
    let replayed = if execution.test_executed
        && !execution.timed_out
        && execution.status_code == Some(0)
    {
        count_tests(
            &execution.selector,
            &representative.stdout_bounded_sanitized,
            &representative.stderr_bounded_sanitized,
        )
        .map_err(|_| "intentional-boundary behavior test count cannot be replayed".to_string())?
    } else {
        super::TestCount::default()
    };
    if replayed.executed != execution.executed_test_count
        || replayed.matched != execution.matched_test_count
    {
        return Err("intentional-boundary behavior test count changed".to_string());
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
