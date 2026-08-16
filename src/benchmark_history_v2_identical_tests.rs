use super::{
    HISTORICAL_V2_IDENTICAL_TEST_EXECUTION_SCHEMA_VERSION,
    HISTORICAL_V2_IDENTICAL_TEST_PLAN_SCHEMA_VERSION, HistoricalV2AssessmentIdentity,
    HistoricalV2AssessmentIdentityInputs, HistoricalV2ExecutionCommandEvidence,
    HistoricalV2ExecutionError, HistoricalV2ExecutionErrorKind, HistoricalV2ExecutionPhase,
    HistoricalV2ExecutionPolicy, HistoricalV2ExecutionSide,
    HistoricalV2IdenticalTestExclusionReason, HistoricalV2IdenticalTestExecution,
    HistoricalV2IdenticalTestExecutionRequest, HistoricalV2IdenticalTestExecutor,
    HistoricalV2IdenticalTestOutcome, HistoricalV2IdenticalTestPlan, HistoricalV2Qualification,
    HistoricalV2RawIdenticalTestExecution, HistoricalV2TestRecipe, HistoricalV2TestRecipeOutcome,
    historical_v2_execution_harness, resolve_historical_v2_base_image,
    validate_historical_v2_execution_harness_repository, validate_historical_v2_materialization,
    validate_historical_v2_test_materialization, validate_historical_v2_test_recipe,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::Path;

const PLAN_CONTRACT: &str = "sniffbench-historical-v2-identical-test-plan-v1";
const EXECUTION_CONTRACT: &str = "sniffbench-historical-v2-identical-test-execution-v1";
const CPU_LIMIT_MILLIS: u64 = 4_000;
const MEMORY_LIMIT_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const PROCESS_LIMIT: u64 = 1_024;
const TEMPORARY_FILESYSTEM_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const INSTALL_COMMAND_TIMEOUT_SECONDS: u64 = 30 * 60;
const TEST_TIMEOUT_SECONDS: u64 = 60 * 60;
const RETAINED_OUTPUT_BYTES: usize = 1024 * 1024;

pub fn prepare_historical_v2_identical_test_plan(
    inputs: &HistoricalV2AssessmentIdentityInputs<'_>,
    identity: &HistoricalV2AssessmentIdentity,
    qualification: &HistoricalV2Qualification,
    recipe: &HistoricalV2TestRecipe,
    harness_repository_root: &Path,
) -> Result<HistoricalV2IdenticalTestPlan, String> {
    validate_historical_v2_test_recipe(inputs, identity, qualification, recipe)?;
    let harness = historical_v2_execution_harness()?;
    validate_historical_v2_execution_harness_repository(harness_repository_root, &harness)?;
    let HistoricalV2TestRecipeOutcome::Selected {
        base_image_name,
        install_commands,
        test_commands,
        ..
    } = &recipe.outcome
    else {
        return Err("historical-v2 identical tests require a selected test recipe".to_string());
    };
    let image = resolve_historical_v2_base_image(&harness, &identity.language, base_image_name)?;
    let (base_commit_oid, patched_commit_oid, test_materialization_sha256) =
        execution_commits(inputs, identity)?;
    let install_command_sha256 = install_commands
        .iter()
        .map(|command| sha256(command.as_bytes()))
        .collect();
    let test_script_sha256 = sha256(test_script(test_commands).as_bytes());
    seal_plan(HistoricalV2IdenticalTestPlan {
        schema_version: HISTORICAL_V2_IDENTICAL_TEST_PLAN_SCHEMA_VERSION,
        plan_contract: PLAN_CONTRACT.to_string(),
        assessment_identity_sha256: identity.assessment_identity_sha256.clone(),
        qualification_sha256: qualification.qualification_sha256.clone(),
        test_recipe_sha256: recipe.test_recipe_sha256.clone(),
        execution_harness_sha256: harness.execution_harness_sha256.clone(),
        materialization_sha256: inputs.materialization.materialization_sha256.clone(),
        test_materialization_sha256,
        language: identity.language.clone(),
        slot_number: identity.slot_number,
        canonical_repository: identity.canonical_repository.clone(),
        base_commit_oid,
        patched_commit_oid,
        base_image_name: image.base_image_name.clone(),
        dockerfile_path: image.dockerfile_path.clone(),
        dockerfile_blob_oid: image.git_blob_oid.clone(),
        install_commands: install_commands.clone(),
        install_command_sha256,
        test_commands: test_commands.clone(),
        test_script_sha256,
        policy: frozen_policy(&harness.execution_platform),
        plan_sha256: String::new(),
    })
}

pub fn validate_historical_v2_identical_test_plan(
    inputs: &HistoricalV2AssessmentIdentityInputs<'_>,
    identity: &HistoricalV2AssessmentIdentity,
    qualification: &HistoricalV2Qualification,
    recipe: &HistoricalV2TestRecipe,
    harness_repository_root: &Path,
    plan: &HistoricalV2IdenticalTestPlan,
) -> Result<(), String> {
    let expected = prepare_historical_v2_identical_test_plan(
        inputs,
        identity,
        qualification,
        recipe,
        harness_repository_root,
    )?;
    if plan != &expected {
        return Err("historical-v2 identical-test plan changed".to_string());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn execute_historical_v2_identical_tests<E: HistoricalV2IdenticalTestExecutor>(
    inputs: &HistoricalV2AssessmentIdentityInputs<'_>,
    identity: &HistoricalV2AssessmentIdentity,
    qualification: &HistoricalV2Qualification,
    recipe: &HistoricalV2TestRecipe,
    harness_repository_root: &Path,
    plan: &HistoricalV2IdenticalTestPlan,
    executor: &E,
) -> Result<HistoricalV2IdenticalTestExecution, HistoricalV2ExecutionError> {
    validate_historical_v2_identical_test_plan(
        inputs,
        identity,
        qualification,
        recipe,
        harness_repository_root,
        plan,
    )
    .map_err(HistoricalV2ExecutionError::invalid)?;
    validate_execution_sources(inputs, identity).map_err(HistoricalV2ExecutionError::invalid)?;
    let raw = executor.execute(&HistoricalV2IdenticalTestExecutionRequest {
        plan,
        harness_repository_root,
        repository_root: &inputs.materialized_roots.repository_root,
    })?;
    validate_historical_v2_identical_test_plan(
        inputs,
        identity,
        qualification,
        recipe,
        harness_repository_root,
        plan,
    )
    .map_err(HistoricalV2ExecutionError::invalid)?;
    validate_execution_sources(inputs, identity).map_err(HistoricalV2ExecutionError::invalid)?;
    validate_raw_execution(plan, &raw).map_err(HistoricalV2ExecutionError::invalid)?;
    seal_execution(plan, raw).map_err(HistoricalV2ExecutionError::invalid)
}

pub(crate) fn test_script(commands: &[String]) -> String {
    let mut script = String::from("set -euo pipefail\n");
    for command in commands {
        script.push_str(command);
        script.push('\n');
    }
    script
}

fn execution_commits(
    inputs: &HistoricalV2AssessmentIdentityInputs<'_>,
    identity: &HistoricalV2AssessmentIdentity,
) -> Result<(String, String, Option<String>), String> {
    match inputs.test_materialization {
        Some(binding) => {
            let expected_patch = identity.test_patch_sha256.as_deref().ok_or_else(|| {
                "historical-v2 tested snapshots have no committed test patch".to_string()
            })?;
            validate_historical_v2_test_materialization(
                inputs.materialization,
                inputs.materialized_roots,
                expected_patch,
                binding.artifact,
                binding.roots,
            )?;
            Ok((
                binding.artifact.base_test_commit_oid.clone(),
                binding.artifact.patched_test_commit_oid.clone(),
                Some(binding.artifact.test_materialization_sha256.clone()),
            ))
        }
        None => {
            if identity.test_patch_sha256.is_some()
                || identity.test_materialization_sha256.is_some()
            {
                return Err(
                    "historical-v2 committed test patch is missing its materialization".to_string(),
                );
            }
            validate_historical_v2_materialization(
                inputs.materialization,
                inputs.materialized_roots,
            )?;
            Ok((
                inputs.materialization.base_revision.clone(),
                inputs.materialization.patched_commit_oid.clone(),
                None,
            ))
        }
    }
}

fn validate_execution_sources(
    inputs: &HistoricalV2AssessmentIdentityInputs<'_>,
    identity: &HistoricalV2AssessmentIdentity,
) -> Result<(), String> {
    execution_commits(inputs, identity).map(|_| ())
}

fn frozen_policy(platform: &str) -> HistoricalV2ExecutionPolicy {
    HistoricalV2ExecutionPolicy {
        platform: platform.to_string(),
        cpu_limit_millis: CPU_LIMIT_MILLIS,
        memory_limit_bytes: MEMORY_LIMIT_BYTES,
        process_limit: PROCESS_LIMIT,
        temporary_filesystem_bytes: TEMPORARY_FILESYSTEM_BYTES,
        install_command_timeout_seconds: INSTALL_COMMAND_TIMEOUT_SECONDS,
        test_timeout_seconds: TEST_TIMEOUT_SECONDS,
        retained_output_bytes: RETAINED_OUTPUT_BYTES,
        install_network_enabled: true,
        test_network_enabled: false,
        ephemeral_root_filesystem: true,
        host_source_mounts_forbidden: true,
        all_capabilities_dropped: true,
        no_new_privileges: true,
    }
}

fn validate_raw_execution(
    plan: &HistoricalV2IdenticalTestPlan,
    raw: &HistoricalV2RawIdenticalTestExecution,
) -> Result<(), String> {
    if !valid_image_id(&raw.image_id) {
        return Err("historical-v2 execution image identity is invalid".to_string());
    }
    let expected = expected_commands(plan);
    if raw.events.is_empty() || raw.events.len() > expected.len() {
        return Err("historical-v2 execution event count is invalid".to_string());
    }
    for (event, expected) in raw.events.iter().zip(&expected) {
        validate_event(plan, event, expected)?;
    }
    let failed = raw
        .events
        .iter()
        .position(|event| event.timed_out || event.exit_code != Some(0));
    if failed.is_some_and(|index| index + 1 != raw.events.len()) {
        return Err("historical-v2 execution continued after a terminal command".to_string());
    }
    match (&raw.outcome, failed) {
        (HistoricalV2IdenticalTestOutcome::Passed, None) if raw.events.len() == expected.len() => {
            Ok(())
        }
        (HistoricalV2IdenticalTestOutcome::Excluded { reason }, Some(index)) => {
            validate_exclusion(reason, &raw.events[index])
        }
        _ => Err("historical-v2 execution outcome disagrees with its events".to_string()),
    }
}

struct ExpectedCommand {
    side: HistoricalV2ExecutionSide,
    phase: HistoricalV2ExecutionPhase,
    command_index: usize,
    command_sha256: String,
}

fn expected_commands(plan: &HistoricalV2IdenticalTestPlan) -> Vec<ExpectedCommand> {
    let mut expected = Vec::new();
    for side in [
        HistoricalV2ExecutionSide::Base,
        HistoricalV2ExecutionSide::Patched,
    ] {
        expected.extend(plan.install_command_sha256.iter().enumerate().map(
            |(command_index, command_sha256)| ExpectedCommand {
                side,
                phase: HistoricalV2ExecutionPhase::Install,
                command_index,
                command_sha256: command_sha256.clone(),
            },
        ));
        expected.push(ExpectedCommand {
            side,
            phase: HistoricalV2ExecutionPhase::Test,
            command_index: 0,
            command_sha256: plan.test_script_sha256.clone(),
        });
    }
    expected
}

fn validate_event(
    plan: &HistoricalV2IdenticalTestPlan,
    event: &HistoricalV2ExecutionCommandEvidence,
    expected: &ExpectedCommand,
) -> Result<(), String> {
    if event.side != expected.side
        || event.phase != expected.phase
        || event.command_index != expected.command_index
        || event.command_sha256 != expected.command_sha256
        || !valid_sha256(&event.stdout_sha256)
        || !valid_sha256(&event.stderr_sha256)
        || event.retained_stdout.len() > plan.policy.retained_output_bytes.saturating_mul(3)
        || event.retained_stderr.len() > plan.policy.retained_output_bytes.saturating_mul(3)
        || (event.timed_out && event.exit_code == Some(0))
    {
        return Err("historical-v2 execution command evidence is invalid".to_string());
    }
    Ok(())
}

fn validate_exclusion(
    reason: &HistoricalV2IdenticalTestExclusionReason,
    event: &HistoricalV2ExecutionCommandEvidence,
) -> Result<(), String> {
    let expected = match (event.phase, event.timed_out) {
        (HistoricalV2ExecutionPhase::Install, true) => {
            HistoricalV2IdenticalTestExclusionReason::InstallCommandTimedOut {
                side: event.side,
                command_index: event.command_index,
            }
        }
        (HistoricalV2ExecutionPhase::Install, false) => {
            HistoricalV2IdenticalTestExclusionReason::InstallCommandFailed {
                side: event.side,
                command_index: event.command_index,
            }
        }
        (HistoricalV2ExecutionPhase::Test, true) => {
            HistoricalV2IdenticalTestExclusionReason::TestCommandsTimedOut { side: event.side }
        }
        (HistoricalV2ExecutionPhase::Test, false) => {
            HistoricalV2IdenticalTestExclusionReason::TestCommandsFailed { side: event.side }
        }
    };
    if reason == &expected {
        Ok(())
    } else {
        Err("historical-v2 exclusion reason disagrees with its command".to_string())
    }
}

fn seal_plan(
    mut plan: HistoricalV2IdenticalTestPlan,
) -> Result<HistoricalV2IdenticalTestPlan, String> {
    plan.plan_sha256 = committed_sha256(&plan, |value| &mut value.plan_sha256)?;
    Ok(plan)
}

fn seal_execution(
    plan: &HistoricalV2IdenticalTestPlan,
    raw: HistoricalV2RawIdenticalTestExecution,
) -> Result<HistoricalV2IdenticalTestExecution, String> {
    let mut execution = HistoricalV2IdenticalTestExecution {
        schema_version: HISTORICAL_V2_IDENTICAL_TEST_EXECUTION_SCHEMA_VERSION,
        execution_contract: EXECUTION_CONTRACT.to_string(),
        plan_sha256: plan.plan_sha256.clone(),
        image_id: raw.image_id,
        events: raw.events,
        outcome: raw.outcome,
        execution_sha256: String::new(),
    };
    execution.execution_sha256 = committed_sha256(&execution, |value| &mut value.execution_sha256)?;
    Ok(execution)
}

fn committed_sha256<T: Clone + Serialize>(
    value: &T,
    clear: impl FnOnce(&mut T) -> &mut String,
) -> Result<String, String> {
    let mut committed = value.clone();
    clear(&mut committed).clear();
    serde_json::to_vec(&committed)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to commit historical-v2 execution artifact: {error}"))
}

fn valid_image_id(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(valid_sha256)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

impl HistoricalV2ExecutionError {
    pub fn invalid(detail: impl Into<String>) -> Self {
        Self {
            kind: HistoricalV2ExecutionErrorKind::InvalidInput,
            detail: detail.into(),
        }
    }

    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self {
            kind: HistoricalV2ExecutionErrorKind::InfrastructureUnavailable,
            detail: detail.into(),
        }
    }

    pub fn infrastructure(detail: impl Into<String>) -> Self {
        Self {
            kind: HistoricalV2ExecutionErrorKind::InfrastructureFailed,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for HistoricalV2ExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.detail)
    }
}

impl std::error::Error for HistoricalV2ExecutionError {}

#[cfg(test)]
#[path = "benchmark_history_v2_identical_tests_tests.rs"]
mod tests;
