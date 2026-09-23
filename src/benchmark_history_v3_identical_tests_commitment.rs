use super::super::{
    HISTORICAL_V3_IDENTICAL_TESTS_SCHEMA_VERSION, HistoricalV3ExecutionCommandEvidence,
    HistoricalV3ExecutionPhase, HistoricalV3ExecutionSide,
    HistoricalV3IdenticalTestExclusionReason, HistoricalV3IdenticalTestOutcome,
    HistoricalV3IdenticalTestPolicy, HistoricalV3IdenticalTests, HistoricalV3Protocol,
    HistoricalV3RawIdenticalTestExecution, HistoricalV3RecipeCommand, HistoricalV3TestRecipe,
    validate_historical_v3_protocol,
};
use super::IDENTICAL_TESTS_CONTRACT;
use base64::Engine;
use serde::Serialize;
use sha2::{Digest, Sha256};

pub fn historical_v3_execution_identity_sha256(
    protocol: &HistoricalV3Protocol,
    recipe: &HistoricalV3TestRecipe,
) -> Result<String, String> {
    validate_historical_v3_protocol(protocol)?;
    json_sha256(&(
        "sniffbench-historical-v3-identical-test-identity-v1",
        &recipe.recipe_sha256,
        &protocol.identical_test_policy,
    ))
}

pub(super) fn seal_execution(
    protocol: &HistoricalV3Protocol,
    recipe: &HistoricalV3TestRecipe,
    raw: HistoricalV3RawIdenticalTestExecution,
) -> Result<HistoricalV3IdenticalTests, String> {
    validate_raw_execution(protocol, recipe, &raw)?;
    let mut artifact = HistoricalV3IdenticalTests {
        schema_version: HISTORICAL_V3_IDENTICAL_TESTS_SCHEMA_VERSION,
        execution_contract: IDENTICAL_TESTS_CONTRACT.to_string(),
        rank: recipe.rank.clone(),
        materialization_sha256: recipe.materialization_sha256.clone(),
        test_recipe_sha256: recipe.recipe_sha256.clone(),
        execution_policy_sha256: json_sha256(&protocol.identical_test_policy)?,
        execution_identity_sha256: historical_v3_execution_identity_sha256(protocol, recipe)?,
        image_digest: raw.image_digest,
        toolchain_manifest_sha256: raw.toolchain_manifest_sha256,
        dependency_store_sha256: raw.dependency_store_sha256,
        events: raw.events,
        outcome: raw.outcome,
        execution_sha256: String::new(),
    };
    artifact.execution_sha256 = execution_sha256(&artifact)?;
    Ok(artifact)
}

pub fn validate_historical_v3_identical_tests(
    protocol: &HistoricalV3Protocol,
    recipe: &HistoricalV3TestRecipe,
    artifact: &HistoricalV3IdenticalTests,
) -> Result<(), String> {
    validate_historical_v3_protocol(protocol)?;
    if artifact.schema_version != HISTORICAL_V3_IDENTICAL_TESTS_SCHEMA_VERSION
        || artifact.execution_contract != IDENTICAL_TESTS_CONTRACT
        || artifact.rank != recipe.rank
        || artifact.materialization_sha256 != recipe.materialization_sha256
        || artifact.test_recipe_sha256 != recipe.recipe_sha256
        || artifact.execution_policy_sha256 != json_sha256(&protocol.identical_test_policy)?
        || artifact.execution_identity_sha256
            != historical_v3_execution_identity_sha256(protocol, recipe)?
        || artifact.execution_sha256 != execution_sha256(artifact)?
    {
        return Err("historical-v3 identical-test commitment changed".to_string());
    }
    validate_raw_execution(
        protocol,
        recipe,
        &HistoricalV3RawIdenticalTestExecution {
            image_digest: artifact.image_digest.clone(),
            toolchain_manifest_sha256: artifact.toolchain_manifest_sha256.clone(),
            dependency_store_sha256: artifact.dependency_store_sha256.clone(),
            events: artifact.events.clone(),
            outcome: artifact.outcome.clone(),
        },
    )
}

fn validate_raw_execution(
    protocol: &HistoricalV3Protocol,
    recipe: &HistoricalV3TestRecipe,
    raw: &HistoricalV3RawIdenticalTestExecution,
) -> Result<(), String> {
    if raw.image_digest != recipe.image_digest
        || raw.toolchain_manifest_sha256 != recipe.toolchain_manifest_sha256
        || raw.dependency_store_sha256 != recipe.dependency_store_sha256
    {
        return Err("historical-v3 execution environment identity changed".to_string());
    }
    let expected = expected_commands(recipe)?;
    if raw.events.is_empty() || raw.events.len() > expected.len() {
        return Err("historical-v3 execution event count is invalid".to_string());
    }
    for (event, expected) in raw.events.iter().zip(&expected) {
        validate_event(&protocol.identical_test_policy, event, expected)?;
    }
    let failed = raw
        .events
        .iter()
        .position(|event| event.timed_out || event.exit_code != Some(0));
    if failed.is_some_and(|index| index + 1 != raw.events.len()) {
        return Err("historical-v3 execution continued after a terminal command".to_string());
    }
    match (&raw.outcome, failed) {
        (HistoricalV3IdenticalTestOutcome::Passed, None) if raw.events.len() == expected.len() => {
            Ok(())
        }
        (HistoricalV3IdenticalTestOutcome::Excluded { reason }, Some(index)) => {
            validate_exclusion(reason, &raw.events[index])
        }
        _ => Err("historical-v3 execution outcome disagrees with its events".to_string()),
    }
}

struct ExpectedCommand {
    side: HistoricalV3ExecutionSide,
    phase: HistoricalV3ExecutionPhase,
    command_index: usize,
    command_sha256: String,
}

fn expected_commands(recipe: &HistoricalV3TestRecipe) -> Result<Vec<ExpectedCommand>, String> {
    let mut expected = Vec::new();
    for side in [
        HistoricalV3ExecutionSide::Base,
        HistoricalV3ExecutionSide::Merge,
    ] {
        for (command_index, command) in recipe.preparation_commands.iter().enumerate() {
            expected.push(ExpectedCommand {
                side,
                phase: HistoricalV3ExecutionPhase::Preparation,
                command_index,
                command_sha256: command_sha256(command)?,
            });
        }
        expected.push(ExpectedCommand {
            side,
            phase: HistoricalV3ExecutionPhase::Test,
            command_index: 0,
            command_sha256: command_sha256(&recipe.test_command)?,
        });
    }
    Ok(expected)
}

pub(super) fn command_sha256(command: &HistoricalV3RecipeCommand) -> Result<String, String> {
    json_sha256(&("sniffbench-historical-v3-command-v1", command))
}

fn validate_event(
    policy: &HistoricalV3IdenticalTestPolicy,
    event: &HistoricalV3ExecutionCommandEvidence,
    expected: &ExpectedCommand,
) -> Result<(), String> {
    if event.side != expected.side
        || event.phase != expected.phase
        || event.command_index != expected.command_index
        || event.command_sha256 != expected.command_sha256
        || !is_lower_sha256(&event.stdout_sha256)
        || !is_lower_sha256(&event.stderr_sha256)
        || (event.timed_out && event.exit_code == Some(0))
    {
        return Err("historical-v3 execution command evidence is invalid".to_string());
    }
    validate_output(
        policy.retained_output_bytes,
        &event.retained_stdout_base64,
        event.stdout_byte_count,
        event.stdout_truncated,
        &event.stdout_sha256,
    )?;
    validate_output(
        policy.retained_output_bytes,
        &event.retained_stderr_base64,
        event.stderr_byte_count,
        event.stderr_truncated,
        &event.stderr_sha256,
    )
}

fn validate_output(
    limit: usize,
    encoded: &str,
    byte_count: u64,
    truncated: bool,
    sha256: &str,
) -> Result<(), String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "historical-v3 retained command output is not base64".to_string())?;
    let retained_count = u64::try_from(bytes.len())
        .map_err(|_| "historical-v3 retained command output length overflowed".to_string())?;
    if bytes.len() > limit
        || byte_count < retained_count
        || truncated != (byte_count > retained_count)
        || (!truncated && format!("{:x}", Sha256::digest(&bytes)) != sha256)
        || base64::engine::general_purpose::STANDARD.encode(&bytes) != encoded
    {
        return Err("historical-v3 retained command output is inconsistent".to_string());
    }
    Ok(())
}

fn validate_exclusion(
    reason: &HistoricalV3IdenticalTestExclusionReason,
    event: &HistoricalV3ExecutionCommandEvidence,
) -> Result<(), String> {
    let expected = match (event.phase, event.timed_out) {
        (HistoricalV3ExecutionPhase::Preparation, true) => {
            HistoricalV3IdenticalTestExclusionReason::PreparationTimedOut {
                side: event.side,
                command_index: event.command_index,
            }
        }
        (HistoricalV3ExecutionPhase::Preparation, false) => {
            HistoricalV3IdenticalTestExclusionReason::PreparationFailed {
                side: event.side,
                command_index: event.command_index,
            }
        }
        (HistoricalV3ExecutionPhase::Test, true) => {
            HistoricalV3IdenticalTestExclusionReason::TestTimedOut { side: event.side }
        }
        (HistoricalV3ExecutionPhase::Test, false) => {
            HistoricalV3IdenticalTestExclusionReason::TestFailed { side: event.side }
        }
    };
    if reason == &expected {
        Ok(())
    } else {
        Err("historical-v3 exclusion reason disagrees with its command".to_string())
    }
}

pub(super) fn execution_sha256(artifact: &HistoricalV3IdenticalTests) -> Result<String, String> {
    let mut committed = artifact.clone();
    committed.execution_sha256.clear();
    json_sha256(&committed)
}

fn json_sha256(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v3 execution: {error}"))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
