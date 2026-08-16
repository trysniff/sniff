use super::{
    HISTORICAL_V2_TEST_RECIPE_SCHEMA_VERSION, HistoricalV2AssessmentIdentity,
    HistoricalV2AssessmentIdentityInputs, HistoricalV2Qualification,
    HistoricalV2QualificationOutcome, HistoricalV2SelectedPayload, HistoricalV2TestRecipe,
    HistoricalV2TestRecipeExclusionReason, HistoricalV2TestRecipeOutcome,
    validate_historical_v2_qualification_commitment,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const TEST_RECIPE_CONTRACT: &str = "sniffbench-historical-v2-test-recipe-v1";
const MAX_INSTALL_COMMANDS: usize = 64;
const MAX_COMMAND_BYTES: usize = 64 * 1024;
const MAX_NAME_BYTES: usize = 256;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInstallConfig {
    base_image_name: String,
    install: Vec<String>,
    log_parser: String,
    test_cmd: String,
}

pub fn prepare_historical_v2_test_recipe(
    inputs: &HistoricalV2AssessmentIdentityInputs<'_>,
    identity: &HistoricalV2AssessmentIdentity,
    qualification: &HistoricalV2Qualification,
) -> Result<HistoricalV2TestRecipe, String> {
    validate_historical_v2_qualification_commitment(inputs, identity, qualification)?;
    let payload = selected_payload(inputs, identity)?;
    prepare_validated_test_recipe(payload, identity, qualification)
}

fn prepare_validated_test_recipe(
    payload: &HistoricalV2SelectedPayload,
    identity: &HistoricalV2AssessmentIdentity,
    qualification: &HistoricalV2Qualification,
) -> Result<HistoricalV2TestRecipe, String> {
    validate_lineage(payload, identity, qualification)?;
    let outcome = recipe_outcome(payload.install_config.as_deref());
    seal_recipe(HistoricalV2TestRecipe {
        schema_version: HISTORICAL_V2_TEST_RECIPE_SCHEMA_VERSION,
        test_recipe_contract: TEST_RECIPE_CONTRACT.to_string(),
        assessment_identity_sha256: identity.assessment_identity_sha256.clone(),
        qualification_sha256: qualification.qualification_sha256.clone(),
        install_config_sha256: payload.install_config_sha256.clone(),
        outcome,
        test_recipe_sha256: String::new(),
    })
}

pub fn validate_historical_v2_test_recipe(
    inputs: &HistoricalV2AssessmentIdentityInputs<'_>,
    identity: &HistoricalV2AssessmentIdentity,
    qualification: &HistoricalV2Qualification,
    recipe: &HistoricalV2TestRecipe,
) -> Result<(), String> {
    let expected = prepare_historical_v2_test_recipe(inputs, identity, qualification)?;
    if recipe != &expected {
        return Err("historical-v2 test recipe changed".to_string());
    }
    Ok(())
}

fn selected_payload<'a>(
    inputs: &'a HistoricalV2AssessmentIdentityInputs<'_>,
    identity: &HistoricalV2AssessmentIdentity,
) -> Result<&'a HistoricalV2SelectedPayload, String> {
    inputs
        .payloads
        .records
        .iter()
        .find(|payload| {
            payload.language == identity.language && payload.slot_number == identity.slot_number
        })
        .ok_or_else(|| "historical-v2 test recipe payload is absent".to_string())
}

fn validate_lineage(
    payload: &HistoricalV2SelectedPayload,
    identity: &HistoricalV2AssessmentIdentity,
    qualification: &HistoricalV2Qualification,
) -> Result<(), String> {
    if payload.language != identity.language
        || payload.slot_number != identity.slot_number
        || payload.global_row_index != identity.global_row_index
        || payload.instance_id != identity.instance_id
        || payload.payload_sha256 != identity.payload_sha256
        || payload.patch_sha256 != identity.historical_patch_sha256
        || payload.install_config_sha256 != identity.install_config_sha256
        || qualification.assessment_identity_sha256 != identity.assessment_identity_sha256
        || qualification.language != identity.language
        || qualification.slot_number != identity.slot_number
    {
        return Err("historical-v2 test recipe inputs cross slot boundaries".to_string());
    }
    if !matches!(
        qualification.outcome,
        HistoricalV2QualificationOutcome::Qualified
    ) {
        return Err("historical-v2 test recipe requires a qualified source reduction".to_string());
    }
    require_sha256(&identity.assessment_identity_sha256, "assessment identity")?;
    require_sha256(&qualification.qualification_sha256, "qualification")?;
    match (
        payload.install_config.as_deref(),
        payload.install_config_sha256.as_deref(),
    ) {
        (Some(config), Some(expected)) if sha256(config.as_bytes()) == expected => Ok(()),
        (None, None) => Ok(()),
        _ => Err("historical-v2 install config changed from its committed payload".to_string()),
    }
}

fn recipe_outcome(config: Option<&str>) -> HistoricalV2TestRecipeOutcome {
    let Some(config) = config else {
        return excluded(HistoricalV2TestRecipeExclusionReason::MissingInstallConfig);
    };
    let Ok(config) = serde_json::from_str::<RawInstallConfig>(config) else {
        return excluded(HistoricalV2TestRecipeExclusionReason::InvalidInstallConfigJson);
    };
    if !valid_name(&config.base_image_name) {
        return excluded(HistoricalV2TestRecipeExclusionReason::InvalidBaseImageName);
    }
    if config.install.len() > MAX_INSTALL_COMMANDS {
        return excluded(HistoricalV2TestRecipeExclusionReason::TooManyInstallCommands);
    }
    if config.install.iter().any(|command| !valid_command(command)) {
        return excluded(HistoricalV2TestRecipeExclusionReason::InvalidInstallCommand);
    }
    if !valid_command(&config.test_cmd) {
        return excluded(HistoricalV2TestRecipeExclusionReason::InvalidTestCommand);
    }
    if !valid_name(&config.log_parser) {
        return excluded(HistoricalV2TestRecipeExclusionReason::InvalidLogParser);
    }
    HistoricalV2TestRecipeOutcome::Selected {
        base_image_name: config.base_image_name,
        install_commands: config.install,
        test_command: config.test_cmd,
        log_parser: config.log_parser,
    }
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NAME_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/' | b':')
        })
}

fn valid_command(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_COMMAND_BYTES && !value.contains('\0')
}

fn excluded(reason: HistoricalV2TestRecipeExclusionReason) -> HistoricalV2TestRecipeOutcome {
    HistoricalV2TestRecipeOutcome::Excluded { reason }
}

fn seal_recipe(mut recipe: HistoricalV2TestRecipe) -> Result<HistoricalV2TestRecipe, String> {
    if !recipe.test_recipe_sha256.is_empty() {
        return Err("historical-v2 test recipe is already sealed".to_string());
    }
    recipe.test_recipe_sha256 = recipe_sha256(&recipe)?;
    Ok(recipe)
}

fn recipe_sha256(recipe: &HistoricalV2TestRecipe) -> Result<String, String> {
    let mut committed = recipe.clone();
    committed.test_recipe_sha256.clear();
    serde_json::to_vec(&committed)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to commit historical-v2 test recipe: {error}"))
}

fn require_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!("historical-v2 {label} commitment is invalid"))
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "benchmark_history_v2_test_recipe_tests.rs"]
mod tests;
