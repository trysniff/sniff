use super::super::{
    HISTORICAL_V3_TEST_RECIPE_EXCLUSION_SCHEMA_VERSION, HISTORICAL_V3_TEST_RECIPE_SCHEMA_VERSION,
    HistoricalV3CandidateCollection, HistoricalV3Materialization,
    HistoricalV3MechanicalQualification, HistoricalV3Protocol, HistoricalV3SemanticCensus,
    HistoricalV3SourceCensus, HistoricalV3TestRecipe, HistoricalV3TestRecipeExclusion,
    HistoricalV3TestRecipeOutcome, historical_v3_rank_identity,
    validate_historical_v3_materialization_commitment,
    validate_historical_v3_mechanical_qualification,
    validate_historical_v3_semantic_census_commitment,
    validate_historical_v3_source_census_commitment,
};
use super::selector::select_recipe;
use super::{TEST_RECIPE_CONTRACT, TEST_RECIPE_EXCLUSION_CONTRACT};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub fn derive_historical_v3_test_recipe(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    materialization: &HistoricalV3Materialization,
    source_census: &HistoricalV3SourceCensus,
    semantic_census: &HistoricalV3SemanticCensus,
    qualification: &HistoricalV3MechanicalQualification,
) -> Result<HistoricalV3TestRecipeOutcome, String> {
    validate_inputs(
        protocol,
        collection,
        materialization,
        source_census,
        semantic_census,
        qualification,
    )?;
    let rank = historical_v3_rank_identity(protocol, collection, qualification.rank.stream_rank)?;
    let recipe_inputs_sha256 = json_sha256(&(
        "sniffbench-historical-v3-recipe-inputs-v1",
        &source_census.base.recipe_input_facts,
        &source_census.merge.recipe_input_facts,
    ))?;
    let plan = match select_recipe(rank.language(), &source_census.base, &source_census.merge) {
        Ok(plan) => plan,
        Err(reason) => {
            return seal_exclusion(HistoricalV3TestRecipeExclusion {
                schema_version: HISTORICAL_V3_TEST_RECIPE_EXCLUSION_SCHEMA_VERSION,
                exclusion_contract: TEST_RECIPE_EXCLUSION_CONTRACT.to_string(),
                rank,
                materialization_sha256: materialization.materialization_sha256.clone(),
                source_census_sha256: source_census.source_census_sha256.clone(),
                semantic_census_sha256: semantic_census.semantic_census_sha256.clone(),
                qualification_sha256: qualification.qualification_sha256.clone(),
                recipe_inputs_sha256,
                reason,
                exclusion_sha256: String::new(),
            })
            .map(Box::new)
            .map(HistoricalV3TestRecipeOutcome::Excluded);
        }
    };
    let environment = protocol
        .test_recipe_policy
        .environments
        .iter()
        .find(|environment| environment.language == rank.language())
        .ok_or_else(|| "historical-v3 test environment is missing".to_string())?;
    let changed_methods_sha256 = json_sha256(&(
        "sniffbench-historical-v3-test-recipe-changed-methods-v1",
        &qualification.evidence.changed_methods,
    ))?;
    let command_identity_sha256 = json_sha256(&(
        "sniffbench-historical-v3-test-command-identity-v1",
        plan.selector,
        &plan.preparation_commands,
        &plan.test_command,
        &plan.runtime_program,
        &plan.inputs,
    ))?;
    let toolchain_identity_sha256 = json_sha256(&(
        "sniffbench-historical-v3-test-toolchain-identity-v1",
        rank.language(),
        &protocol.test_recipe_policy.execution_platform,
        &environment.image_digest,
        &environment.toolchain_manifest_sha256,
        &environment.dependency_store_sha256,
        &plan.runtime_program,
    ))?;
    seal_recipe(HistoricalV3TestRecipe {
        schema_version: HISTORICAL_V3_TEST_RECIPE_SCHEMA_VERSION,
        recipe_contract: TEST_RECIPE_CONTRACT.to_string(),
        rank,
        materialization_sha256: materialization.materialization_sha256.clone(),
        source_census_sha256: source_census.source_census_sha256.clone(),
        semantic_census_sha256: semantic_census.semantic_census_sha256.clone(),
        qualification_sha256: qualification.qualification_sha256.clone(),
        selector: plan.selector,
        execution_platform: protocol.test_recipe_policy.execution_platform.clone(),
        image_digest: environment.image_digest.clone(),
        toolchain_manifest_sha256: environment.toolchain_manifest_sha256.clone(),
        dependency_store_sha256: environment.dependency_store_sha256.clone(),
        preparation_commands: plan.preparation_commands,
        test_command: plan.test_command,
        runtime_program: plan.runtime_program,
        inputs: plan.inputs,
        changed_method_count: qualification.evidence.changed_methods.len(),
        changed_methods_sha256,
        command_identity_sha256,
        toolchain_identity_sha256,
        recipe_sha256: String::new(),
    })
    .map(Box::new)
    .map(HistoricalV3TestRecipeOutcome::Selected)
}

pub fn validate_historical_v3_test_recipe(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    materialization: &HistoricalV3Materialization,
    source_census: &HistoricalV3SourceCensus,
    semantic_census: &HistoricalV3SemanticCensus,
    qualification: &HistoricalV3MechanicalQualification,
    artifact: &HistoricalV3TestRecipe,
) -> Result<(), String> {
    let HistoricalV3TestRecipeOutcome::Selected(expected) = derive_historical_v3_test_recipe(
        protocol,
        collection,
        materialization,
        source_census,
        semantic_census,
        qualification,
    )?
    else {
        return Err("historical-v3 test recipe is not mechanically selectable".to_string());
    };
    if artifact != expected.as_ref() {
        return Err("historical-v3 test recipe changed its committed derivation".to_string());
    }
    Ok(())
}

pub fn validate_historical_v3_test_recipe_exclusion(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    materialization: &HistoricalV3Materialization,
    source_census: &HistoricalV3SourceCensus,
    semantic_census: &HistoricalV3SemanticCensus,
    qualification: &HistoricalV3MechanicalQualification,
    artifact: &HistoricalV3TestRecipeExclusion,
) -> Result<(), String> {
    let HistoricalV3TestRecipeOutcome::Excluded(expected) = derive_historical_v3_test_recipe(
        protocol,
        collection,
        materialization,
        source_census,
        semantic_census,
        qualification,
    )?
    else {
        return Err("historical-v3 test recipe exclusion is not reproducible".to_string());
    };
    if artifact != expected.as_ref() {
        return Err("historical-v3 test recipe exclusion changed its derivation".to_string());
    }
    Ok(())
}

fn validate_inputs(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    materialization: &HistoricalV3Materialization,
    source_census: &HistoricalV3SourceCensus,
    semantic_census: &HistoricalV3SemanticCensus,
    qualification: &HistoricalV3MechanicalQualification,
) -> Result<(), String> {
    validate_historical_v3_materialization_commitment(protocol, collection, materialization)
        .map_err(|error| error.detail)?;
    validate_historical_v3_source_census_commitment(
        protocol,
        collection,
        materialization,
        source_census,
    )?;
    validate_historical_v3_semantic_census_commitment(
        protocol,
        collection,
        materialization,
        source_census,
        semantic_census,
    )?;
    validate_historical_v3_mechanical_qualification(
        protocol,
        collection,
        materialization,
        source_census,
        semantic_census,
        qualification,
    )
}

pub(super) fn seal_recipe(
    mut artifact: HistoricalV3TestRecipe,
) -> Result<HistoricalV3TestRecipe, String> {
    artifact.recipe_sha256.clear();
    artifact.recipe_sha256 = recipe_sha256(&artifact)?;
    Ok(artifact)
}

fn seal_exclusion(
    mut artifact: HistoricalV3TestRecipeExclusion,
) -> Result<HistoricalV3TestRecipeExclusion, String> {
    artifact.exclusion_sha256.clear();
    artifact.exclusion_sha256 = exclusion_sha256(&artifact)?;
    Ok(artifact)
}

fn recipe_sha256(artifact: &HistoricalV3TestRecipe) -> Result<String, String> {
    let mut committed = artifact.clone();
    committed.recipe_sha256.clear();
    json_sha256(&committed)
}

fn exclusion_sha256(artifact: &HistoricalV3TestRecipeExclusion) -> Result<String, String> {
    let mut committed = artifact.clone();
    committed.exclusion_sha256.clear();
    json_sha256(&committed)
}

fn json_sha256(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v3 test recipe: {error}"))
}
