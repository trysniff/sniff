use super::intentional_boundary_behavior::census_intentional_boundary_behavior_tests_typed;
use super::intentional_boundary_behavior_outcome::{
    BehaviorDerivationError, BehaviorDerivationErrorKind,
};
use super::intentional_boundary_generator_stage::generator_stage_sha256;
use super::{
    INTENTIONAL_BOUNDARY_BEHAVIOR_STAGE_SCHEMA_VERSION, IntentionalBoundaryAstCensusStage,
    IntentionalBoundaryBehaviorCensus, IntentionalBoundaryBehaviorStage,
    IntentionalBoundaryBehaviorStageError, IntentionalBoundaryBehaviorStageErrorKind,
    IntentionalBoundaryEvidenceStage, IntentionalBoundaryFrameTask,
    IntentionalBoundaryGeneratorStage, IntentionalBoundaryLicenseCensusStage,
    IntentionalBoundaryManifestStage, IntentionalBoundaryMaterialization,
    IntentionalBoundaryProjectModelStage, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticCensusStage, IntentionalBoundarySourceCensusStage,
    compose_intentional_boundary_behavior_evidence,
    validate_intentional_boundary_behavior_census_commitment,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

const STAGE_CONTRACT: &str = "sniffbench-intentional-boundary-behavior-stage-v1";

#[allow(clippy::too_many_arguments)]
pub fn census_intentional_boundary_behavior_stage(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    semantic_census: &IntentionalBoundarySemanticCensusStage,
    ast_census: &IntentionalBoundaryAstCensusStage,
    manifest_stage: &IntentionalBoundaryManifestStage,
    base_evidence_stage: &IntentionalBoundaryEvidenceStage,
    project_model_stage: &IntentionalBoundaryProjectModelStage,
    generator_stage: &IntentionalBoundaryGeneratorStage,
) -> Result<IntentionalBoundaryBehaviorStage, IntentionalBoundaryBehaviorStageError> {
    validate_upstream_lineage(
        task,
        materialization,
        inventory,
        source_census,
        license_census,
        semantic_census,
        ast_census,
        manifest_stage,
        base_evidence_stage,
        project_model_stage,
        generator_stage,
    )?;
    let behavior_census = census_intentional_boundary_behavior_tests_typed(
        &materialization.repository,
        &materialization.revision,
        root,
        inventory,
        &source_census.source_census,
        &semantic_census.semantic_census,
        &generator_stage.evidence_census,
    )
    .map_err(map_derivation_error)?;
    finish_behavior_stage(
        task,
        materialization,
        inventory,
        source_census,
        license_census,
        semantic_census,
        ast_census,
        manifest_stage,
        base_evidence_stage,
        project_model_stage,
        generator_stage,
        behavior_census,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn validate_intentional_boundary_behavior_stage(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    semantic_census: &IntentionalBoundarySemanticCensusStage,
    ast_census: &IntentionalBoundaryAstCensusStage,
    manifest_stage: &IntentionalBoundaryManifestStage,
    base_evidence_stage: &IntentionalBoundaryEvidenceStage,
    project_model_stage: &IntentionalBoundaryProjectModelStage,
    generator_stage: &IntentionalBoundaryGeneratorStage,
    stage: &IntentionalBoundaryBehaviorStage,
) -> Result<(), IntentionalBoundaryBehaviorStageError> {
    let expected = census_intentional_boundary_behavior_stage(
        task,
        materialization,
        root,
        inventory,
        source_census,
        license_census,
        semantic_census,
        ast_census,
        manifest_stage,
        base_evidence_stage,
        project_model_stage,
        generator_stage,
    )?;
    if stage != &expected {
        return Err(invalid("intentional-boundary behavior stage changed"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn finish_behavior_stage(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    semantic_census: &IntentionalBoundarySemanticCensusStage,
    ast_census: &IntentionalBoundaryAstCensusStage,
    manifest_stage: &IntentionalBoundaryManifestStage,
    base_evidence_stage: &IntentionalBoundaryEvidenceStage,
    project_model_stage: &IntentionalBoundaryProjectModelStage,
    generator_stage: &IntentionalBoundaryGeneratorStage,
    behavior_census: IntentionalBoundaryBehaviorCensus,
) -> Result<IntentionalBoundaryBehaviorStage, IntentionalBoundaryBehaviorStageError> {
    validate_upstream_lineage(
        task,
        materialization,
        inventory,
        source_census,
        license_census,
        semantic_census,
        ast_census,
        manifest_stage,
        base_evidence_stage,
        project_model_stage,
        generator_stage,
    )?;
    validate_intentional_boundary_behavior_census_commitment(
        &source_census.source_census,
        &semantic_census.semantic_census,
        &generator_stage.evidence_census,
        &behavior_census,
    )
    .map_err(invalid)?;
    let evidence_census = compose_intentional_boundary_behavior_evidence(
        &source_census.source_census,
        &semantic_census.semantic_census,
        &generator_stage.evidence_census,
        &behavior_census,
    )
    .map_err(invalid)?;
    let mut stage = IntentionalBoundaryBehaviorStage {
        schema_version: INTENTIONAL_BOUNDARY_BEHAVIOR_STAGE_SCHEMA_VERSION,
        stage_contract: STAGE_CONTRACT.to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        population_rank: materialization.population_rank,
        materialization_sha256: materialization.materialization_sha256.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        source_census_stage_sha256: source_census.stage_sha256.clone(),
        license_census_stage_sha256: license_census.stage_sha256.clone(),
        semantic_census_stage_sha256: semantic_census.stage_sha256.clone(),
        ast_census_stage_sha256: ast_census.stage_sha256.clone(),
        manifest_stage_sha256: manifest_stage.stage_sha256.clone(),
        base_evidence_stage_sha256: base_evidence_stage.stage_sha256.clone(),
        project_model_stage_sha256: project_model_stage.stage_sha256.clone(),
        generator_stage_sha256: generator_stage.stage_sha256.clone(),
        behavior_census,
        evidence_census,
        stage_sha256: String::new(),
    };
    stage.stage_sha256 = behavior_stage_sha256(&stage)?;
    Ok(stage)
}

#[allow(clippy::too_many_arguments)]
fn validate_upstream_lineage(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    semantic_census: &IntentionalBoundarySemanticCensusStage,
    ast_census: &IntentionalBoundaryAstCensusStage,
    manifest_stage: &IntentionalBoundaryManifestStage,
    base_evidence_stage: &IntentionalBoundaryEvidenceStage,
    project_model_stage: &IntentionalBoundaryProjectModelStage,
    generator_stage: &IntentionalBoundaryGeneratorStage,
) -> Result<(), IntentionalBoundaryBehaviorStageError> {
    let committed_generator =
        generator_stage_sha256(generator_stage).map_err(|error| invalid(error.detail))?;
    if generator_stage.stage_sha256 != committed_generator
        || generator_stage.frame_task_sha256 != task.task_sha256
        || generator_stage.population_rank != materialization.population_rank
        || generator_stage.materialization_sha256 != materialization.materialization_sha256
        || generator_stage.inventory_sha256 != inventory.inventory_sha256
        || generator_stage.source_census_stage_sha256 != source_census.stage_sha256
        || generator_stage.license_census_stage_sha256 != license_census.stage_sha256
        || generator_stage.semantic_census_stage_sha256 != semantic_census.stage_sha256
        || generator_stage.ast_census_stage_sha256 != ast_census.stage_sha256
        || generator_stage.manifest_stage_sha256 != manifest_stage.stage_sha256
        || generator_stage.base_evidence_stage_sha256 != base_evidence_stage.stage_sha256
        || generator_stage.project_model_stage_sha256 != project_model_stage.stage_sha256
    {
        return Err(invalid(
            "intentional-boundary behavior stage changed generator lineage",
        ));
    }
    Ok(())
}

pub(super) fn behavior_stage_sha256(
    value: &IntentionalBoundaryBehaviorStage,
) -> Result<String, IntentionalBoundaryBehaviorStageError> {
    hash_json(&(
        (
            value.schema_version,
            &value.stage_contract,
            &value.frame_task_sha256,
            value.population_rank,
            &value.materialization_sha256,
            &value.inventory_sha256,
            &value.source_census_stage_sha256,
            &value.license_census_stage_sha256,
        ),
        (
            &value.semantic_census_stage_sha256,
            &value.ast_census_stage_sha256,
            &value.manifest_stage_sha256,
            &value.base_evidence_stage_sha256,
            &value.project_model_stage_sha256,
            &value.generator_stage_sha256,
            &value.behavior_census,
            &value.evidence_census,
        ),
    ))
}

fn hash_json(value: &impl Serialize) -> Result<String, IntentionalBoundaryBehaviorStageError> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| invalid(format!("failed to commit behavior stage: {error}")))
}

fn map_derivation_error(error: BehaviorDerivationError) -> IntentionalBoundaryBehaviorStageError {
    IntentionalBoundaryBehaviorStageError {
        kind: match error.kind {
            BehaviorDerivationErrorKind::InvalidInput => {
                IntentionalBoundaryBehaviorStageErrorKind::InvalidInput
            }
            BehaviorDerivationErrorKind::InfrastructureUnavailable => {
                IntentionalBoundaryBehaviorStageErrorKind::InfrastructureUnavailable
            }
            BehaviorDerivationErrorKind::InfrastructureFailed => {
                IntentionalBoundaryBehaviorStageErrorKind::InfrastructureFailed
            }
        },
        detail: error.detail,
    }
}

fn invalid(detail: impl Into<String>) -> IntentionalBoundaryBehaviorStageError {
    IntentionalBoundaryBehaviorStageError {
        kind: IntentionalBoundaryBehaviorStageErrorKind::InvalidInput,
        detail: detail.into(),
    }
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_behavior_stage_tests.rs"]
mod tests;
