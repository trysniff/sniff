use super::intentional_boundary_generator::census_intentional_boundary_generators_typed;
use super::intentional_boundary_generator_outcome::{
    GeneratorDerivationError, GeneratorDerivationErrorKind,
};
use super::intentional_boundary_project_model_stage_commitment::stage_sha256 as project_model_stage_sha256;
use super::{
    INTENTIONAL_BOUNDARY_GENERATOR_STAGE_SCHEMA_VERSION, IntentionalBoundaryAstCensusStage,
    IntentionalBoundaryEvidenceStage, IntentionalBoundaryFrameTask,
    IntentionalBoundaryGeneratorCensus, IntentionalBoundaryGeneratorEvidenceInputs,
    IntentionalBoundaryGeneratorStage, IntentionalBoundaryGeneratorStageError,
    IntentionalBoundaryGeneratorStageErrorKind, IntentionalBoundaryLicenseCensusStage,
    IntentionalBoundaryManifestStage, IntentionalBoundaryMaterialization,
    IntentionalBoundaryProjectModelStage, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticCensusStage, IntentionalBoundarySourceCensusStage,
    compose_intentional_boundary_generator_evidence, validate_committed_project_model_stage,
    validate_intentional_boundary_generator_census_commitment,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

const STAGE_CONTRACT: &str = "sniffbench-intentional-boundary-generator-stage-v1";

#[allow(clippy::too_many_arguments)]
pub fn census_intentional_boundary_generator_stage(
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
) -> Result<IntentionalBoundaryGeneratorStage, IntentionalBoundaryGeneratorStageError> {
    validate_committed_upstream_lineage(
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
    )?;
    let generator_census = census_intentional_boundary_generators_typed(
        &materialization.repository,
        &materialization.revision,
        root,
        inventory,
        &source_census.source_census,
        &semantic_census.semantic_census,
        &project_model_stage.project_model_census,
        &manifest_stage.manifest_census,
        &manifest_stage.binding_census,
        &project_model_stage.evidence_census,
    )
    .map_err(map_derivation_error)?;
    finish_generator_stage(
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
        generator_census,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn validate_intentional_boundary_generator_stage(
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
    stage: &IntentionalBoundaryGeneratorStage,
) -> Result<(), IntentionalBoundaryGeneratorStageError> {
    let expected = census_intentional_boundary_generator_stage(
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
    )?;
    if stage != &expected {
        return Err(invalid("intentional-boundary generator stage changed"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_committed_generator_stage(
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
    stage: &IntentionalBoundaryGeneratorStage,
) -> Result<(), IntentionalBoundaryGeneratorStageError> {
    validate_committed_upstream_lineage(
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
    )?;
    let expected = finish_generator_stage(
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
        stage.generator_census.clone(),
    )?;
    if stage != &expected {
        return Err(invalid(
            "intentional-boundary committed generator stage changed",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn finish_generator_stage(
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
    generator_census: IntentionalBoundaryGeneratorCensus,
) -> Result<IntentionalBoundaryGeneratorStage, IntentionalBoundaryGeneratorStageError> {
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
    )?;
    let inputs = IntentionalBoundaryGeneratorEvidenceInputs {
        inventory,
        source_census: &source_census.source_census,
        semantic_census: &semantic_census.semantic_census,
        project_model_census: &project_model_stage.project_model_census,
        manifest_census: &manifest_stage.manifest_census,
        binding_census: &manifest_stage.binding_census,
        base_evidence: &project_model_stage.evidence_census,
        generator_census: &generator_census,
    };
    validate_intentional_boundary_generator_census_commitment(
        inputs.inventory,
        inputs.source_census,
        inputs.semantic_census,
        inputs.project_model_census,
        inputs.manifest_census,
        inputs.binding_census,
        inputs.base_evidence,
        inputs.generator_census,
    )
    .map_err(invalid)?;
    let evidence_census =
        compose_intentional_boundary_generator_evidence(inputs).map_err(invalid)?;
    let mut stage = IntentionalBoundaryGeneratorStage {
        schema_version: INTENTIONAL_BOUNDARY_GENERATOR_STAGE_SCHEMA_VERSION,
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
        generator_census,
        evidence_census,
        stage_sha256: String::new(),
    };
    stage.stage_sha256 = generator_stage_sha256(&stage)?;
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
) -> Result<(), IntentionalBoundaryGeneratorStageError> {
    let committed_project_model =
        project_model_stage_sha256(project_model_stage).map_err(|error| invalid(error.detail))?;
    if project_model_stage.stage_sha256 != committed_project_model
        || project_model_stage.frame_task_sha256 != task.task_sha256
        || project_model_stage.population_rank != materialization.population_rank
        || project_model_stage.materialization_sha256 != materialization.materialization_sha256
        || project_model_stage.inventory_sha256 != inventory.inventory_sha256
        || project_model_stage.source_census_stage_sha256 != source_census.stage_sha256
        || project_model_stage.license_census_stage_sha256 != license_census.stage_sha256
        || project_model_stage.semantic_census_stage_sha256 != semantic_census.stage_sha256
        || project_model_stage.ast_census_stage_sha256 != ast_census.stage_sha256
        || project_model_stage.manifest_stage_sha256 != manifest_stage.stage_sha256
        || project_model_stage.base_evidence_stage_sha256 != base_evidence_stage.stage_sha256
    {
        return Err(invalid(
            "intentional-boundary generator stage changed project-model lineage",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_committed_upstream_lineage(
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
) -> Result<(), IntentionalBoundaryGeneratorStageError> {
    validate_committed_project_model_stage(
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
    )
    .map_err(map_project_model_error)
}

pub(super) fn generator_stage_sha256(
    value: &IntentionalBoundaryGeneratorStage,
) -> Result<String, IntentionalBoundaryGeneratorStageError> {
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
            &value.generator_census,
            &value.evidence_census,
        ),
    ))
}

fn hash_json(value: &impl Serialize) -> Result<String, IntentionalBoundaryGeneratorStageError> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| invalid(format!("failed to commit generator stage: {error}")))
}

fn map_derivation_error(error: GeneratorDerivationError) -> IntentionalBoundaryGeneratorStageError {
    IntentionalBoundaryGeneratorStageError {
        kind: match error.kind {
            GeneratorDerivationErrorKind::InvalidInput => {
                IntentionalBoundaryGeneratorStageErrorKind::InvalidInput
            }
            GeneratorDerivationErrorKind::InfrastructureUnavailable => {
                IntentionalBoundaryGeneratorStageErrorKind::InfrastructureUnavailable
            }
            GeneratorDerivationErrorKind::InfrastructureFailed => {
                IntentionalBoundaryGeneratorStageErrorKind::InfrastructureFailed
            }
        },
        detail: error.detail,
    }
}

fn map_project_model_error(
    error: super::IntentionalBoundaryProjectModelStageError,
) -> IntentionalBoundaryGeneratorStageError {
    IntentionalBoundaryGeneratorStageError {
        kind: match error.kind {
            super::IntentionalBoundaryProjectModelStageErrorKind::InvalidInput => {
                IntentionalBoundaryGeneratorStageErrorKind::InvalidInput
            }
            super::IntentionalBoundaryProjectModelStageErrorKind::InfrastructureUnavailable => {
                IntentionalBoundaryGeneratorStageErrorKind::InfrastructureUnavailable
            }
            super::IntentionalBoundaryProjectModelStageErrorKind::InfrastructureFailed => {
                IntentionalBoundaryGeneratorStageErrorKind::InfrastructureFailed
            }
        },
        detail: error.detail,
    }
}

fn invalid(detail: impl Into<String>) -> IntentionalBoundaryGeneratorStageError {
    IntentionalBoundaryGeneratorStageError {
        kind: IntentionalBoundaryGeneratorStageErrorKind::InvalidInput,
        detail: detail.into(),
    }
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_generator_stage_tests.rs"]
mod tests;
