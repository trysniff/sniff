use super::intentional_boundary_behavior_stage::behavior_stage_sha256;
use super::intentional_boundary_candidate::qualify_intentional_boundary_candidates_typed;
use super::intentional_boundary_candidate_outcome::{
    CandidateDerivationError, CandidateDerivationErrorKind,
};
use super::{
    INTENTIONAL_BOUNDARY_CANDIDATE_STAGE_SCHEMA_VERSION, IntentionalBoundaryAstCensusStage,
    IntentionalBoundaryBehaviorStage, IntentionalBoundaryCandidateCensus,
    IntentionalBoundaryCandidateStage, IntentionalBoundaryCandidateStageError,
    IntentionalBoundaryCandidateStageErrorKind, IntentionalBoundaryEvidenceStage,
    IntentionalBoundaryFrameTask, IntentionalBoundaryGeneratorStage,
    IntentionalBoundaryLicenseCensusStage, IntentionalBoundaryManifestStage,
    IntentionalBoundaryMaterialization, IntentionalBoundaryProjectModelStage,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundarySemanticCensusStage,
    IntentionalBoundarySourceCensusStage, ValidatedIntentionalBoundaryProtocol,
    validate_intentional_boundary_candidate_census,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

const STAGE_CONTRACT: &str = "sniffbench-intentional-boundary-candidate-stage-v1";

#[allow(clippy::too_many_arguments)]
pub fn qualify_intentional_boundary_candidate_stage(
    protocol: &ValidatedIntentionalBoundaryProtocol,
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
    behavior_stage: &IntentionalBoundaryBehaviorStage,
) -> Result<IntentionalBoundaryCandidateStage, IntentionalBoundaryCandidateStageError> {
    validate_upstream_lineage(
        protocol,
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
        behavior_stage,
    )?;
    let candidate_census = qualify_intentional_boundary_candidates_typed(
        protocol,
        &source_census.source_census,
        &semantic_census.semantic_census,
        &behavior_stage.evidence_census,
    )
    .map_err(map_derivation_error)?;
    finish_candidate_stage(
        protocol,
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
        behavior_stage,
        candidate_census,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn validate_intentional_boundary_candidate_stage(
    protocol: &ValidatedIntentionalBoundaryProtocol,
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
    behavior_stage: &IntentionalBoundaryBehaviorStage,
    stage: &IntentionalBoundaryCandidateStage,
) -> Result<(), IntentionalBoundaryCandidateStageError> {
    let expected = qualify_intentional_boundary_candidate_stage(
        protocol,
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
        behavior_stage,
    )?;
    if stage != &expected {
        return Err(invalid("intentional-boundary candidate stage changed"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn finish_candidate_stage(
    protocol: &ValidatedIntentionalBoundaryProtocol,
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
    behavior_stage: &IntentionalBoundaryBehaviorStage,
    candidate_census: IntentionalBoundaryCandidateCensus,
) -> Result<IntentionalBoundaryCandidateStage, IntentionalBoundaryCandidateStageError> {
    validate_upstream_lineage(
        protocol,
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
        behavior_stage,
    )?;
    validate_intentional_boundary_candidate_census(
        protocol,
        &source_census.source_census,
        &semantic_census.semantic_census,
        &behavior_stage.evidence_census,
        &candidate_census,
    )
    .map_err(invalid)?;
    let mut stage = IntentionalBoundaryCandidateStage {
        schema_version: INTENTIONAL_BOUNDARY_CANDIDATE_STAGE_SCHEMA_VERSION,
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
        behavior_stage_sha256: behavior_stage.stage_sha256.clone(),
        protocol_sha256: protocol.protocol_sha256.clone(),
        candidate_census,
        stage_sha256: String::new(),
    };
    stage.stage_sha256 = candidate_stage_sha256(&stage)?;
    Ok(stage)
}

#[allow(clippy::too_many_arguments)]
fn validate_upstream_lineage(
    protocol: &ValidatedIntentionalBoundaryProtocol,
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
    behavior_stage: &IntentionalBoundaryBehaviorStage,
) -> Result<(), IntentionalBoundaryCandidateStageError> {
    let committed_behavior =
        behavior_stage_sha256(behavior_stage).map_err(|error| invalid(error.detail))?;
    if protocol.protocol_sha256 != task.protocol_sha256 {
        return Err(invalid(
            "intentional-boundary candidate protocol does not match the frame task",
        ));
    }
    if behavior_stage.stage_sha256 != committed_behavior
        || behavior_stage.frame_task_sha256 != task.task_sha256
        || behavior_stage.population_rank != materialization.population_rank
        || behavior_stage.materialization_sha256 != materialization.materialization_sha256
        || behavior_stage.inventory_sha256 != inventory.inventory_sha256
        || behavior_stage.source_census_stage_sha256 != source_census.stage_sha256
        || behavior_stage.license_census_stage_sha256 != license_census.stage_sha256
        || behavior_stage.semantic_census_stage_sha256 != semantic_census.stage_sha256
        || behavior_stage.ast_census_stage_sha256 != ast_census.stage_sha256
        || behavior_stage.manifest_stage_sha256 != manifest_stage.stage_sha256
        || behavior_stage.base_evidence_stage_sha256 != base_evidence_stage.stage_sha256
        || behavior_stage.project_model_stage_sha256 != project_model_stage.stage_sha256
        || behavior_stage.generator_stage_sha256 != generator_stage.stage_sha256
    {
        return Err(invalid(
            "intentional-boundary candidate stage changed behavior lineage",
        ));
    }
    Ok(())
}

pub(super) fn candidate_stage_sha256(
    value: &IntentionalBoundaryCandidateStage,
) -> Result<String, IntentionalBoundaryCandidateStageError> {
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
            &value.behavior_stage_sha256,
            &value.protocol_sha256,
            &value.candidate_census,
        ),
    ))
}

fn hash_json(value: &impl Serialize) -> Result<String, IntentionalBoundaryCandidateStageError> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| invalid(format!("failed to commit candidate stage: {error}")))
}

fn map_derivation_error(error: CandidateDerivationError) -> IntentionalBoundaryCandidateStageError {
    match error.kind {
        CandidateDerivationErrorKind::InvalidInput => IntentionalBoundaryCandidateStageError {
            kind: IntentionalBoundaryCandidateStageErrorKind::InvalidInput,
            detail: error.detail,
        },
    }
}

fn invalid(detail: impl Into<String>) -> IntentionalBoundaryCandidateStageError {
    IntentionalBoundaryCandidateStageError {
        kind: IntentionalBoundaryCandidateStageErrorKind::InvalidInput,
        detail: detail.into(),
    }
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_candidate_stage_tests.rs"]
mod tests;
