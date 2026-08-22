use super::intentional_boundary_compiler_evidence::validate_evidence_census_commitment;
use super::intentional_boundary_evidence_outcome::{
    EvidenceDerivationError, EvidenceDerivationErrorKind,
};
use super::intentional_boundary_evidence_stage_support::{
    derive_base_evidence, expected_base_evidence_inputs,
};
use super::{
    INTENTIONAL_BOUNDARY_EVIDENCE_STAGE_SCHEMA_VERSION, IntentionalBoundaryAstCensusStage,
    IntentionalBoundaryEvidenceCensus, IntentionalBoundaryEvidenceStage,
    IntentionalBoundaryEvidenceStageError, IntentionalBoundaryEvidenceStageErrorKind,
    IntentionalBoundaryFrameTask, IntentionalBoundaryLicenseCensusStage,
    IntentionalBoundaryManifestStage, IntentionalBoundaryManifestStageError,
    IntentionalBoundaryManifestStageErrorKind, IntentionalBoundaryManifestStageOutcome,
    IntentionalBoundaryMaterialization, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticCensusStage, IntentionalBoundarySourceCensusStage,
    validate_intentional_boundary_manifest_stage_outcome,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

const STAGE_CONTRACT: &str = "sniffbench-intentional-boundary-base-evidence-stage-v1";

#[allow(clippy::too_many_arguments)]
pub async fn census_intentional_boundary_evidence_stage(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    semantic_census: &IntentionalBoundarySemanticCensusStage,
    ast_census: &IntentionalBoundaryAstCensusStage,
    manifest_stage: &IntentionalBoundaryManifestStage,
) -> Result<IntentionalBoundaryEvidenceStage, IntentionalBoundaryEvidenceStageError> {
    validate_manifest_stage(
        task,
        materialization,
        root,
        inventory,
        source_census,
        license_census,
        semantic_census,
        ast_census,
        manifest_stage,
    )
    .await?;
    let evidence_census = derive_base_evidence(
        &source_census.source_census,
        &semantic_census.semantic_census,
        &ast_census.ast_censuses,
        &manifest_stage.manifest_census,
        &manifest_stage.binding_census,
    )
    .map_err(map_derivation_error)?;
    finish_evidence_stage(
        task,
        materialization,
        inventory,
        source_census,
        license_census,
        semantic_census,
        ast_census,
        manifest_stage,
        evidence_census,
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn validate_intentional_boundary_evidence_stage(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    semantic_census: &IntentionalBoundarySemanticCensusStage,
    ast_census: &IntentionalBoundaryAstCensusStage,
    manifest_stage: &IntentionalBoundaryManifestStage,
    stage: &IntentionalBoundaryEvidenceStage,
) -> Result<(), IntentionalBoundaryEvidenceStageError> {
    let expected = census_intentional_boundary_evidence_stage(
        task,
        materialization,
        root,
        inventory,
        source_census,
        license_census,
        semantic_census,
        ast_census,
        manifest_stage,
    )
    .await?;
    if stage != &expected {
        return Err(invalid("intentional-boundary base evidence stage changed"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn finish_evidence_stage(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    semantic_census: &IntentionalBoundarySemanticCensusStage,
    ast_census: &IntentionalBoundaryAstCensusStage,
    manifest_stage: &IntentionalBoundaryManifestStage,
    evidence_census: IntentionalBoundaryEvidenceCensus,
) -> Result<IntentionalBoundaryEvidenceStage, IntentionalBoundaryEvidenceStageError> {
    validate_evidence_census_commitment(
        &source_census.source_census,
        &semantic_census.semantic_census,
        &evidence_census,
    )
    .map_err(invalid)?;
    let expected_inputs = expected_base_evidence_inputs(
        &semantic_census.semantic_census,
        &ast_census.ast_censuses,
        &manifest_stage.manifest_census,
        &manifest_stage.binding_census,
    )
    .map_err(map_derivation_error)?;
    if evidence_census.repository != materialization.repository
        || evidence_census.revision != materialization.revision
        || evidence_census.source_census_sha256 != source_census.source_census.census_sha256
        || evidence_census.semantic_census_sha256
            != semantic_census.semantic_census.semantic_census_sha256
        || evidence_census.input_census_sha256 != expected_inputs
        || manifest_stage.frame_task_sha256 != task.task_sha256
        || manifest_stage.population_rank != materialization.population_rank
        || manifest_stage.materialization_sha256 != materialization.materialization_sha256
        || manifest_stage.inventory_sha256 != inventory.inventory_sha256
        || manifest_stage.source_census_stage_sha256 != source_census.stage_sha256
        || manifest_stage.license_census_stage_sha256 != license_census.stage_sha256
        || manifest_stage.semantic_census_stage_sha256 != semantic_census.stage_sha256
        || manifest_stage.ast_census_stage_sha256 != ast_census.stage_sha256
    {
        return Err(invalid(
            "intentional-boundary base evidence stage changed producer lineage",
        ));
    }
    let mut stage = IntentionalBoundaryEvidenceStage {
        schema_version: INTENTIONAL_BOUNDARY_EVIDENCE_STAGE_SCHEMA_VERSION,
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
        evidence_census,
        stage_sha256: String::new(),
    };
    stage.stage_sha256 = stage_sha256(&stage)?;
    Ok(stage)
}

#[allow(clippy::too_many_arguments)]
async fn validate_manifest_stage(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    semantic_census: &IntentionalBoundarySemanticCensusStage,
    ast_census: &IntentionalBoundaryAstCensusStage,
    manifest_stage: &IntentionalBoundaryManifestStage,
) -> Result<(), IntentionalBoundaryEvidenceStageError> {
    validate_intentional_boundary_manifest_stage_outcome(
        task,
        materialization,
        root,
        inventory,
        source_census,
        license_census,
        semantic_census,
        ast_census,
        &IntentionalBoundaryManifestStageOutcome::Completed(Box::new(manifest_stage.clone())),
    )
    .await
    .map_err(map_manifest_error)
}

fn stage_sha256(
    value: &IntentionalBoundaryEvidenceStage,
) -> Result<String, IntentionalBoundaryEvidenceStageError> {
    hash_json(&(
        value.schema_version,
        &value.stage_contract,
        &value.frame_task_sha256,
        value.population_rank,
        &value.materialization_sha256,
        &value.inventory_sha256,
        &value.source_census_stage_sha256,
        &value.license_census_stage_sha256,
        &value.semantic_census_stage_sha256,
        &value.ast_census_stage_sha256,
        &value.manifest_stage_sha256,
        &value.evidence_census,
    ))
}

fn hash_json(value: &impl Serialize) -> Result<String, IntentionalBoundaryEvidenceStageError> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| invalid(format!("failed to commit base evidence stage: {error}")))
}

pub(super) fn map_manifest_error(
    error: IntentionalBoundaryManifestStageError,
) -> IntentionalBoundaryEvidenceStageError {
    IntentionalBoundaryEvidenceStageError {
        kind: match error.kind {
            IntentionalBoundaryManifestStageErrorKind::InvalidInput => {
                IntentionalBoundaryEvidenceStageErrorKind::InvalidInput
            }
            IntentionalBoundaryManifestStageErrorKind::InfrastructureUnavailable => {
                IntentionalBoundaryEvidenceStageErrorKind::InfrastructureUnavailable
            }
            IntentionalBoundaryManifestStageErrorKind::InfrastructureFailed => {
                IntentionalBoundaryEvidenceStageErrorKind::InfrastructureFailed
            }
        },
        detail: error.detail,
    }
}

fn map_derivation_error(error: EvidenceDerivationError) -> IntentionalBoundaryEvidenceStageError {
    match error.kind {
        EvidenceDerivationErrorKind::InvalidInput => invalid(error.detail),
    }
}

fn invalid(detail: impl Into<String>) -> IntentionalBoundaryEvidenceStageError {
    IntentionalBoundaryEvidenceStageError {
        kind: IntentionalBoundaryEvidenceStageErrorKind::InvalidInput,
        detail: detail.into(),
    }
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_evidence_stage_tests.rs"]
mod tests;
