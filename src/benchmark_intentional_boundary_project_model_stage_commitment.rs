use super::{
    IntentionalBoundaryEvidenceCensus, IntentionalBoundaryEvidenceStage,
    IntentionalBoundaryEvidenceStageError, IntentionalBoundaryEvidenceStageErrorKind,
    IntentionalBoundaryManifestStage, IntentionalBoundaryMaterialization,
    IntentionalBoundaryProjectModelBindingCensus, IntentionalBoundaryProjectModelCensus,
    IntentionalBoundaryProjectModelExclusion, IntentionalBoundaryProjectModelProvider,
    IntentionalBoundaryProjectModelStage, IntentionalBoundaryProjectModelStageError,
    IntentionalBoundaryProjectModelStageErrorKind, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticCensusStage, IntentionalBoundarySourceCensusStage,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub(super) const PROJECT_MODEL_INPUT: &str = "compiler_project_models";
pub(super) const PROJECT_MODEL_BINDING_INPUT: &str = "compiler_project_model_bindings";

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_completion_lineage(
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    semantic_census: &IntentionalBoundarySemanticCensusStage,
    manifest_stage: &IntentionalBoundaryManifestStage,
    base_evidence_stage: &IntentionalBoundaryEvidenceStage,
    required_providers: &[IntentionalBoundaryProjectModelProvider],
    project_models: &IntentionalBoundaryProjectModelCensus,
    bindings: &IntentionalBoundaryProjectModelBindingCensus,
    evidence: &IntentionalBoundaryEvidenceCensus,
) -> Result<(), IntentionalBoundaryProjectModelStageError> {
    let execution_providers = project_models
        .executions
        .iter()
        .map(|execution| execution.provider)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut expected_inputs = base_evidence_stage
        .evidence_census
        .input_census_sha256
        .clone();
    if expected_inputs
        .insert(
            PROJECT_MODEL_INPUT.to_string(),
            project_models.project_model_census_sha256.clone(),
        )
        .is_some()
        || expected_inputs
            .insert(
                PROJECT_MODEL_BINDING_INPUT.to_string(),
                bindings.binding_census_sha256.clone(),
            )
            .is_some()
    {
        return Err(invalid("project-model evidence input collision"));
    }
    if project_models.repository != materialization.repository
        || project_models.revision != materialization.revision
        || project_models.inventory_sha256 != inventory.inventory_sha256
        || execution_providers != required_providers
        || bindings.repository != materialization.repository
        || bindings.revision != materialization.revision
        || bindings.source_census_sha256 != source_census.source_census.census_sha256
        || bindings.semantic_census_sha256 != semantic_census.semantic_census.semantic_census_sha256
        || bindings.project_model_census_sha256 != project_models.project_model_census_sha256
        || evidence.repository != materialization.repository
        || evidence.revision != materialization.revision
        || evidence.source_census_sha256 != source_census.source_census.census_sha256
        || evidence.semantic_census_sha256 != semantic_census.semantic_census.semantic_census_sha256
        || evidence.input_census_sha256 != expected_inputs
        || manifest_stage.frame_task_sha256 != base_evidence_stage.frame_task_sha256
        || manifest_stage.population_rank != base_evidence_stage.population_rank
        || manifest_stage.stage_sha256 != base_evidence_stage.manifest_stage_sha256
    {
        return Err(invalid("project-model completion changed producer lineage"));
    }
    Ok(())
}

pub(super) fn stage_sha256(
    value: &IntentionalBoundaryProjectModelStage,
) -> Result<String, IntentionalBoundaryProjectModelStageError> {
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
            &value.required_providers,
            &value.project_model_census,
            &value.binding_census,
            &value.evidence_census,
        ),
    ))
}

pub(super) fn exclusion_sha256(
    value: &IntentionalBoundaryProjectModelExclusion,
) -> Result<String, IntentionalBoundaryProjectModelStageError> {
    hash_json(&(
        (
            value.schema_version,
            &value.exclusion_contract,
            &value.frame_task_sha256,
            value.population_rank,
            &value.repository,
            &value.revision,
            &value.materialization_sha256,
            &value.inventory_sha256,
        ),
        (
            &value.source_census_stage_sha256,
            &value.license_census_stage_sha256,
            &value.semantic_census_stage_sha256,
            &value.ast_census_stage_sha256,
            &value.manifest_stage_sha256,
            &value.base_evidence_stage_sha256,
            &value.required_providers,
            &value.reasons,
            &value.failures,
        ),
    ))
}

pub(super) fn map_evidence_error(
    error: IntentionalBoundaryEvidenceStageError,
) -> IntentionalBoundaryProjectModelStageError {
    IntentionalBoundaryProjectModelStageError {
        kind: match error.kind {
            IntentionalBoundaryEvidenceStageErrorKind::InvalidInput => {
                IntentionalBoundaryProjectModelStageErrorKind::InvalidInput
            }
            IntentionalBoundaryEvidenceStageErrorKind::InfrastructureUnavailable => {
                IntentionalBoundaryProjectModelStageErrorKind::InfrastructureUnavailable
            }
            IntentionalBoundaryEvidenceStageErrorKind::InfrastructureFailed => {
                IntentionalBoundaryProjectModelStageErrorKind::InfrastructureFailed
            }
        },
        detail: error.detail,
    }
}

fn hash_json(value: &impl Serialize) -> Result<String, IntentionalBoundaryProjectModelStageError> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| invalid(format!("failed to commit project-model stage: {error}")))
}

fn invalid(detail: impl Into<String>) -> IntentionalBoundaryProjectModelStageError {
    IntentionalBoundaryProjectModelStageError {
        kind: IntentionalBoundaryProjectModelStageErrorKind::InvalidInput,
        detail: detail.into(),
    }
}
