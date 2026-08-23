use super::intentional_boundary_semantic::build_semantic_census;
use super::intentional_boundary_semantic_stage_support::{
    ResolvedSemanticRun, assembly_failure, failure_key, resolve_semantic_run,
};
use super::intentional_boundary_source_census::intentional_boundary_file_records_typed;
use super::{
    INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_EXCLUSION_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_STAGE_SCHEMA_VERSION, IntentionalBoundaryFrameTask,
    IntentionalBoundaryInventoryError, IntentionalBoundaryInventoryErrorKind,
    IntentionalBoundaryLicenseCensusStage, IntentionalBoundaryLicenseCensusStageError,
    IntentionalBoundaryLicenseCensusStageErrorKind, IntentionalBoundaryMaterialization,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundarySemanticCensusExclusion,
    IntentionalBoundarySemanticCensusStage, IntentionalBoundarySemanticCensusStageError,
    IntentionalBoundarySemanticCensusStageErrorKind, IntentionalBoundarySemanticCensusStageOutcome,
    IntentionalBoundarySourceCensusStage, validate_committed_license_census_stage,
    validate_intentional_boundary_semantic_census,
};
use crate::semantic_indexer_runner::{SemanticIndexerBatchOutcome, SemanticIndexerRunFailure};
use crate::types::FileRecord;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;

const STAGE_CONTRACT: &str = "sniffbench-intentional-boundary-semantic-census-stage-v1";
const EXCLUSION_CONTRACT: &str = "sniffbench-intentional-boundary-semantic-census-exclusion-v1";

pub async fn census_intentional_boundary_semantics_stage(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
) -> Result<
    IntentionalBoundarySemanticCensusStageOutcome,
    IntentionalBoundarySemanticCensusStageError,
> {
    validate_license_census(
        task,
        materialization,
        inventory,
        source_census,
        license_census,
    )?;
    let files =
        intentional_boundary_file_records_typed(root, inventory, &source_census.source_census)
            .map_err(map_inventory_error)?;
    let run =
        crate::semantic_indexer_runner::run_required_indexers_exhaustive_typed(root, &files).await;
    finish_semantic_stage(
        task,
        materialization,
        inventory,
        source_census,
        license_census,
        root,
        &files,
        run,
    )
}

pub async fn validate_intentional_boundary_semantic_census_stage_outcome(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    outcome: &IntentionalBoundarySemanticCensusStageOutcome,
) -> Result<(), IntentionalBoundarySemanticCensusStageError> {
    let expected = census_intentional_boundary_semantics_stage(
        task,
        materialization,
        root,
        inventory,
        source_census,
        license_census,
    )
    .await?;
    if outcome != &expected {
        return Err(invalid(
            "intentional-boundary semantic census stage outcome changed",
        ));
    }
    Ok(())
}

pub(super) fn validate_committed_semantic_census_stage(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    stage: &IntentionalBoundarySemanticCensusStage,
) -> Result<(), IntentionalBoundarySemanticCensusStageError> {
    validate_license_census(
        task,
        materialization,
        inventory,
        source_census,
        license_census,
    )?;
    validate_intentional_boundary_semantic_census(
        &source_census.source_census,
        &stage.semantic_census,
    )
    .map_err(invalid)?;
    if stage.schema_version != INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_STAGE_SCHEMA_VERSION
        || stage.stage_contract != STAGE_CONTRACT
        || stage.frame_task_sha256 != task.task_sha256
        || stage.population_rank != materialization.population_rank
        || stage.materialization_sha256 != materialization.materialization_sha256
        || stage.inventory_sha256 != inventory.inventory_sha256
        || stage.source_census_stage_sha256 != source_census.stage_sha256
        || stage.license_census_stage_sha256 != license_census.stage_sha256
        || stage.stage_sha256 != stage_sha256(stage)?
    {
        return Err(invalid(
            "intentional-boundary committed semantic census stage changed",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn finish_semantic_stage(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    root: &Path,
    files: &[FileRecord],
    run: Result<SemanticIndexerBatchOutcome, SemanticIndexerRunFailure>,
) -> Result<
    IntentionalBoundarySemanticCensusStageOutcome,
    IntentionalBoundarySemanticCensusStageError,
> {
    let indexes = match resolve_semantic_run(run)? {
        ResolvedSemanticRun::Completed(indexes) => indexes,
        ResolvedSemanticRun::Excluded(failures) => {
            return exclusion(
                task,
                materialization,
                inventory,
                source_census,
                license_census,
                failures,
            )
            .map(IntentionalBoundarySemanticCensusStageOutcome::Excluded);
        }
    };
    let semantic_census =
        match build_semantic_census(root, &source_census.source_census, files, &indexes) {
            Ok(census) => census,
            Err(detail) => {
                return exclusion(
                    task,
                    materialization,
                    inventory,
                    source_census,
                    license_census,
                    vec![assembly_failure(detail)],
                )
                .map(IntentionalBoundarySemanticCensusStageOutcome::Excluded);
            }
        };
    completion(
        task,
        materialization,
        inventory,
        source_census,
        license_census,
        semantic_census,
    )
    .map(IntentionalBoundarySemanticCensusStageOutcome::Completed)
}

fn completion(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    semantic_census: super::IntentionalBoundarySemanticCensus,
) -> Result<IntentionalBoundarySemanticCensusStage, IntentionalBoundarySemanticCensusStageError> {
    let mut stage = IntentionalBoundarySemanticCensusStage {
        schema_version: INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_STAGE_SCHEMA_VERSION,
        stage_contract: STAGE_CONTRACT.to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        population_rank: materialization.population_rank,
        materialization_sha256: materialization.materialization_sha256.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        source_census_stage_sha256: source_census.stage_sha256.clone(),
        license_census_stage_sha256: license_census.stage_sha256.clone(),
        semantic_census,
        stage_sha256: String::new(),
    };
    stage.stage_sha256 = stage_sha256(&stage)?;
    Ok(stage)
}

fn exclusion(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    mut failures: Vec<super::IntentionalBoundarySemanticCensusFailureEvidence>,
) -> Result<IntentionalBoundarySemanticCensusExclusion, IntentionalBoundarySemanticCensusStageError>
{
    if failures.is_empty() {
        return Err(invalid(
            "intentional-boundary semantic exclusion requires failure evidence",
        ));
    }
    failures.sort_by(failure_key);
    let reasons = failures
        .iter()
        .map(|failure| failure.reason)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut exclusion = IntentionalBoundarySemanticCensusExclusion {
        schema_version: INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_EXCLUSION_SCHEMA_VERSION,
        exclusion_contract: EXCLUSION_CONTRACT.to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        population_rank: materialization.population_rank,
        repository: materialization.repository.clone(),
        revision: materialization.revision.clone(),
        materialization_sha256: materialization.materialization_sha256.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        source_census_stage_sha256: source_census.stage_sha256.clone(),
        license_census_stage_sha256: license_census.stage_sha256.clone(),
        reasons,
        failures,
        exclusion_sha256: String::new(),
    };
    exclusion.exclusion_sha256 = exclusion_sha256(&exclusion)?;
    Ok(exclusion)
}

fn validate_license_census(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
) -> Result<(), IntentionalBoundarySemanticCensusStageError> {
    validate_committed_license_census_stage(
        task,
        materialization,
        inventory,
        source_census,
        license_census,
    )
    .map_err(map_license_error)
}

fn stage_sha256(
    value: &IntentionalBoundarySemanticCensusStage,
) -> Result<String, IntentionalBoundarySemanticCensusStageError> {
    hash_json(&(
        value.schema_version,
        &value.stage_contract,
        &value.frame_task_sha256,
        value.population_rank,
        &value.materialization_sha256,
        &value.inventory_sha256,
        &value.source_census_stage_sha256,
        &value.license_census_stage_sha256,
        &value.semantic_census,
    ))
}

fn exclusion_sha256(
    value: &IntentionalBoundarySemanticCensusExclusion,
) -> Result<String, IntentionalBoundarySemanticCensusStageError> {
    hash_json(&(
        value.schema_version,
        &value.exclusion_contract,
        &value.frame_task_sha256,
        value.population_rank,
        &value.repository,
        &value.revision,
        &value.materialization_sha256,
        &value.inventory_sha256,
        &value.source_census_stage_sha256,
        &value.license_census_stage_sha256,
        &value.reasons,
        &value.failures,
    ))
}

fn hash_json(
    value: &impl Serialize,
) -> Result<String, IntentionalBoundarySemanticCensusStageError> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| invalid(format!("failed to commit semantic census stage: {error}")))
}

fn map_license_error(
    error: IntentionalBoundaryLicenseCensusStageError,
) -> IntentionalBoundarySemanticCensusStageError {
    IntentionalBoundarySemanticCensusStageError {
        kind: match error.kind {
            IntentionalBoundaryLicenseCensusStageErrorKind::InvalidInput => {
                IntentionalBoundarySemanticCensusStageErrorKind::InvalidInput
            }
            IntentionalBoundaryLicenseCensusStageErrorKind::InfrastructureUnavailable => {
                IntentionalBoundarySemanticCensusStageErrorKind::InfrastructureUnavailable
            }
            IntentionalBoundaryLicenseCensusStageErrorKind::InfrastructureFailed => {
                IntentionalBoundarySemanticCensusStageErrorKind::InfrastructureFailed
            }
        },
        detail: error.detail,
    }
}

fn map_inventory_error(
    error: IntentionalBoundaryInventoryError,
) -> IntentionalBoundarySemanticCensusStageError {
    IntentionalBoundarySemanticCensusStageError {
        kind: match error.kind {
            IntentionalBoundaryInventoryErrorKind::InvalidInput => {
                IntentionalBoundarySemanticCensusStageErrorKind::InvalidInput
            }
            IntentionalBoundaryInventoryErrorKind::InfrastructureUnavailable => {
                IntentionalBoundarySemanticCensusStageErrorKind::InfrastructureUnavailable
            }
            IntentionalBoundaryInventoryErrorKind::InfrastructureFailed => {
                IntentionalBoundarySemanticCensusStageErrorKind::InfrastructureFailed
            }
        },
        detail: error.detail,
    }
}

fn invalid(detail: impl Into<String>) -> IntentionalBoundarySemanticCensusStageError {
    IntentionalBoundarySemanticCensusStageError {
        kind: IntentionalBoundarySemanticCensusStageErrorKind::InvalidInput,
        detail: detail.into(),
    }
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_semantic_stage_tests.rs"]
mod tests;
