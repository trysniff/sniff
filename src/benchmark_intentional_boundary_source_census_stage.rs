use super::intentional_boundary_source_census::{
    INTENTIONAL_BOUNDARY_SOURCE_EXTENSION_CONTRACT, IntentionalBoundarySourceInspection,
    inspect_intentional_boundary_repository_sources_typed,
};
use super::intentional_boundary_source_census_commitment::validate_source_census_commitment;
use super::{
    INTENTIONAL_BOUNDARY_SOURCE_CENSUS_EXCLUSION_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_SOURCE_CENSUS_STAGE_SCHEMA_VERSION, IntentionalBoundaryFrameTask,
    IntentionalBoundaryInventoryError, IntentionalBoundaryInventoryErrorKind,
    IntentionalBoundaryMaterialization, IntentionalBoundaryMaterializationError,
    IntentionalBoundaryMaterializationErrorKind, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySourceCensusExclusion, IntentionalBoundarySourceCensusExclusionReason,
    IntentionalBoundarySourceCensusFailureEvidence, IntentionalBoundarySourceCensusStage,
    IntentionalBoundarySourceCensusStageError, IntentionalBoundarySourceCensusStageErrorKind,
    IntentionalBoundarySourceCensusStageOutcome, validate_intentional_boundary_materialization,
    validate_intentional_boundary_materialization_commitment,
    validate_intentional_boundary_repository_inventory_commitment_typed,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

const STAGE_CONTRACT: &str = "sniffbench-intentional-boundary-source-census-stage-v1";
const EXCLUSION_CONTRACT: &str = "sniffbench-intentional-boundary-source-census-exclusion-v1";

pub fn census_intentional_boundary_repository_stage(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Result<IntentionalBoundarySourceCensusStageOutcome, IntentionalBoundarySourceCensusStageError>
{
    validate_intentional_boundary_materialization(task, materialization, root)
        .map_err(map_materialization_error)?;
    if inventory.repository != materialization.repository
        || inventory.revision != materialization.revision
    {
        return Err(invalid(
            "intentional-boundary source census inputs disagree on repository identity",
        ));
    }
    match inspect_intentional_boundary_repository_sources_typed(
        &materialization.repository,
        &materialization.revision,
        root,
        inventory,
    )
    .map_err(map_inventory_error)?
    {
        IntentionalBoundarySourceInspection::Excluded(failures) => exclusion(
            task,
            materialization,
            inventory,
            IntentionalBoundarySourceCensusExclusionReason::UnsupportedProjectShape,
            failures,
        )
        .map(IntentionalBoundarySourceCensusStageOutcome::Excluded),
        IntentionalBoundarySourceInspection::Completed(source_census)
            if source_census.source_files.is_empty() =>
        {
            exclusion(
                task,
                materialization,
                inventory,
                IntentionalBoundarySourceCensusExclusionReason::NoSupportedSources,
                Vec::new(),
            )
            .map(IntentionalBoundarySourceCensusStageOutcome::Excluded)
        }
        IntentionalBoundarySourceInspection::Completed(source_census) => {
            let mut stage = IntentionalBoundarySourceCensusStage {
                schema_version: INTENTIONAL_BOUNDARY_SOURCE_CENSUS_STAGE_SCHEMA_VERSION,
                stage_contract: STAGE_CONTRACT.to_string(),
                frame_task_sha256: task.task_sha256.clone(),
                population_rank: materialization.population_rank,
                materialization_sha256: materialization.materialization_sha256.clone(),
                inventory_sha256: inventory.inventory_sha256.clone(),
                source_extension_contract: INTENTIONAL_BOUNDARY_SOURCE_EXTENSION_CONTRACT
                    .to_string(),
                source_census,
                stage_sha256: String::new(),
            };
            stage.stage_sha256 = stage_sha256(&stage)?;
            Ok(IntentionalBoundarySourceCensusStageOutcome::Completed(
                stage,
            ))
        }
    }
}

pub fn validate_intentional_boundary_source_census_stage_outcome(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    outcome: &IntentionalBoundarySourceCensusStageOutcome,
) -> Result<(), IntentionalBoundarySourceCensusStageError> {
    let expected =
        census_intentional_boundary_repository_stage(task, materialization, root, inventory)?;
    if outcome != &expected {
        return Err(invalid(
            "intentional-boundary source census stage outcome changed",
        ));
    }
    Ok(())
}

pub(super) fn validate_committed_source_census_stage(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
    stage: &IntentionalBoundarySourceCensusStage,
) -> Result<(), IntentionalBoundarySourceCensusStageError> {
    validate_intentional_boundary_materialization_commitment(task, materialization)
        .map_err(map_materialization_error)?;
    validate_intentional_boundary_repository_inventory_commitment_typed(
        &materialization.repository,
        &materialization.revision,
        inventory,
    )
    .map_err(map_inventory_error)?;
    validate_source_census_commitment(inventory, &stage.source_census).map_err(invalid)?;
    if stage.schema_version != INTENTIONAL_BOUNDARY_SOURCE_CENSUS_STAGE_SCHEMA_VERSION
        || stage.stage_contract != STAGE_CONTRACT
        || stage.frame_task_sha256 != task.task_sha256
        || stage.population_rank != materialization.population_rank
        || stage.materialization_sha256 != materialization.materialization_sha256
        || stage.inventory_sha256 != inventory.inventory_sha256
        || stage.source_extension_contract != INTENTIONAL_BOUNDARY_SOURCE_EXTENSION_CONTRACT
        || stage.source_census.source_files.is_empty()
        || stage.stage_sha256 != stage_sha256(stage)?
    {
        return Err(invalid(
            "intentional-boundary committed source census stage changed",
        ));
    }
    Ok(())
}

fn exclusion(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
    reason: IntentionalBoundarySourceCensusExclusionReason,
    failures: Vec<IntentionalBoundarySourceCensusFailureEvidence>,
) -> Result<IntentionalBoundarySourceCensusExclusion, IntentionalBoundarySourceCensusStageError> {
    let evidence_matches_reason = match reason {
        IntentionalBoundarySourceCensusExclusionReason::NoSupportedSources => failures.is_empty(),
        IntentionalBoundarySourceCensusExclusionReason::UnsupportedProjectShape => {
            !failures.is_empty()
        }
    };
    if !evidence_matches_reason {
        return Err(invalid(
            "intentional-boundary source exclusion evidence contradicts its reason",
        ));
    }
    let mut exclusion = IntentionalBoundarySourceCensusExclusion {
        schema_version: INTENTIONAL_BOUNDARY_SOURCE_CENSUS_EXCLUSION_SCHEMA_VERSION,
        exclusion_contract: EXCLUSION_CONTRACT.to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        population_rank: materialization.population_rank,
        repository: materialization.repository.clone(),
        revision: materialization.revision.clone(),
        materialization_sha256: materialization.materialization_sha256.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        source_extension_contract: INTENTIONAL_BOUNDARY_SOURCE_EXTENSION_CONTRACT.to_string(),
        reason,
        tracked_entry_count: inventory.tracked_entries.len(),
        failures,
        exclusion_sha256: String::new(),
    };
    exclusion.exclusion_sha256 = exclusion_sha256(&exclusion)?;
    Ok(exclusion)
}

fn stage_sha256(
    value: &IntentionalBoundarySourceCensusStage,
) -> Result<String, IntentionalBoundarySourceCensusStageError> {
    hash_json(&(
        value.schema_version,
        &value.stage_contract,
        &value.frame_task_sha256,
        value.population_rank,
        &value.materialization_sha256,
        &value.inventory_sha256,
        &value.source_extension_contract,
        &value.source_census,
    ))
}

fn exclusion_sha256(
    value: &IntentionalBoundarySourceCensusExclusion,
) -> Result<String, IntentionalBoundarySourceCensusStageError> {
    hash_json(&(
        value.schema_version,
        &value.exclusion_contract,
        &value.frame_task_sha256,
        value.population_rank,
        &value.repository,
        &value.revision,
        &value.materialization_sha256,
        &value.inventory_sha256,
        &value.source_extension_contract,
        value.reason,
        value.tracked_entry_count,
        &value.failures,
    ))
}

fn hash_json(value: &impl Serialize) -> Result<String, IntentionalBoundarySourceCensusStageError> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| invalid(format!("failed to commit source census stage: {error}")))
}

fn map_materialization_error(
    error: IntentionalBoundaryMaterializationError,
) -> IntentionalBoundarySourceCensusStageError {
    IntentionalBoundarySourceCensusStageError {
        kind: match error.kind {
            IntentionalBoundaryMaterializationErrorKind::InvalidInput => {
                IntentionalBoundarySourceCensusStageErrorKind::InvalidInput
            }
            IntentionalBoundaryMaterializationErrorKind::InfrastructureUnavailable => {
                IntentionalBoundarySourceCensusStageErrorKind::InfrastructureUnavailable
            }
            IntentionalBoundaryMaterializationErrorKind::InfrastructureFailed => {
                IntentionalBoundarySourceCensusStageErrorKind::InfrastructureFailed
            }
        },
        detail: error.detail,
    }
}

fn map_inventory_error(
    error: IntentionalBoundaryInventoryError,
) -> IntentionalBoundarySourceCensusStageError {
    IntentionalBoundarySourceCensusStageError {
        kind: match error.kind {
            IntentionalBoundaryInventoryErrorKind::InvalidInput => {
                IntentionalBoundarySourceCensusStageErrorKind::InvalidInput
            }
            IntentionalBoundaryInventoryErrorKind::InfrastructureUnavailable => {
                IntentionalBoundarySourceCensusStageErrorKind::InfrastructureUnavailable
            }
            IntentionalBoundaryInventoryErrorKind::InfrastructureFailed => {
                IntentionalBoundarySourceCensusStageErrorKind::InfrastructureFailed
            }
        },
        detail: error.detail,
    }
}

fn invalid(detail: impl Into<String>) -> IntentionalBoundarySourceCensusStageError {
    IntentionalBoundarySourceCensusStageError {
        kind: IntentionalBoundarySourceCensusStageErrorKind::InvalidInput,
        detail: detail.into(),
    }
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_source_census_stage_tests.rs"]
mod tests;
