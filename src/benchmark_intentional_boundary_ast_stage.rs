use super::intentional_boundary_ast_commitment::validate_ast_census_commitment;
use super::intentional_boundary_ast_stage_support::{
    ResolvedAstRun, derive_repository_ast_runs, failure_key, resolve_ast_runs,
};
use super::intentional_boundary_source_census::intentional_boundary_file_records_typed;
use super::{
    INTENTIONAL_BOUNDARY_AST_CENSUS_EXCLUSION_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_AST_CENSUS_STAGE_SCHEMA_VERSION, IntentionalBoundaryAstCensusExclusion,
    IntentionalBoundaryAstCensusStage, IntentionalBoundaryAstCensusStageError,
    IntentionalBoundaryAstCensusStageErrorKind, IntentionalBoundaryAstCensusStageOutcome,
    IntentionalBoundaryFrameTask, IntentionalBoundaryInventoryError,
    IntentionalBoundaryInventoryErrorKind, IntentionalBoundaryLicenseCensusStage,
    IntentionalBoundaryMaterialization, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticCensusStage, IntentionalBoundarySemanticCensusStageError,
    IntentionalBoundarySemanticCensusStageErrorKind, IntentionalBoundarySourceCensusStage,
    validate_committed_semantic_census_stage,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;

const STAGE_CONTRACT: &str = "sniffbench-intentional-boundary-ast-census-stage-v1";
const EXCLUSION_CONTRACT: &str = "sniffbench-intentional-boundary-ast-census-exclusion-v1";

#[allow(clippy::too_many_arguments)]
pub async fn census_intentional_boundary_ast_stage(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    semantic_census: &IntentionalBoundarySemanticCensusStage,
) -> Result<IntentionalBoundaryAstCensusStageOutcome, IntentionalBoundaryAstCensusStageError> {
    validate_semantic_census(
        task,
        materialization,
        inventory,
        source_census,
        license_census,
        semantic_census,
    )?;
    let files =
        intentional_boundary_file_records_typed(root, inventory, &source_census.source_census)
            .map_err(map_inventory_error)?;
    let runs = derive_repository_ast_runs(
        &source_census.source_census,
        &semantic_census.semantic_census,
        &files,
    );
    finish_ast_stage(
        task,
        materialization,
        inventory,
        source_census,
        license_census,
        semantic_census,
        runs,
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn validate_intentional_boundary_ast_census_stage_outcome(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    semantic_census: &IntentionalBoundarySemanticCensusStage,
    outcome: &IntentionalBoundaryAstCensusStageOutcome,
) -> Result<(), IntentionalBoundaryAstCensusStageError> {
    let expected = census_intentional_boundary_ast_stage(
        task,
        materialization,
        root,
        inventory,
        source_census,
        license_census,
        semantic_census,
    )
    .await?;
    if outcome != &expected {
        return Err(invalid(
            "intentional-boundary AST census stage outcome changed",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_committed_ast_census_stage(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    semantic_census: &IntentionalBoundarySemanticCensusStage,
    stage: &IntentionalBoundaryAstCensusStage,
) -> Result<(), IntentionalBoundaryAstCensusStageError> {
    validate_semantic_census(
        task,
        materialization,
        inventory,
        source_census,
        license_census,
        semantic_census,
    )?;
    for census in &stage.ast_censuses {
        validate_ast_census_commitment(
            &source_census.source_census,
            &semantic_census.semantic_census,
            census,
        )
        .map_err(invalid)?;
    }
    let expected_languages = source_census
        .source_census
        .source_files
        .iter()
        .map(|file| file.language.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let census_languages = stage
        .ast_censuses
        .iter()
        .filter_map(|census| census.languages.first().cloned())
        .collect::<Vec<_>>();
    if stage.schema_version != INTENTIONAL_BOUNDARY_AST_CENSUS_STAGE_SCHEMA_VERSION
        || stage.stage_contract != STAGE_CONTRACT
        || stage.frame_task_sha256 != task.task_sha256
        || stage.population_rank != materialization.population_rank
        || stage.materialization_sha256 != materialization.materialization_sha256
        || stage.inventory_sha256 != inventory.inventory_sha256
        || stage.source_census_stage_sha256 != source_census.stage_sha256
        || stage.license_census_stage_sha256 != license_census.stage_sha256
        || stage.semantic_census_stage_sha256 != semantic_census.stage_sha256
        || stage.languages != expected_languages
        || stage
            .ast_censuses
            .iter()
            .any(|census| census.languages.len() != 1)
        || census_languages != stage.languages
        || stage.stage_sha256 != stage_sha256(stage)?
    {
        return Err(invalid(
            "intentional-boundary committed AST census stage changed",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn finish_ast_stage(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    semantic_census: &IntentionalBoundarySemanticCensusStage,
    runs: Vec<
        Result<
            super::IntentionalBoundaryAstCensus,
            super::intentional_boundary_ast_outcome::AstDerivationError,
        >,
    >,
) -> Result<IntentionalBoundaryAstCensusStageOutcome, IntentionalBoundaryAstCensusStageError> {
    match resolve_ast_runs(runs)? {
        ResolvedAstRun::Completed(ast_censuses) => completion(
            task,
            materialization,
            inventory,
            source_census,
            license_census,
            semantic_census,
            ast_censuses,
        )
        .map(IntentionalBoundaryAstCensusStageOutcome::Completed),
        ResolvedAstRun::Excluded(failures) => exclusion(
            task,
            materialization,
            inventory,
            source_census,
            license_census,
            semantic_census,
            failures,
        )
        .map(IntentionalBoundaryAstCensusStageOutcome::Excluded),
    }
}

#[allow(clippy::too_many_arguments)]
fn completion(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    semantic_census: &IntentionalBoundarySemanticCensusStage,
    ast_censuses: Vec<super::IntentionalBoundaryAstCensus>,
) -> Result<IntentionalBoundaryAstCensusStage, IntentionalBoundaryAstCensusStageError> {
    let languages = ast_censuses
        .iter()
        .map(|census| {
            census.languages.first().cloned().ok_or_else(|| {
                invalid("intentional-boundary AST completion has no census language")
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expected_languages = source_census
        .source_census
        .source_files
        .iter()
        .map(|file| file.language.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if languages != expected_languages {
        return Err(invalid(
            "intentional-boundary AST completion omitted or invented a source language",
        ));
    }
    let mut stage = IntentionalBoundaryAstCensusStage {
        schema_version: INTENTIONAL_BOUNDARY_AST_CENSUS_STAGE_SCHEMA_VERSION,
        stage_contract: STAGE_CONTRACT.to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        population_rank: materialization.population_rank,
        materialization_sha256: materialization.materialization_sha256.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        source_census_stage_sha256: source_census.stage_sha256.clone(),
        license_census_stage_sha256: license_census.stage_sha256.clone(),
        semantic_census_stage_sha256: semantic_census.stage_sha256.clone(),
        languages,
        ast_censuses,
        stage_sha256: String::new(),
    };
    stage.stage_sha256 = stage_sha256(&stage)?;
    Ok(stage)
}

#[allow(clippy::too_many_arguments)]
fn exclusion(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    semantic_census: &IntentionalBoundarySemanticCensusStage,
    mut failures: Vec<super::IntentionalBoundaryAstCensusFailureEvidence>,
) -> Result<IntentionalBoundaryAstCensusExclusion, IntentionalBoundaryAstCensusStageError> {
    if failures.is_empty() {
        return Err(invalid(
            "intentional-boundary AST exclusion requires failure evidence",
        ));
    }
    failures.sort_by(failure_key);
    let reasons = failures
        .iter()
        .map(|failure| failure.reason)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut exclusion = IntentionalBoundaryAstCensusExclusion {
        schema_version: INTENTIONAL_BOUNDARY_AST_CENSUS_EXCLUSION_SCHEMA_VERSION,
        exclusion_contract: EXCLUSION_CONTRACT.to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        population_rank: materialization.population_rank,
        repository: materialization.repository.clone(),
        revision: materialization.revision.clone(),
        materialization_sha256: materialization.materialization_sha256.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        source_census_stage_sha256: source_census.stage_sha256.clone(),
        license_census_stage_sha256: license_census.stage_sha256.clone(),
        semantic_census_stage_sha256: semantic_census.stage_sha256.clone(),
        reasons,
        failures,
        exclusion_sha256: String::new(),
    };
    exclusion.exclusion_sha256 = exclusion_sha256(&exclusion)?;
    Ok(exclusion)
}

#[allow(clippy::too_many_arguments)]
fn validate_semantic_census(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    semantic_census: &IntentionalBoundarySemanticCensusStage,
) -> Result<(), IntentionalBoundaryAstCensusStageError> {
    validate_committed_semantic_census_stage(
        task,
        materialization,
        inventory,
        source_census,
        license_census,
        semantic_census,
    )
    .map_err(map_semantic_error)
}

fn stage_sha256(
    value: &IntentionalBoundaryAstCensusStage,
) -> Result<String, IntentionalBoundaryAstCensusStageError> {
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
        &value.languages,
        &value.ast_censuses,
    ))
}

fn exclusion_sha256(
    value: &IntentionalBoundaryAstCensusExclusion,
) -> Result<String, IntentionalBoundaryAstCensusStageError> {
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
        &value.semantic_census_stage_sha256,
        &value.reasons,
        &value.failures,
    ))
}

fn hash_json(value: &impl Serialize) -> Result<String, IntentionalBoundaryAstCensusStageError> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| invalid(format!("failed to commit AST census stage: {error}")))
}

fn map_semantic_error(
    error: IntentionalBoundarySemanticCensusStageError,
) -> IntentionalBoundaryAstCensusStageError {
    IntentionalBoundaryAstCensusStageError {
        kind: match error.kind {
            IntentionalBoundarySemanticCensusStageErrorKind::InvalidInput => {
                IntentionalBoundaryAstCensusStageErrorKind::InvalidInput
            }
            IntentionalBoundarySemanticCensusStageErrorKind::InfrastructureUnavailable => {
                IntentionalBoundaryAstCensusStageErrorKind::InfrastructureUnavailable
            }
            IntentionalBoundarySemanticCensusStageErrorKind::InfrastructureFailed => {
                IntentionalBoundaryAstCensusStageErrorKind::InfrastructureFailed
            }
        },
        detail: error.detail,
    }
}

fn map_inventory_error(
    error: IntentionalBoundaryInventoryError,
) -> IntentionalBoundaryAstCensusStageError {
    IntentionalBoundaryAstCensusStageError {
        kind: match error.kind {
            IntentionalBoundaryInventoryErrorKind::InvalidInput => {
                IntentionalBoundaryAstCensusStageErrorKind::InvalidInput
            }
            IntentionalBoundaryInventoryErrorKind::InfrastructureUnavailable => {
                IntentionalBoundaryAstCensusStageErrorKind::InfrastructureUnavailable
            }
            IntentionalBoundaryInventoryErrorKind::InfrastructureFailed => {
                IntentionalBoundaryAstCensusStageErrorKind::InfrastructureFailed
            }
        },
        detail: error.detail,
    }
}

fn invalid(detail: impl Into<String>) -> IntentionalBoundaryAstCensusStageError {
    IntentionalBoundaryAstCensusStageError {
        kind: IntentionalBoundaryAstCensusStageErrorKind::InvalidInput,
        detail: detail.into(),
    }
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_ast_stage_tests.rs"]
mod tests;
