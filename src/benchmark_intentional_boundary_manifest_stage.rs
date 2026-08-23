use super::intentional_boundary_manifest::{
    census_intentional_boundary_manifests_typed, validate_manifest_census_commitment,
};
use super::intentional_boundary_manifest_binding::bind_intentional_boundary_manifests_typed;
use super::intentional_boundary_manifest_stage_support::{
    ManifestPreflight, failure_key, preflight_manifest_entries, resolve_manifest_errors,
};
use super::{
    INTENTIONAL_BOUNDARY_MANIFEST_EXCLUSION_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_MANIFEST_STAGE_SCHEMA_VERSION, IntentionalBoundaryAstCensusStage,
    IntentionalBoundaryAstCensusStageError, IntentionalBoundaryAstCensusStageErrorKind,
    IntentionalBoundaryFrameTask, IntentionalBoundaryLicenseCensusStage,
    IntentionalBoundaryManifestBindingCensus, IntentionalBoundaryManifestCensus,
    IntentionalBoundaryManifestExclusion, IntentionalBoundaryManifestFailureEvidence,
    IntentionalBoundaryManifestStage, IntentionalBoundaryManifestStageError,
    IntentionalBoundaryManifestStageErrorKind, IntentionalBoundaryManifestStageOutcome,
    IntentionalBoundaryMaterialization, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticCensusStage, IntentionalBoundarySourceCensusStage,
    validate_committed_ast_census_stage, validate_intentional_boundary_manifest_bindings,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;

const STAGE_CONTRACT: &str = "sniffbench-intentional-boundary-manifest-stage-v1";
const EXCLUSION_CONTRACT: &str = "sniffbench-intentional-boundary-manifest-exclusion-v1";

#[allow(clippy::too_many_arguments)]
pub async fn census_intentional_boundary_manifest_stage(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    semantic_census: &IntentionalBoundarySemanticCensusStage,
    ast_census: &IntentionalBoundaryAstCensusStage,
) -> Result<IntentionalBoundaryManifestStageOutcome, IntentionalBoundaryManifestStageError> {
    validate_ast_census(
        task,
        materialization,
        inventory,
        source_census,
        license_census,
        semantic_census,
        ast_census,
    )?;
    let preflight = preflight_manifest_entries(root, inventory);
    if !preflight.is_empty() {
        return finish_manifest_stage(
            task,
            materialization,
            inventory,
            source_census,
            license_census,
            semantic_census,
            ast_census,
            Err(preflight),
        );
    }
    let manifest_census = match census_intentional_boundary_manifests_typed(
        &materialization.repository,
        &materialization.revision,
        root,
        inventory,
    ) {
        Ok(census) => census,
        Err(error) => {
            return finish_manifest_stage(
                task,
                materialization,
                inventory,
                source_census,
                license_census,
                semantic_census,
                ast_census,
                Err(vec![error]),
            );
        }
    };
    let binding_census = match bind_intentional_boundary_manifests_typed(
        &source_census.source_census,
        &semantic_census.semantic_census,
        &manifest_census,
    ) {
        Ok(census) => census,
        Err(error) => {
            return finish_manifest_stage(
                task,
                materialization,
                inventory,
                source_census,
                license_census,
                semantic_census,
                ast_census,
                Err(vec![error]),
            );
        }
    };
    finish_manifest_stage(
        task,
        materialization,
        inventory,
        source_census,
        license_census,
        semantic_census,
        ast_census,
        Ok((manifest_census, binding_census)),
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn validate_intentional_boundary_manifest_stage_outcome(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    semantic_census: &IntentionalBoundarySemanticCensusStage,
    ast_census: &IntentionalBoundaryAstCensusStage,
    outcome: &IntentionalBoundaryManifestStageOutcome,
) -> Result<(), IntentionalBoundaryManifestStageError> {
    let expected = census_intentional_boundary_manifest_stage(
        task,
        materialization,
        root,
        inventory,
        source_census,
        license_census,
        semantic_census,
        ast_census,
    )
    .await?;
    if outcome != &expected {
        return Err(invalid(
            "intentional-boundary manifest stage outcome changed",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_committed_manifest_stage(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    semantic_census: &IntentionalBoundarySemanticCensusStage,
    ast_census: &IntentionalBoundaryAstCensusStage,
    stage: &IntentionalBoundaryManifestStage,
) -> Result<(), IntentionalBoundaryManifestStageError> {
    validate_ast_census(
        task,
        materialization,
        inventory,
        source_census,
        license_census,
        semantic_census,
        ast_census,
    )?;
    validate_manifest_census_commitment(
        inventory.inventory_sha256.as_str(),
        &stage.manifest_census,
    )
    .map_err(invalid)?;
    validate_intentional_boundary_manifest_bindings(
        &source_census.source_census,
        &semantic_census.semantic_census,
        &stage.manifest_census,
        &stage.binding_census,
    )
    .map_err(invalid)?;
    if stage.schema_version != INTENTIONAL_BOUNDARY_MANIFEST_STAGE_SCHEMA_VERSION
        || stage.stage_contract != STAGE_CONTRACT
        || stage.frame_task_sha256 != task.task_sha256
        || stage.population_rank != materialization.population_rank
        || stage.materialization_sha256 != materialization.materialization_sha256
        || stage.inventory_sha256 != inventory.inventory_sha256
        || stage.source_census_stage_sha256 != source_census.stage_sha256
        || stage.license_census_stage_sha256 != license_census.stage_sha256
        || stage.semantic_census_stage_sha256 != semantic_census.stage_sha256
        || stage.ast_census_stage_sha256 != ast_census.stage_sha256
        || stage.manifest_census.repository != materialization.repository
        || stage.manifest_census.revision != materialization.revision
        || stage.stage_sha256 != stage_sha256(stage)?
    {
        return Err(invalid(
            "intentional-boundary committed manifest stage changed",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn finish_manifest_stage(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    semantic_census: &IntentionalBoundarySemanticCensusStage,
    ast_census: &IntentionalBoundaryAstCensusStage,
    result: Result<
        (
            IntentionalBoundaryManifestCensus,
            IntentionalBoundaryManifestBindingCensus,
        ),
        Vec<super::intentional_boundary_manifest_outcome::ManifestDerivationError>,
    >,
) -> Result<IntentionalBoundaryManifestStageOutcome, IntentionalBoundaryManifestStageError> {
    match result {
        Ok((manifest_census, binding_census)) => completion(
            task,
            materialization,
            inventory,
            source_census,
            license_census,
            semantic_census,
            ast_census,
            manifest_census,
            binding_census,
        )
        .map(Box::new)
        .map(IntentionalBoundaryManifestStageOutcome::Completed),
        Err(errors) => match resolve_manifest_errors(errors)? {
            ManifestPreflight::Excluded(failures) => exclusion(
                task,
                materialization,
                inventory,
                source_census,
                license_census,
                semantic_census,
                ast_census,
                failures,
            )
            .map(Box::new)
            .map(IntentionalBoundaryManifestStageOutcome::Excluded),
            ManifestPreflight::Clear => Err(invalid(
                "intentional-boundary manifest stage received an empty failure set",
            )),
        },
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
    ast_census: &IntentionalBoundaryAstCensusStage,
    manifest_census: IntentionalBoundaryManifestCensus,
    binding_census: IntentionalBoundaryManifestBindingCensus,
) -> Result<IntentionalBoundaryManifestStage, IntentionalBoundaryManifestStageError> {
    if manifest_census.repository != materialization.repository
        || manifest_census.revision != materialization.revision
        || manifest_census.inventory_sha256 != inventory.inventory_sha256
        || binding_census.repository != materialization.repository
        || binding_census.revision != materialization.revision
        || binding_census.manifest_census_sha256 != manifest_census.manifest_census_sha256
        || binding_census.source_census_sha256 != source_census.source_census.census_sha256
        || binding_census.semantic_census_sha256
            != semantic_census.semantic_census.semantic_census_sha256
    {
        return Err(invalid(
            "intentional-boundary manifest completion changed producer lineage",
        ));
    }
    let mut stage = IntentionalBoundaryManifestStage {
        schema_version: INTENTIONAL_BOUNDARY_MANIFEST_STAGE_SCHEMA_VERSION,
        stage_contract: STAGE_CONTRACT.to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        population_rank: materialization.population_rank,
        materialization_sha256: materialization.materialization_sha256.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        source_census_stage_sha256: source_census.stage_sha256.clone(),
        license_census_stage_sha256: license_census.stage_sha256.clone(),
        semantic_census_stage_sha256: semantic_census.stage_sha256.clone(),
        ast_census_stage_sha256: ast_census.stage_sha256.clone(),
        manifest_census,
        binding_census,
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
    ast_census: &IntentionalBoundaryAstCensusStage,
    mut failures: Vec<IntentionalBoundaryManifestFailureEvidence>,
) -> Result<IntentionalBoundaryManifestExclusion, IntentionalBoundaryManifestStageError> {
    if failures.is_empty() {
        return Err(invalid(
            "intentional-boundary manifest exclusion requires failure evidence",
        ));
    }
    failures.sort_by(failure_key);
    let reasons = failures
        .iter()
        .map(|failure| failure.reason)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut exclusion = IntentionalBoundaryManifestExclusion {
        schema_version: INTENTIONAL_BOUNDARY_MANIFEST_EXCLUSION_SCHEMA_VERSION,
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
        ast_census_stage_sha256: ast_census.stage_sha256.clone(),
        reasons,
        failures,
        exclusion_sha256: String::new(),
    };
    exclusion.exclusion_sha256 = exclusion_sha256(&exclusion)?;
    Ok(exclusion)
}

#[allow(clippy::too_many_arguments)]
fn validate_ast_census(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    semantic_census: &IntentionalBoundarySemanticCensusStage,
    ast_census: &IntentionalBoundaryAstCensusStage,
) -> Result<(), IntentionalBoundaryManifestStageError> {
    validate_committed_ast_census_stage(
        task,
        materialization,
        inventory,
        source_census,
        license_census,
        semantic_census,
        ast_census,
    )
    .map_err(map_ast_error)
}

fn stage_sha256(
    value: &IntentionalBoundaryManifestStage,
) -> Result<String, IntentionalBoundaryManifestStageError> {
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
        &value.manifest_census,
        &value.binding_census,
    ))
}

fn exclusion_sha256(
    value: &IntentionalBoundaryManifestExclusion,
) -> Result<String, IntentionalBoundaryManifestStageError> {
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
        &value.ast_census_stage_sha256,
        &value.reasons,
        &value.failures,
    ))
}

fn hash_json(value: &impl Serialize) -> Result<String, IntentionalBoundaryManifestStageError> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| invalid(format!("failed to commit manifest stage: {error}")))
}

fn map_ast_error(
    error: IntentionalBoundaryAstCensusStageError,
) -> IntentionalBoundaryManifestStageError {
    IntentionalBoundaryManifestStageError {
        kind: match error.kind {
            IntentionalBoundaryAstCensusStageErrorKind::InvalidInput => {
                IntentionalBoundaryManifestStageErrorKind::InvalidInput
            }
            IntentionalBoundaryAstCensusStageErrorKind::InfrastructureUnavailable => {
                IntentionalBoundaryManifestStageErrorKind::InfrastructureUnavailable
            }
            IntentionalBoundaryAstCensusStageErrorKind::InfrastructureFailed => {
                IntentionalBoundaryManifestStageErrorKind::InfrastructureFailed
            }
        },
        detail: error.detail,
    }
}

fn invalid(detail: impl Into<String>) -> IntentionalBoundaryManifestStageError {
    IntentionalBoundaryManifestStageError {
        kind: IntentionalBoundaryManifestStageErrorKind::InvalidInput,
        detail: detail.into(),
    }
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_manifest_stage_tests.rs"]
mod tests;
