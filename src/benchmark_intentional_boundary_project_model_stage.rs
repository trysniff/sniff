use super::intentional_boundary_project_model_cargo::census_intentional_boundary_cargo_project_models_typed;
use super::intentional_boundary_project_model_go::census_intentional_boundary_go_project_models_typed;
use super::intentional_boundary_project_model_gradle::census_intentional_boundary_gradle_project_models_typed;
#[cfg(test)]
use super::intentional_boundary_project_model_stage_commitment::{
    PROJECT_MODEL_BINDING_INPUT, PROJECT_MODEL_INPUT,
};
use super::intentional_boundary_project_model_stage_commitment::{
    exclusion_sha256, map_evidence_error, stage_sha256, validate_completion_lineage,
};
use super::intentional_boundary_project_model_stage_support::{
    ProjectModelProviderRun, ResolvedProjectModelRun, failure_key, resolve_project_model_runs,
};
use super::{
    INTENTIONAL_BOUNDARY_PROJECT_MODEL_EXCLUSION_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_PROJECT_MODEL_STAGE_SCHEMA_VERSION, IntentionalBoundaryAstCensusStage,
    IntentionalBoundaryEvidenceStage, IntentionalBoundaryFrameTask,
    IntentionalBoundaryLicenseCensusStage, IntentionalBoundaryManifestProvider,
    IntentionalBoundaryManifestStage, IntentionalBoundaryMaterialization,
    IntentionalBoundaryProjectModelExclusion, IntentionalBoundaryProjectModelFailureEvidence,
    IntentionalBoundaryProjectModelProvider, IntentionalBoundaryProjectModelStage,
    IntentionalBoundaryProjectModelStageError, IntentionalBoundaryProjectModelStageErrorKind,
    IntentionalBoundaryProjectModelStageOutcome, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticCensusStage, IntentionalBoundarySourceCensusStage,
    bind_intentional_boundary_project_models, compose_intentional_boundary_project_model_evidence,
    validate_intentional_boundary_evidence_stage,
};
use std::collections::BTreeSet;
use std::path::Path;

const STAGE_CONTRACT: &str = "sniffbench-intentional-boundary-project-model-stage-v1";
const EXCLUSION_CONTRACT: &str = "sniffbench-intentional-boundary-project-model-exclusion-v1";

#[allow(clippy::too_many_arguments)]
pub async fn census_intentional_boundary_project_model_stage(
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
) -> Result<IntentionalBoundaryProjectModelStageOutcome, IntentionalBoundaryProjectModelStageError>
{
    validate_base_evidence(
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
    )
    .await?;
    let required_providers = manifest_required_providers(manifest_stage);
    let runs = collect_provider_runs(
        &required_providers,
        &materialization.repository,
        &materialization.revision,
        root,
        inventory,
    );
    finish_project_model_stage(
        task,
        materialization,
        inventory,
        source_census,
        license_census,
        semantic_census,
        ast_census,
        manifest_stage,
        base_evidence_stage,
        required_providers,
        runs,
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn validate_intentional_boundary_project_model_stage_outcome(
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
    outcome: &IntentionalBoundaryProjectModelStageOutcome,
) -> Result<(), IntentionalBoundaryProjectModelStageError> {
    let expected = census_intentional_boundary_project_model_stage(
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
    )
    .await?;
    if outcome != &expected {
        return Err(invalid("intentional-boundary project-model stage changed"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn finish_project_model_stage(
    task: &IntentionalBoundaryFrameTask,
    materialization: &IntentionalBoundaryMaterialization,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensusStage,
    license_census: &IntentionalBoundaryLicenseCensusStage,
    semantic_census: &IntentionalBoundarySemanticCensusStage,
    ast_census: &IntentionalBoundaryAstCensusStage,
    manifest_stage: &IntentionalBoundaryManifestStage,
    base_evidence_stage: &IntentionalBoundaryEvidenceStage,
    required_providers: Vec<IntentionalBoundaryProjectModelProvider>,
    runs: Vec<ProjectModelProviderRun>,
) -> Result<IntentionalBoundaryProjectModelStageOutcome, IntentionalBoundaryProjectModelStageError>
{
    if required_providers.windows(2).any(|pair| pair[0] >= pair[1])
        || required_providers != manifest_required_providers(manifest_stage)
        || runs
            .iter()
            .map(|(provider, _)| *provider)
            .collect::<Vec<_>>()
            != required_providers
    {
        return Err(invalid(
            "project-model required providers and producer runs changed",
        ));
    }
    match resolve_project_model_runs(inventory, runs)? {
        ResolvedProjectModelRun::Completed(project_model_census) => completion(
            task,
            materialization,
            inventory,
            source_census,
            license_census,
            semantic_census,
            ast_census,
            manifest_stage,
            base_evidence_stage,
            required_providers,
            project_model_census,
        )
        .map(Box::new)
        .map(IntentionalBoundaryProjectModelStageOutcome::Completed),
        ResolvedProjectModelRun::Excluded(failures) => exclusion(
            task,
            materialization,
            inventory,
            source_census,
            license_census,
            semantic_census,
            ast_census,
            manifest_stage,
            base_evidence_stage,
            required_providers,
            failures,
        )
        .map(Box::new)
        .map(IntentionalBoundaryProjectModelStageOutcome::Excluded),
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
    manifest_stage: &IntentionalBoundaryManifestStage,
    base_evidence_stage: &IntentionalBoundaryEvidenceStage,
    required_providers: Vec<IntentionalBoundaryProjectModelProvider>,
    project_model_census: super::IntentionalBoundaryProjectModelCensus,
) -> Result<IntentionalBoundaryProjectModelStage, IntentionalBoundaryProjectModelStageError> {
    let binding_census = bind_intentional_boundary_project_models(
        inventory,
        &source_census.source_census,
        &semantic_census.semantic_census,
        &project_model_census,
    )
    .map_err(invalid)?;
    let evidence_census = compose_intentional_boundary_project_model_evidence(
        inventory,
        &source_census.source_census,
        &semantic_census.semantic_census,
        &project_model_census,
        &binding_census,
        base_evidence_stage.evidence_census.clone(),
    )
    .map_err(invalid)?;
    validate_completion_lineage(
        materialization,
        inventory,
        source_census,
        semantic_census,
        manifest_stage,
        base_evidence_stage,
        &required_providers,
        &project_model_census,
        &binding_census,
        &evidence_census,
    )?;
    let mut stage = IntentionalBoundaryProjectModelStage {
        schema_version: INTENTIONAL_BOUNDARY_PROJECT_MODEL_STAGE_SCHEMA_VERSION,
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
        required_providers,
        project_model_census,
        binding_census,
        evidence_census,
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
    manifest_stage: &IntentionalBoundaryManifestStage,
    base_evidence_stage: &IntentionalBoundaryEvidenceStage,
    required_providers: Vec<IntentionalBoundaryProjectModelProvider>,
    mut failures: Vec<IntentionalBoundaryProjectModelFailureEvidence>,
) -> Result<IntentionalBoundaryProjectModelExclusion, IntentionalBoundaryProjectModelStageError> {
    let required = required_providers.iter().copied().collect::<BTreeSet<_>>();
    if failures.is_empty()
        || required.is_empty()
        || failures
            .iter()
            .any(|failure| !required.contains(&failure.provider))
    {
        return Err(invalid(
            "project-model exclusion changed required provider evidence",
        ));
    }
    failures.sort_by(failure_key);
    let reasons = failures
        .iter()
        .map(|failure| failure.reason)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut exclusion = IntentionalBoundaryProjectModelExclusion {
        schema_version: INTENTIONAL_BOUNDARY_PROJECT_MODEL_EXCLUSION_SCHEMA_VERSION,
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
        manifest_stage_sha256: manifest_stage.stage_sha256.clone(),
        base_evidence_stage_sha256: base_evidence_stage.stage_sha256.clone(),
        required_providers,
        reasons,
        failures,
        exclusion_sha256: String::new(),
    };
    exclusion.exclusion_sha256 = exclusion_sha256(&exclusion)?;
    Ok(exclusion)
}

fn manifest_required_providers(
    manifest_stage: &IntentionalBoundaryManifestStage,
) -> Vec<IntentionalBoundaryProjectModelProvider> {
    manifest_stage
        .manifest_census
        .documents
        .iter()
        .filter_map(|document| match document.provider {
            IntentionalBoundaryManifestProvider::CargoManifest => {
                Some(IntentionalBoundaryProjectModelProvider::CargoMetadata)
            }
            IntentionalBoundaryManifestProvider::GoPackageMetadata => {
                Some(IntentionalBoundaryProjectModelProvider::GoList)
            }
            IntentionalBoundaryManifestProvider::GradleProjectModel => {
                Some(IntentionalBoundaryProjectModelProvider::GradleToolingApi)
            }
            IntentionalBoundaryManifestProvider::NodePackageManifest
            | IntentionalBoundaryManifestProvider::PythonProjectManifest
            | IntentionalBoundaryManifestProvider::GoGenerateSource => None,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn collect_provider_runs(
    providers: &[IntentionalBoundaryProjectModelProvider],
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Vec<ProjectModelProviderRun> {
    providers
        .iter()
        .map(|provider| {
            let run = match provider {
                IntentionalBoundaryProjectModelProvider::CargoMetadata => {
                    census_intentional_boundary_cargo_project_models_typed(
                        repository, revision, root, inventory,
                    )
                }
                IntentionalBoundaryProjectModelProvider::GoList => {
                    census_intentional_boundary_go_project_models_typed(
                        repository, revision, root, inventory,
                    )
                }
                IntentionalBoundaryProjectModelProvider::GradleToolingApi => {
                    census_intentional_boundary_gradle_project_models_typed(
                        repository, revision, root, inventory,
                    )
                }
            };
            (*provider, run)
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
async fn validate_base_evidence(
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
) -> Result<(), IntentionalBoundaryProjectModelStageError> {
    validate_intentional_boundary_evidence_stage(
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
    )
    .await
    .map_err(map_evidence_error)
}

fn invalid(detail: impl Into<String>) -> IntentionalBoundaryProjectModelStageError {
    IntentionalBoundaryProjectModelStageError {
        kind: IntentionalBoundaryProjectModelStageErrorKind::InvalidInput,
        detail: detail.into(),
    }
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_project_model_stage_tests.rs"]
mod tests;
