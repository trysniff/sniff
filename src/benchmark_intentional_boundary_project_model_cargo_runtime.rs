use super::super::IntentionalBoundaryProjectModelFailurePhase;
use super::super::intentional_boundary_project_model_outcome::{
    ProjectModelDerivationError, ProjectModelDerivationErrorKind, legacy_project_model_error,
    project_model_error, project_model_process_error, project_model_runtime_plan_error,
    project_model_sandbox_error,
};
use super::super::intentional_boundary_runtime_snapshot::{
    IntentionalBoundaryRuntimeSnapshot, allocate_runtime_directory,
};
use super::super::non_blind_history_runtime::prepare_historical_runtime;
use super::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const CARGO_METADATA_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const CARGO_METADATA_OUTPUT_LIMIT: usize = 16 * 1024 * 1024;

struct CargoMetadataCallRuntime(PathBuf);

impl CargoMetadataCallRuntime {
    fn create(root: &Path) -> Result<Self, String> {
        allocate_runtime_directory(root, ".sniff-cargo-metadata-call").map(Self)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for CargoMetadataCallRuntime {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(super) struct CargoMetadataExecutionOutput {
    pub(super) toolchain_identity_sha256: String,
    pub(super) stdout: String,
}

pub fn census_intentional_boundary_cargo_project_models(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Result<IntentionalBoundaryProjectModelCensus, String> {
    census_intentional_boundary_cargo_project_models_typed(repository, revision, root, inventory)
        .map_err(legacy_project_model_error)
}

pub(in crate::benchmark::release) fn census_intentional_boundary_cargo_project_models_typed(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Result<IntentionalBoundaryProjectModelCensus, ProjectModelDerivationError> {
    validate_intentional_boundary_repository_inventory(repository, revision, root, inventory)
        .map_err(|detail| {
            cargo_error(
                ProjectModelDerivationErrorKind::InvalidInput,
                IntentionalBoundaryProjectModelFailurePhase::RepositoryValidation,
                None,
                detail,
            )
        })?;
    let snapshot =
        IntentionalBoundaryRuntimeSnapshot::create(root, revision, "sniff-cargo-metadata-snapshot")
            .map_err(|detail| {
                cargo_error(
                    ProjectModelDerivationErrorKind::InfrastructureFailed,
                    IntentionalBoundaryProjectModelFailurePhase::SnapshotPreparation,
                    None,
                    detail,
                )
            })?;
    census_cargo_project_models_at_execution_root(
        repository,
        revision,
        root,
        snapshot.path(),
        inventory,
        run_cargo_metadata,
    )
}

#[cfg(test)]
pub(super) fn census_cargo_project_models_with_executor<F>(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    executor: F,
) -> Result<IntentionalBoundaryProjectModelCensus, String>
where
    F: FnMut(&Path, &str) -> Result<CargoMetadataExecutionOutput, String>,
{
    let mut executor = executor;
    census_cargo_project_models_at_execution_root(
        repository,
        revision,
        root,
        root,
        inventory,
        |execution_root, manifest_path| {
            executor(execution_root, manifest_path).map_err(|detail| {
                cargo_error(
                    ProjectModelDerivationErrorKind::InfrastructureFailed,
                    IntentionalBoundaryProjectModelFailurePhase::Execution,
                    Some(manifest_path),
                    detail,
                )
            })
        },
    )
    .map_err(legacy_project_model_error)
}

fn census_cargo_project_models_at_execution_root<F>(
    repository: &str,
    revision: &str,
    immutable_root: &Path,
    execution_root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    mut executor: F,
) -> Result<IntentionalBoundaryProjectModelCensus, ProjectModelDerivationError>
where
    F: FnMut(&Path, &str) -> Result<CargoMetadataExecutionOutput, ProjectModelDerivationError>,
{
    validate_intentional_boundary_repository_inventory(
        repository,
        revision,
        immutable_root,
        inventory,
    )
    .map_err(|detail| {
        cargo_error(
            ProjectModelDerivationErrorKind::InvalidInput,
            IntentionalBoundaryProjectModelFailurePhase::RepositoryValidation,
            None,
            detail,
        )
    })?;
    let cargo_manifests = inventory
        .tracked_entries
        .iter()
        .filter(|entry| entry.repository_path.rsplit('/').next() == Some("Cargo.toml"))
        .map(|entry| {
            if entry.kind != BoundaryGitEntryKind::RegularBlob {
                return Err(cargo_error(
                    ProjectModelDerivationErrorKind::UnsupportedProjectShape,
                    IntentionalBoundaryProjectModelFailurePhase::RepositoryValidation,
                    Some(&entry.repository_path),
                    format!(
                        "Cargo manifest is not a regular Git blob: {}",
                        entry.repository_path
                    ),
                ));
            }
            Ok(entry.repository_path.clone())
        })
        .collect::<Result<BTreeSet<_>, ProjectModelDerivationError>>()?;
    let mut covered_manifests = BTreeSet::new();
    let mut executions = Vec::new();
    let mut targets = Vec::new();
    for manifest_path in &cargo_manifests {
        if covered_manifests.contains(manifest_path) {
            continue;
        }
        let output = executor(execution_root, manifest_path);
        let post_execution_inventory = validate_intentional_boundary_repository_inventory(
            repository,
            revision,
            immutable_root,
            inventory,
        );
        if let Err(error) = post_execution_inventory {
            return Err(cargo_error(
                ProjectModelDerivationErrorKind::InfrastructureFailed,
                IntentionalBoundaryProjectModelFailurePhase::IntegrityVerification,
                Some(manifest_path),
                format!("Cargo metadata changed the immutable repository: {error}"),
            ));
        }
        let output = output?;
        let contribution = parse_intentional_boundary_cargo_metadata(
            execution_root,
            inventory,
            manifest_path,
            &output.toolchain_identity_sha256,
            output.stdout.as_bytes(),
        )
        .map_err(|detail| {
            cargo_error(
                ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
                IntentionalBoundaryProjectModelFailurePhase::OutputValidation,
                Some(manifest_path),
                detail,
            )
        })?;
        let [execution] = contribution.executions.as_slice() else {
            return Err(cargo_error(
                ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
                IntentionalBoundaryProjectModelFailurePhase::CensusAssembly,
                Some(manifest_path),
                "Cargo project-model contribution changed cardinality",
            ));
        };
        for covered in &execution.covered_manifest_repository_paths {
            if !cargo_manifests.contains(covered) {
                return Err(cargo_error(
                    ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
                    IntentionalBoundaryProjectModelFailurePhase::OutputValidation,
                    Some(manifest_path),
                    format!("Cargo metadata covered an unrecognized manifest: {covered}"),
                ));
            }
            covered_manifests.insert(covered.clone());
        }
        executions.extend(contribution.executions);
        targets.extend(contribution.targets);
    }
    if covered_manifests != cargo_manifests {
        return Err(cargo_error(
            ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
            IntentionalBoundaryProjectModelFailurePhase::CensusAssembly,
            None,
            "Cargo metadata omitted a tracked Cargo manifest",
        ));
    }
    validate_intentional_boundary_repository_inventory(
        repository,
        revision,
        immutable_root,
        inventory,
    )
    .map_err(|detail| {
        cargo_error(
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            IntentionalBoundaryProjectModelFailurePhase::IntegrityVerification,
            None,
            detail,
        )
    })?;
    finish_project_model_census(inventory, executions, targets).map_err(|detail| {
        cargo_error(
            ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
            IntentionalBoundaryProjectModelFailurePhase::CensusAssembly,
            None,
            detail,
        )
    })
}

fn run_cargo_metadata(
    root: &Path,
    manifest_repository_path: &str,
) -> Result<CargoMetadataExecutionOutput, ProjectModelDerivationError> {
    let runtime = CargoMetadataCallRuntime::create(root).map_err(|detail| {
        cargo_error(
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            IntentionalBoundaryProjectModelFailurePhase::RuntimePreparation,
            Some(manifest_repository_path),
            detail,
        )
    })?;
    let cache = runtime.path().join("cache");
    fs::create_dir(&cache).map_err(|error| {
        cargo_error(
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            IntentionalBoundaryProjectModelFailurePhase::RuntimePreparation,
            Some(manifest_repository_path),
            format!("failed to create private Cargo metadata cache: {error}"),
        )
    })?;
    let logical_command = vec![
        "cargo".to_string(),
        "metadata".to_string(),
        "--format-version".to_string(),
        "1".to_string(),
        "--no-deps".to_string(),
        "--offline".to_string(),
        "--manifest-path".to_string(),
        manifest_repository_path.to_string(),
    ];
    let mut plan = prepare_historical_runtime(root, &cache, &logical_command).map_err(|error| {
        project_model_runtime_plan_error(
            Provider::CargoMetadata,
            manifest_repository_path,
            "Cargo metadata runtime",
            error,
        )
    })?;
    plan.command.allow_network = false;
    #[cfg(target_os = "macos")]
    {
        plan.command.allow_local_network = false;
    }
    plan.command.timeout = CARGO_METADATA_TIMEOUT;
    plan.command.output_limit = CARGO_METADATA_OUTPUT_LIMIT;
    let toolchain_identity_sha256 = plan.runtime_identity;
    let output = crate::sandbox::run(&plan.command).map_err(|error| {
        project_model_sandbox_error(
            Provider::CargoMetadata,
            manifest_repository_path,
            "sandboxed Cargo metadata failed",
            error,
        )
    })?;
    if output.timed_out {
        return Err(project_model_process_error(
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            Provider::CargoMetadata,
            IntentionalBoundaryProjectModelFailurePhase::Execution,
            manifest_repository_path,
            "sandboxed Cargo metadata timed out",
            output,
        ));
    }
    if output.status_code != Some(0) {
        let detail = format!(
            "sandboxed Cargo metadata exited with status {}",
            output
                .status_code
                .map_or_else(|| "unknown".to_string(), |status| status.to_string())
        );
        return Err(project_model_process_error(
            ProjectModelDerivationErrorKind::ProviderRejectedRepository,
            Provider::CargoMetadata,
            IntentionalBoundaryProjectModelFailurePhase::Execution,
            manifest_repository_path,
            detail,
            output,
        ));
    }
    Ok(CargoMetadataExecutionOutput {
        toolchain_identity_sha256,
        stdout: output.stdout,
    })
}

fn cargo_error(
    kind: ProjectModelDerivationErrorKind,
    phase: IntentionalBoundaryProjectModelFailurePhase,
    invocation_anchor_repository_path: Option<&str>,
    detail: impl Into<String>,
) -> ProjectModelDerivationError {
    project_model_error(
        kind,
        Provider::CargoMetadata,
        phase,
        invocation_anchor_repository_path,
        detail,
    )
}
