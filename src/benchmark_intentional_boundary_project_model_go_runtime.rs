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

const GO_LIST_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const GO_LIST_OUTPUT_LIMIT: usize = 32 * 1024 * 1024;

struct GoListCallRuntime(PathBuf);

impl GoListCallRuntime {
    fn create(root: &Path) -> Result<Self, String> {
        allocate_runtime_directory(root, ".sniff-go-list-call").map(Self)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for GoListCallRuntime {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(super) struct GoListExecutionOutput {
    pub(super) toolchain_identity_sha256: String,
    pub(super) stdout: String,
}

pub fn census_intentional_boundary_go_project_models(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Result<IntentionalBoundaryProjectModelCensus, String> {
    census_intentional_boundary_go_project_models_typed(repository, revision, root, inventory)
        .map_err(legacy_project_model_error)
}

pub(in crate::benchmark::release) fn census_intentional_boundary_go_project_models_typed(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Result<IntentionalBoundaryProjectModelCensus, ProjectModelDerivationError> {
    validate_intentional_boundary_repository_inventory(repository, revision, root, inventory)
        .map_err(|detail| {
            go_error(
                ProjectModelDerivationErrorKind::InvalidInput,
                IntentionalBoundaryProjectModelFailurePhase::RepositoryValidation,
                None,
                detail,
            )
        })?;
    let snapshot =
        IntentionalBoundaryRuntimeSnapshot::create(root, revision, "sniff-go-list-snapshot")
            .map_err(|detail| {
                go_error(
                    ProjectModelDerivationErrorKind::InfrastructureFailed,
                    IntentionalBoundaryProjectModelFailurePhase::SnapshotPreparation,
                    None,
                    detail,
                )
            })?;
    census_go_project_models_at_execution_root(
        repository,
        revision,
        root,
        snapshot.path(),
        inventory,
        run_go_list,
    )
}

#[cfg(test)]
pub(super) fn census_go_project_models_with_executor<F>(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    executor: F,
) -> Result<IntentionalBoundaryProjectModelCensus, String>
where
    F: FnMut(&Path, &str) -> Result<GoListExecutionOutput, String>,
{
    let mut executor = executor;
    census_go_project_models_at_execution_root(
        repository,
        revision,
        root,
        root,
        inventory,
        |execution_root, manifest_path| {
            executor(execution_root, manifest_path).map_err(|detail| {
                go_error(
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

fn census_go_project_models_at_execution_root<F>(
    repository: &str,
    revision: &str,
    immutable_root: &Path,
    execution_root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    mut executor: F,
) -> Result<IntentionalBoundaryProjectModelCensus, ProjectModelDerivationError>
where
    F: FnMut(&Path, &str) -> Result<GoListExecutionOutput, ProjectModelDerivationError>,
{
    validate_intentional_boundary_repository_inventory(
        repository,
        revision,
        immutable_root,
        inventory,
    )
    .map_err(|detail| {
        go_error(
            ProjectModelDerivationErrorKind::InvalidInput,
            IntentionalBoundaryProjectModelFailurePhase::RepositoryValidation,
            None,
            detail,
        )
    })?;
    let go_manifests = inventory
        .tracked_entries
        .iter()
        .filter(|entry| entry.repository_path.rsplit('/').next() == Some("go.mod"))
        .map(|entry| {
            if entry.kind != BoundaryGitEntryKind::RegularBlob {
                return Err(go_error(
                    ProjectModelDerivationErrorKind::UnsupportedProjectShape,
                    IntentionalBoundaryProjectModelFailurePhase::RepositoryValidation,
                    Some(&entry.repository_path),
                    format!(
                        "Go manifest is not a regular Git blob: {}",
                        entry.repository_path
                    ),
                ));
            }
            Ok(entry.repository_path.clone())
        })
        .collect::<Result<Vec<_>, ProjectModelDerivationError>>()?;
    let mut executions = Vec::with_capacity(go_manifests.len());
    let mut targets = Vec::new();
    for manifest_path in &go_manifests {
        let output = executor(execution_root, manifest_path);
        if let Err(error) = validate_intentional_boundary_repository_inventory(
            repository,
            revision,
            immutable_root,
            inventory,
        ) {
            return Err(go_error(
                ProjectModelDerivationErrorKind::InfrastructureFailed,
                IntentionalBoundaryProjectModelFailurePhase::IntegrityVerification,
                Some(manifest_path),
                format!("go list changed the immutable repository: {error}"),
            ));
        }
        let output = output?;
        let contribution = parse_intentional_boundary_go_list(
            execution_root,
            inventory,
            manifest_path,
            &output.toolchain_identity_sha256,
            output.stdout.as_bytes(),
        )
        .map_err(|detail| {
            go_error(
                ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
                IntentionalBoundaryProjectModelFailurePhase::OutputValidation,
                Some(manifest_path),
                detail,
            )
        })?;
        let [execution] = contribution.executions.as_slice() else {
            return Err(go_error(
                ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
                IntentionalBoundaryProjectModelFailurePhase::CensusAssembly,
                Some(manifest_path),
                "Go project-model contribution changed cardinality",
            ));
        };
        if execution.covered_manifest_repository_paths != [manifest_path.clone()] {
            return Err(go_error(
                ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
                IntentionalBoundaryProjectModelFailurePhase::OutputValidation,
                Some(manifest_path),
                "go list covered a manifest outside its isolated module",
            ));
        }
        executions.extend(contribution.executions);
        targets.extend(contribution.targets);
    }
    validate_intentional_boundary_repository_inventory(
        repository,
        revision,
        immutable_root,
        inventory,
    )
    .map_err(|detail| {
        go_error(
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            IntentionalBoundaryProjectModelFailurePhase::IntegrityVerification,
            None,
            detail,
        )
    })?;
    finish_project_model_census(inventory, executions, targets).map_err(|detail| {
        go_error(
            ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
            IntentionalBoundaryProjectModelFailurePhase::CensusAssembly,
            None,
            detail,
        )
    })
}

fn run_go_list(
    root: &Path,
    manifest_repository_path: &str,
) -> Result<GoListExecutionOutput, ProjectModelDerivationError> {
    let runtime = GoListCallRuntime::create(root).map_err(|detail| {
        go_error(
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            IntentionalBoundaryProjectModelFailurePhase::RuntimePreparation,
            Some(manifest_repository_path),
            detail,
        )
    })?;
    let cache = runtime.path().join("cache");
    fs::create_dir(&cache).map_err(|error| {
        go_error(
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            IntentionalBoundaryProjectModelFailurePhase::RuntimePreparation,
            Some(manifest_repository_path),
            format!("failed to create private go list cache: {error}"),
        )
    })?;
    let module_directory = manifest_repository_path
        .rsplit_once('/')
        .map_or(".", |(directory, _)| directory);
    let logical_command = vec![
        "go".to_string(),
        "-C".to_string(),
        module_directory.to_string(),
        "list".to_string(),
        "-json".to_string(),
        "-find".to_string(),
        "-mod=readonly".to_string(),
        "-buildvcs=false".to_string(),
        "./...".to_string(),
    ];
    let mut plan = prepare_historical_runtime(root, &cache, &logical_command).map_err(|error| {
        project_model_runtime_plan_error(
            Provider::GoList,
            manifest_repository_path,
            "Go project-model runtime",
            error,
        )
    })?;
    plan.command.env.extend([
        ("GOENV".to_string(), "off".to_string()),
        ("GOPROXY".to_string(), "off".to_string()),
        ("GOSUMDB".to_string(), "off".to_string()),
        ("GOTOOLCHAIN".to_string(), "local".to_string()),
        ("GOWORK".to_string(), "off".to_string()),
    ]);
    plan.command.env.sort_by(|left, right| left.0.cmp(&right.0));
    if plan
        .command
        .env
        .windows(2)
        .any(|pair| pair[0].0 == pair[1].0)
    {
        return Err(go_error(
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            IntentionalBoundaryProjectModelFailurePhase::RuntimePreparation,
            Some(manifest_repository_path),
            "go list runtime environment contains duplicate names",
        ));
    }
    plan.command.allow_network = false;
    #[cfg(target_os = "macos")]
    {
        plan.command.allow_local_network = false;
    }
    plan.command.timeout = GO_LIST_TIMEOUT;
    plan.command.output_limit = GO_LIST_OUTPUT_LIMIT;
    let toolchain_identity_sha256 = plan.runtime_identity;
    let output = crate::sandbox::run(&plan.command).map_err(|error| {
        project_model_sandbox_error(
            Provider::GoList,
            manifest_repository_path,
            "sandboxed go list failed",
            error,
        )
    })?;
    if output.timed_out {
        return Err(project_model_process_error(
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            Provider::GoList,
            IntentionalBoundaryProjectModelFailurePhase::Execution,
            manifest_repository_path,
            "sandboxed go list timed out",
            output,
        ));
    }
    if output.status_code != Some(0) {
        let stderr = output.stderr.trim();
        let detail = format!(
            "sandboxed go list exited with status {}{}",
            output
                .status_code
                .map_or_else(|| "unknown".to_string(), |status| status.to_string()),
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        );
        return Err(project_model_process_error(
            ProjectModelDerivationErrorKind::ProviderRejectedRepository,
            Provider::GoList,
            IntentionalBoundaryProjectModelFailurePhase::Execution,
            manifest_repository_path,
            detail,
            output,
        ));
    }
    Ok(GoListExecutionOutput {
        toolchain_identity_sha256,
        stdout: output.stdout,
    })
}

fn go_error(
    kind: ProjectModelDerivationErrorKind,
    phase: IntentionalBoundaryProjectModelFailurePhase,
    invocation_anchor_repository_path: Option<&str>,
    detail: impl Into<String>,
) -> ProjectModelDerivationError {
    project_model_error(
        kind,
        Provider::GoList,
        phase,
        invocation_anchor_repository_path,
        detail,
    )
}
