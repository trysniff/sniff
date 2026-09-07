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
    pub(super) variant: IntentionalBoundaryProjectModelVariant,
    pub(super) stdout: String,
}

#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
struct GoBuildContextOutput {
    GOOS: String,
    GOARCH: String,
    CGO_ENABLED: String,
}

struct GoCommandExecution {
    toolchain_identity_sha256: String,
    output: crate::sandbox::SandboxOutput,
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
            output.variant,
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
    let context_command = vec![
        "go".to_string(),
        "-C".to_string(),
        module_directory.to_string(),
        "env".to_string(),
        "-json".to_string(),
        "GOOS".to_string(),
        "GOARCH".to_string(),
        "CGO_ENABLED".to_string(),
    ];
    let context_execution = run_go_project_model_command(
        root,
        &cache,
        manifest_repository_path,
        context_command,
        &[],
        ProjectModelDerivationErrorKind::InfrastructureFailed,
        "sandboxed Go build-context discovery",
    )?;
    let context: GoBuildContextOutput = serde_json::from_str(&context_execution.output.stdout)
        .map_err(|error| {
            go_error(
                ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
                IntentionalBoundaryProjectModelFailurePhase::OutputValidation,
                Some(manifest_repository_path),
                format!("Go build-context discovery returned invalid JSON: {error}"),
            )
        })?;
    let cgo_enabled = match context.CGO_ENABLED.as_str() {
        "0" => false,
        "1" => true,
        _ => {
            return Err(go_error(
                ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
                IntentionalBoundaryProjectModelFailurePhase::OutputValidation,
                Some(manifest_repository_path),
                "Go build-context discovery returned an invalid CGO_ENABLED value",
            ));
        }
    };
    if context.GOOS.trim().is_empty() || context.GOARCH.trim().is_empty() {
        return Err(go_error(
            ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
            IntentionalBoundaryProjectModelFailurePhase::OutputValidation,
            Some(manifest_repository_path),
            "Go build-context discovery omitted GOOS or GOARCH",
        ));
    }
    let variant = IntentionalBoundaryProjectModelVariant::Go {
        goos: context.GOOS.clone(),
        goarch: context.GOARCH.clone(),
        cgo_enabled,
        build_tags: Vec::new(),
    };
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
    let explicit_context = vec![
        ("CGO_ENABLED".to_string(), context.CGO_ENABLED),
        ("GOARCH".to_string(), context.GOARCH),
        ("GOOS".to_string(), context.GOOS),
    ];
    let list_execution = run_go_project_model_command(
        root,
        &cache,
        manifest_repository_path,
        logical_command,
        &explicit_context,
        ProjectModelDerivationErrorKind::ProviderRejectedRepository,
        "sandboxed go list",
    )?;
    if context_execution.toolchain_identity_sha256 != list_execution.toolchain_identity_sha256 {
        return Err(go_error(
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            IntentionalBoundaryProjectModelFailurePhase::IntegrityVerification,
            Some(manifest_repository_path),
            "Go toolchain identity changed between context discovery and package selection",
        ));
    }
    Ok(GoListExecutionOutput {
        toolchain_identity_sha256: list_execution.toolchain_identity_sha256,
        variant,
        stdout: list_execution.output.stdout,
    })
}

fn run_go_project_model_command(
    root: &Path,
    cache: &Path,
    manifest_repository_path: &str,
    logical_command: Vec<String>,
    explicit_context: &[(String, String)],
    nonzero_kind: ProjectModelDerivationErrorKind,
    label: &str,
) -> Result<GoCommandExecution, ProjectModelDerivationError> {
    let mut plan = prepare_historical_runtime(root, cache, &logical_command).map_err(|error| {
        project_model_runtime_plan_error(
            Provider::GoList,
            manifest_repository_path,
            "Go project-model runtime",
            error,
        )
    })?;
    plan.command.env.extend([
        ("GOENV".to_string(), "off".to_string()),
        ("GOFLAGS".to_string(), String::new()),
        ("GOPROXY".to_string(), "off".to_string()),
        ("GOSUMDB".to_string(), "off".to_string()),
        ("GOTOOLCHAIN".to_string(), "local".to_string()),
        ("GOWORK".to_string(), "off".to_string()),
    ]);
    plan.command.env.extend(explicit_context.iter().cloned());
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
            "Go project-model runtime environment contains duplicate names",
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
            &format!("{label} failed"),
            error,
        )
    })?;
    if output.timed_out {
        return Err(project_model_process_error(
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            Provider::GoList,
            IntentionalBoundaryProjectModelFailurePhase::Execution,
            manifest_repository_path,
            format!("{label} timed out"),
            output,
        ));
    }
    if output.status_code != Some(0) {
        let stderr = output.stderr.trim();
        let detail = format!(
            "{label} exited with status {}{}",
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
            nonzero_kind,
            Provider::GoList,
            IntentionalBoundaryProjectModelFailurePhase::Execution,
            manifest_repository_path,
            detail,
            output,
        ));
    }
    Ok(GoCommandExecution {
        toolchain_identity_sha256,
        output,
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
