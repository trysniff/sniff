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
pub(super) const GO_VARIANT_LIMIT: usize = 256;

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

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GoDistPlatform {
    #[serde(rename = "GOOS")]
    goos: String,
    #[serde(rename = "GOARCH")]
    goarch: String,
    #[serde(rename = "CgoSupported")]
    cgo_supported: bool,
    #[serde(rename = "FirstClass")]
    _first_class: bool,
    #[serde(default, rename = "Broken")]
    broken: bool,
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
        run_go_lists,
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
    F: FnMut(&Path, &str) -> Result<Vec<GoListExecutionOutput>, String>,
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
    F: FnMut(&Path, &str) -> Result<Vec<GoListExecutionOutput>, ProjectModelDerivationError>,
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
    let mut executions = Vec::new();
    let mut targets = Vec::new();
    for manifest_path in &go_manifests {
        let outputs = executor(execution_root, manifest_path);
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
        let outputs = outputs?;
        if outputs.is_empty() || outputs.len() > GO_VARIANT_LIMIT {
            return Err(go_error(
                ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
                IntentionalBoundaryProjectModelFailurePhase::CensusAssembly,
                Some(manifest_path),
                "Go project-model variant ledger is empty or exceeds its strict limit",
            ));
        }
        for output in outputs {
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

fn run_go_lists(
    root: &Path,
    manifest_repository_path: &str,
) -> Result<Vec<GoListExecutionOutput>, ProjectModelDerivationError> {
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
    let platform_command = vec![
        "go".to_string(),
        "-C".to_string(),
        module_directory.to_string(),
        "tool".to_string(),
        "dist".to_string(),
        "list".to_string(),
        "-json".to_string(),
    ];
    let platform_execution = run_go_project_model_command(
        root,
        &cache,
        manifest_repository_path,
        platform_command,
        &[],
        ProjectModelDerivationErrorKind::InfrastructureFailed,
        "sandboxed Go platform discovery",
    )?;
    let variants = parse_go_dist_variants(&platform_execution.output.stdout).map_err(|detail| {
        go_error(
            ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
            IntentionalBoundaryProjectModelFailurePhase::OutputValidation,
            Some(manifest_repository_path),
            detail,
        )
    })?;
    let mut outputs = Vec::with_capacity(variants.len());
    for variant in variants {
        let IntentionalBoundaryProjectModelVariant::Go {
            goos,
            goarch,
            cgo_enabled,
            ..
        } = &variant
        else {
            unreachable!("Go platform planning only emits Go variants");
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
            (
                "CGO_ENABLED".to_string(),
                if *cgo_enabled { "1" } else { "0" }.to_string(),
            ),
            ("GOARCH".to_string(), goarch.clone()),
            ("GOOS".to_string(), goos.clone()),
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
        if platform_execution.toolchain_identity_sha256 != list_execution.toolchain_identity_sha256
        {
            return Err(go_error(
                ProjectModelDerivationErrorKind::InfrastructureFailed,
                IntentionalBoundaryProjectModelFailurePhase::IntegrityVerification,
                Some(manifest_repository_path),
                "Go toolchain identity changed between platform discovery and package selection",
            ));
        }
        outputs.push(GoListExecutionOutput {
            toolchain_identity_sha256: list_execution.toolchain_identity_sha256,
            variant,
            stdout: list_execution.output.stdout,
        });
    }
    Ok(outputs)
}

pub(super) fn parse_go_dist_variants(
    stdout: &str,
) -> Result<Vec<IntentionalBoundaryProjectModelVariant>, String> {
    let platforms: Vec<GoDistPlatform> = serde_json::from_str(stdout)
        .map_err(|error| format!("Go platform discovery returned invalid JSON: {error}"))?;
    if platforms.is_empty() {
        return Err("Go platform discovery returned no supported platforms".to_string());
    }
    let mut platform_keys = BTreeSet::new();
    let mut variants = Vec::new();
    for platform in platforms {
        if !platform_component_is_valid(&platform.goos)
            || !platform_component_is_valid(&platform.goarch)
            || platform.broken
            || !platform_keys.insert((platform.goos.clone(), platform.goarch.clone()))
        {
            return Err(
                "Go platform discovery returned an invalid or repeated platform".to_string(),
            );
        }
        for cgo_enabled in
            [false, true]
                .into_iter()
                .take(if platform.cgo_supported { 2 } else { 1 })
        {
            variants.push(IntentionalBoundaryProjectModelVariant::Go {
                goos: platform.goos.clone(),
                goarch: platform.goarch.clone(),
                cgo_enabled,
                build_tags: Vec::new(),
            });
        }
    }
    variants.sort();
    if variants.len() > GO_VARIANT_LIMIT || variants.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(
            "Go platform discovery exceeds or repeats the strict variant limit".to_string(),
        );
    }
    Ok(variants)
}

fn platform_component_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
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
