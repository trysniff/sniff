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
use super::variants::{
    GO_VARIANT_LIMIT, go_project_model_pipeline_identity, parse_go_constraint_tags,
    parse_go_dist_variants, stage_go_constraint_invocation,
};
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
    F: FnMut(&Path, &str, &[String]) -> Result<Vec<GoListExecutionOutput>, String>,
{
    let mut executor = executor;
    census_go_project_models_at_execution_root(
        repository,
        revision,
        root,
        root,
        inventory,
        |execution_root, manifest_path, source_paths| {
            executor(execution_root, manifest_path, source_paths).map_err(|detail| {
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
    F: FnMut(
        &Path,
        &str,
        &[String],
    ) -> Result<Vec<GoListExecutionOutput>, ProjectModelDerivationError>,
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
            if !entry.kind.is_file_blob() {
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
        let module_sources = go_module_source_paths(inventory, &go_manifests, manifest_path)?;
        let outputs = executor(execution_root, manifest_path, &module_sources);
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

fn go_module_source_paths(
    inventory: &IntentionalBoundaryRepositoryInventory,
    go_manifests: &[String],
    manifest_repository_path: &str,
) -> Result<Vec<String>, ProjectModelDerivationError> {
    let module_directory = manifest_repository_path
        .rsplit_once('/')
        .map_or("", |(directory, _)| directory);
    let module_prefix = (!module_directory.is_empty()).then(|| format!("{module_directory}/"));
    let nested_module_prefixes = go_manifests
        .iter()
        .filter_map(|manifest| manifest.rsplit_once('/').map(|(directory, _)| directory))
        .filter(|directory| {
            *directory != module_directory
                && (module_directory.is_empty()
                    || directory
                        .strip_prefix(module_directory)
                        .is_some_and(|suffix| suffix.starts_with('/')))
        })
        .map(|directory| format!("{directory}/"))
        .collect::<Vec<_>>();
    let mut sources = Vec::new();
    for entry in &inventory.tracked_entries {
        let path = entry.repository_path.as_str();
        if !path.ends_with(".go")
            || path.ends_with("_test.go")
            || module_prefix
                .as_deref()
                .is_some_and(|prefix| !path.starts_with(prefix))
            || nested_module_prefixes
                .iter()
                .any(|prefix| path.starts_with(prefix))
        {
            continue;
        }
        if !entry.kind.is_file_blob() {
            return Err(go_error(
                ProjectModelDerivationErrorKind::UnsupportedProjectShape,
                IntentionalBoundaryProjectModelFailurePhase::RepositoryValidation,
                Some(manifest_repository_path),
                format!("Go module source is not a regular Git blob: {path}"),
            ));
        }
        sources.push(path.to_string());
    }
    Ok(sources)
}

fn run_go_lists(
    root: &Path,
    manifest_repository_path: &str,
    source_repository_paths: &[String],
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
    let constraint_invocation =
        stage_go_constraint_invocation(root, &cache, source_repository_paths).map_err(
            |detail| {
                go_error(
                    ProjectModelDerivationErrorKind::InfrastructureFailed,
                    IntentionalBoundaryProjectModelFailurePhase::RuntimePreparation,
                    Some(manifest_repository_path),
                    detail,
                )
            },
        )?;
    let constraint_command = vec![
        "go".to_string(),
        "run".to_string(),
        constraint_invocation.helper_repository_path,
        constraint_invocation.request_repository_path,
    ];
    let constraint_execution = run_go_project_model_command(
        root,
        &cache,
        manifest_repository_path,
        constraint_command,
        &[("GO111MODULE".to_string(), "off".to_string())],
        ProjectModelDerivationErrorKind::ProviderRejectedRepository,
        "sandboxed Go constraint discovery",
    )?;
    if platform_execution.toolchain_identity_sha256
        != constraint_execution.toolchain_identity_sha256
    {
        return Err(go_error(
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            IntentionalBoundaryProjectModelFailurePhase::IntegrityVerification,
            Some(manifest_repository_path),
            "Go toolchain identity changed between platform and constraint discovery",
        ));
    }
    let tag_domain = parse_go_constraint_tags(
        &constraint_execution.output.stdout,
        source_repository_paths,
        &platform_execution.output.stdout,
    )
    .map_err(|detail| {
        go_error(
            ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
            IntentionalBoundaryProjectModelFailurePhase::OutputValidation,
            Some(manifest_repository_path),
            detail,
        )
    })?;
    let variants = parse_go_dist_variants(&platform_execution.output.stdout, &tag_domain).map_err(
        |detail| {
            go_error(
                ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
                IntentionalBoundaryProjectModelFailurePhase::OutputValidation,
                Some(manifest_repository_path),
                detail,
            )
        },
    )?;
    let mut outputs = Vec::with_capacity(variants.len());
    for variant in variants {
        let IntentionalBoundaryProjectModelVariant::Go {
            goos,
            goarch,
            cgo_enabled,
            build_tags,
            architecture,
        } = &variant
        else {
            unreachable!("Go platform planning only emits Go variants");
        };
        let mut logical_command = vec![
            "go".to_string(),
            "-C".to_string(),
            module_directory.to_string(),
            "list".to_string(),
            "-json".to_string(),
            "-find".to_string(),
            "-mod=readonly".to_string(),
            "-buildvcs=false".to_string(),
        ];
        if !build_tags.is_empty() {
            logical_command.push(format!("-tags={}", build_tags.join(",")));
        }
        logical_command.push("./...".to_string());
        let mut explicit_context = vec![
            (
                "CGO_ENABLED".to_string(),
                if *cgo_enabled { "1" } else { "0" }.to_string(),
            ),
            ("GOARCH".to_string(), goarch.clone()),
            ("GOOS".to_string(), goos.clone()),
        ];
        if let IntentionalBoundaryProjectModelGoArchitecture::Explicit {
            environment_variable,
            value,
        } = architecture
        {
            explicit_context.push((environment_variable.clone(), value.clone()));
        }
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
    let toolchain_identity_sha256 = go_project_model_pipeline_identity(&plan.runtime_identity)
        .map_err(|detail| {
            go_error(
                ProjectModelDerivationErrorKind::InfrastructureFailed,
                IntentionalBoundaryProjectModelFailurePhase::RuntimePreparation,
                Some(manifest_repository_path),
                detail,
            )
        })?;
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
