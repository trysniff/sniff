use super::super::IntentionalBoundaryProjectModelFailurePhase;
use super::super::intentional_boundary_project_model_outcome::{
    ProjectModelDerivationError, ProjectModelDerivationErrorKind, legacy_project_model_error,
    project_model_error, project_model_process_error, project_model_sandbox_error,
};
use super::super::intentional_boundary_runtime_snapshot::{
    IntentionalBoundaryRuntimeSnapshot, allocate_runtime_directory,
};
use super::dependency::{
    GoCommandNetworkPolicy, prepare_go_command_plan, prepare_go_dependency_cache,
};
use super::variants::{
    GO_VARIANT_LIMIT, go_project_model_pipeline_identity, parse_go_constraint_tags,
    parse_go_dist_variants, stage_go_constraint_invocation,
};
use super::*;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;

const GO_LIST_PARALLELISM: usize = 4;
type GoListClasses =
    BTreeMap<(String, IntentionalBoundaryProjectModelGoQuery, Vec<Vec<u8>>), GoListClass>;

struct GoListClass {
    stdout: String,
    variants: Vec<IntentionalBoundaryProjectModelVariant>,
    module_identity: Option<GoListModule>,
}

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

#[derive(Debug)]
pub(super) struct GoListExecutionOutput {
    pub(super) toolchain_identity_sha256: String,
    pub(super) variant: IntentionalBoundaryProjectModelVariant,
    pub(super) equivalent_variants: Vec<IntentionalBoundaryProjectModelVariant>,
    pub(super) module_identity: Option<GoListModule>,
    pub(super) stdout: String,
}

struct GoCommandExecution {
    toolchain_identity_sha256: String,
    output: crate::sandbox::SandboxOutput,
}

struct GoProjectModelCommand<'a> {
    root: &'a Path,
    cache: &'a Path,
    manifest_repository_path: &'a str,
    logical_command: Vec<String>,
    explicit_context: &'a [(String, String)],
    dependency_preparation_identity: &'a str,
    nonzero_kind: ProjectModelDerivationErrorKind,
    label: &'a str,
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
            let contribution = parse_intentional_boundary_go_list_with_equivalents(
                execution_root,
                inventory,
                manifest_path,
                &output.toolchain_identity_sha256,
                output.variant,
                output.equivalent_variants,
                output.module_identity.as_ref(),
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
    let dependency_preparation_identity =
        prepare_go_dependency_cache(root, &cache, manifest_repository_path, module_directory)?;
    let platform_command = vec![
        "go".to_string(),
        "-C".to_string(),
        module_directory.to_string(),
        "tool".to_string(),
        "dist".to_string(),
        "list".to_string(),
        "-json".to_string(),
    ];
    let platform_execution = run_go_project_model_command(GoProjectModelCommand {
        root,
        cache: &cache,
        manifest_repository_path,
        logical_command: platform_command,
        explicit_context: &[],
        dependency_preparation_identity: &dependency_preparation_identity,
        nonzero_kind: ProjectModelDerivationErrorKind::InfrastructureFailed,
        label: "sandboxed Go platform discovery",
    })?;
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
    let constraint_context = [("GO111MODULE".to_string(), "off".to_string())];
    let constraint_execution = run_go_project_model_command(GoProjectModelCommand {
        root,
        cache: &cache,
        manifest_repository_path,
        logical_command: constraint_command,
        explicit_context: &constraint_context,
        dependency_preparation_identity: &dependency_preparation_identity,
        nonzero_kind: ProjectModelDerivationErrorKind::ProviderRejectedRepository,
        label: "sandboxed Go constraint discovery",
    })?;
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
    let mut variants = parse_go_dist_variants(&platform_execution.output.stdout, &tag_domain)
        .map_err(|detail| {
            go_error(
                ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
                IntentionalBoundaryProjectModelFailurePhase::OutputValidation,
                Some(manifest_repository_path),
                detail,
            )
        })?;
    variants.extend(tag_domain.standalone_source_repository_paths.iter().map(
        |source_repository_path| IntentionalBoundaryProjectModelVariant::Go {
            goos: "linux".to_string(),
            goarch: "amd64".to_string(),
            cgo_enabled: false,
            build_tags: Vec::new(),
            architecture: IntentionalBoundaryProjectModelGoArchitecture::Default,
            query: IntentionalBoundaryProjectModelGoQuery::StandaloneSource {
                source_repository_path: source_repository_path.clone(),
            },
        },
    ));
    variants.sort();
    if variants.len() > GO_VARIANT_LIMIT || variants.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(go_error(
            ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
            IntentionalBoundaryProjectModelFailurePhase::CensusAssembly,
            Some(manifest_repository_path),
            "Go source-fact variants are repeated or exceed the strict limit",
        ));
    }
    let module_identity = if tag_domain.standalone_source_repository_paths.is_empty() {
        None
    } else {
        let module_command = vec![
            "go".to_string(),
            "-C".to_string(),
            module_directory.to_string(),
            "list".to_string(),
            "-m".to_string(),
            "-json".to_string(),
            "-mod=readonly".to_string(),
        ];
        let module_execution = run_go_project_model_command(GoProjectModelCommand {
            root,
            cache: &cache,
            manifest_repository_path,
            logical_command: module_command,
            explicit_context: &[],
            dependency_preparation_identity: &dependency_preparation_identity,
            nonzero_kind: ProjectModelDerivationErrorKind::ProviderRejectedRepository,
            label: "sandboxed Go module identity discovery",
        })?;
        if platform_execution.toolchain_identity_sha256
            != module_execution.toolchain_identity_sha256
        {
            return Err(go_error(
                ProjectModelDerivationErrorKind::InfrastructureFailed,
                IntentionalBoundaryProjectModelFailurePhase::IntegrityVerification,
                Some(manifest_repository_path),
                "Go toolchain identity changed during module identity discovery",
            ));
        }
        Some(
            serde_json::from_str(&module_execution.output.stdout).map_err(|error| {
                go_error(
                    ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
                    IntentionalBoundaryProjectModelFailurePhase::OutputValidation,
                    Some(manifest_repository_path),
                    format!("Go module identity discovery returned invalid JSON: {error}"),
                )
            })?,
        )
    };
    run_go_variant_classes(
        root,
        &cache,
        manifest_repository_path,
        module_directory,
        &dependency_preparation_identity,
        &platform_execution.toolchain_identity_sha256,
        module_identity.as_ref(),
        variants,
    )
}

fn run_go_variant_classes(
    root: &Path,
    cache: &Path,
    manifest_repository_path: &str,
    module_directory: &str,
    dependency_preparation_identity: &str,
    expected_toolchain_identity_sha256: &str,
    module_identity: Option<&GoListModule>,
    variants: Vec<IntentionalBoundaryProjectModelVariant>,
) -> Result<Vec<GoListExecutionOutput>, ProjectModelDerivationError> {
    let mut classes = GoListClasses::new();
    for chunk in variants.chunks(GO_LIST_PARALLELISM) {
        let outputs = thread::scope(|scope| {
            let handles = chunk
                .iter()
                .cloned()
                .map(|variant| {
                    scope.spawn(move || {
                        run_go_variant(
                            root,
                            cache,
                            manifest_repository_path,
                            module_directory,
                            dependency_preparation_identity,
                            expected_toolchain_identity_sha256,
                            module_identity,
                            variant,
                        )
                    })
                })
                .collect::<Vec<_>>();
            let mut outputs = Vec::with_capacity(handles.len());
            for handle in handles {
                outputs.push(handle.join().map_err(|_| {
                    go_error(
                        ProjectModelDerivationErrorKind::InfrastructureFailed,
                        IntentionalBoundaryProjectModelFailurePhase::Execution,
                        Some(manifest_repository_path),
                        "parallel go list worker panicked",
                    )
                })??);
            }
            Ok::<_, ProjectModelDerivationError>(outputs)
        })?;
        for output in outputs {
            let valid = go_list_context_is_valid(&output.stdout).map_err(|detail| {
                go_error(
                    ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
                    IntentionalBoundaryProjectModelFailurePhase::OutputValidation,
                    Some(manifest_repository_path),
                    detail,
                )
            })?;
            if !valid {
                if is_required_go_variant(&output.variant) {
                    return Err(go_error(
                        ProjectModelDerivationErrorKind::ProviderRejectedRepository,
                        IntentionalBoundaryProjectModelFailurePhase::Execution,
                        Some(manifest_repository_path),
                        "required Go compiler context was rejected by go list",
                    ));
                }
                continue;
            }
            insert_go_list_output(&mut classes, output).map_err(|detail| {
                go_error(
                    ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
                    IntentionalBoundaryProjectModelFailurePhase::OutputValidation,
                    Some(manifest_repository_path),
                    detail,
                )
            })?;
        }
    }
    finish_go_list_classes(classes, manifest_repository_path)
}

fn insert_go_list_output(
    classes: &mut GoListClasses,
    output: GoListExecutionOutput,
) -> Result<(), String> {
    let GoListExecutionOutput {
        toolchain_identity_sha256,
        variant,
        equivalent_variants,
        module_identity,
        stdout,
    } = output;
    let query = match &variant {
        IntentionalBoundaryProjectModelVariant::Go { query, .. } => query.clone(),
        _ => return Err("Go list output has an untyped compiler query".to_string()),
    };
    let projection = canonical_go_list_projection(&stdout)?;
    let expected_module_identity = module_identity.clone();
    let class = classes
        .entry((toolchain_identity_sha256, query, projection))
        .or_insert_with(|| GoListClass {
            stdout,
            variants: Vec::new(),
            module_identity,
        });
    if class.module_identity != expected_module_identity {
        return Err("equivalent Go compiler worlds disagree on module identity".to_string());
    }
    class.variants.push(variant);
    class.variants.extend(equivalent_variants);
    Ok(())
}

fn finish_go_list_classes(
    classes: GoListClasses,
    manifest_repository_path: &str,
) -> Result<Vec<GoListExecutionOutput>, ProjectModelDerivationError> {
    let mut outputs = classes
        .into_iter()
        .map(|((toolchain_identity_sha256, query, _), class)| {
            let GoListClass {
                stdout,
                mut variants,
                module_identity,
            } = class;
            variants.sort();
            if variants.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(go_error(
                    ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
                    IntentionalBoundaryProjectModelFailurePhase::CensusAssembly,
                    Some(manifest_repository_path),
                    "Go equivalent-variant class repeated a compiler context",
                ));
            }
            let variant = variants.remove(0);
            if matches!(
                query,
                IntentionalBoundaryProjectModelGoQuery::StandaloneSource { .. }
            ) && variants.len() > 0
            {
                return Err(go_error(
                    ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
                    IntentionalBoundaryProjectModelFailurePhase::CensusAssembly,
                    Some(manifest_repository_path),
                    "standalone Go compiler world unexpectedly has equivalent variants",
                ));
            }
            Ok(GoListExecutionOutput {
                toolchain_identity_sha256,
                variant,
                equivalent_variants: variants,
                module_identity,
                stdout,
            })
        })
        .collect::<Result<Vec<_>, ProjectModelDerivationError>>()?;
    outputs.sort_by(|left, right| left.variant.cmp(&right.variant));
    Ok(outputs)
}

#[cfg(test)]
pub(super) fn collapse_go_list_outputs(
    outputs: Vec<GoListExecutionOutput>,
) -> Result<Vec<GoListExecutionOutput>, String> {
    let mut classes = GoListClasses::new();
    for output in outputs {
        if !go_list_context_is_valid(&output.stdout)? {
            if is_required_go_variant(&output.variant) {
                return Err("required Go compiler context was rejected by go list".to_string());
            }
            continue;
        }
        insert_go_list_output(&mut classes, output)?;
    }
    finish_go_list_classes(classes, "go.mod").map_err(legacy_project_model_error)
}

pub(super) fn go_list_context_is_valid(stdout: &str) -> Result<bool, String> {
    let packages = serde_json::Deserializer::from_str(stdout).into_iter::<GoListPackage>();
    let mut valid = true;
    for package in packages {
        let package = package
            .map_err(|error| format!("failed to parse concatenated go list JSON: {error}"))?;
        if package.incomplete || package.error.is_some() {
            valid = false;
        }
    }
    Ok(valid)
}

fn is_canonical_portable_go_variant(variant: &IntentionalBoundaryProjectModelVariant) -> bool {
    matches!(
        variant,
        IntentionalBoundaryProjectModelVariant::Go {
            goos,
            goarch,
            cgo_enabled: false,
            build_tags,
            architecture: IntentionalBoundaryProjectModelGoArchitecture::Default,
            query: IntentionalBoundaryProjectModelGoQuery::ModulePackages,
        } if goos == "linux" && goarch == "amd64" && build_tags.is_empty()
    )
}

fn run_go_variant(
    root: &Path,
    cache: &Path,
    manifest_repository_path: &str,
    module_directory: &str,
    dependency_preparation_identity: &str,
    expected_toolchain_identity_sha256: &str,
    module_identity: Option<&GoListModule>,
    variant: IntentionalBoundaryProjectModelVariant,
) -> Result<GoListExecutionOutput, ProjectModelDerivationError> {
    let IntentionalBoundaryProjectModelVariant::Go {
        goos,
        goarch,
        cgo_enabled,
        build_tags,
        architecture,
        query,
    } = &variant
    else {
        unreachable!("Go platform planning only emits Go variants");
    };
    let mut logical_command = vec![
        "go".to_string(),
        "-C".to_string(),
        module_directory.to_string(),
        "list".to_string(),
        "-e".to_string(),
        "-json".to_string(),
        "-find".to_string(),
        "-mod=readonly".to_string(),
        "-buildvcs=false".to_string(),
    ];
    if !build_tags.is_empty() {
        logical_command.push(format!("-tags={}", build_tags.join(",")));
    }
    match query {
        IntentionalBoundaryProjectModelGoQuery::ModulePackages => {
            logical_command.push("./...".to_string());
        }
        IntentionalBoundaryProjectModelGoQuery::StandaloneSource {
            source_repository_path,
        } => {
            logical_command.push(go_query_argument(module_directory, source_repository_path)?);
        }
    }
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
    let list_execution = run_go_project_model_command(GoProjectModelCommand {
        root,
        cache,
        manifest_repository_path,
        logical_command,
        explicit_context: &explicit_context,
        dependency_preparation_identity,
        nonzero_kind: ProjectModelDerivationErrorKind::ProviderRejectedRepository,
        label: "sandboxed go list",
    })?;
    if expected_toolchain_identity_sha256 != list_execution.toolchain_identity_sha256 {
        return Err(go_error(
            ProjectModelDerivationErrorKind::InfrastructureFailed,
            IntentionalBoundaryProjectModelFailurePhase::IntegrityVerification,
            Some(manifest_repository_path),
            "Go toolchain identity changed between platform discovery and package selection",
        ));
    }
    let retained_module_identity = match query {
        IntentionalBoundaryProjectModelGoQuery::ModulePackages => None,
        IntentionalBoundaryProjectModelGoQuery::StandaloneSource { .. } => {
            Some(module_identity.cloned().ok_or_else(|| {
                go_error(
                    ProjectModelDerivationErrorKind::InfrastructureFailed,
                    IntentionalBoundaryProjectModelFailurePhase::Execution,
                    Some(manifest_repository_path),
                    "standalone Go compiler world omitted module identity",
                )
            })?)
        }
    };
    Ok(GoListExecutionOutput {
        toolchain_identity_sha256: list_execution.toolchain_identity_sha256,
        variant,
        equivalent_variants: Vec::new(),
        module_identity: retained_module_identity,
        stdout: list_execution.output.stdout,
    })
}

fn is_required_go_variant(variant: &IntentionalBoundaryProjectModelVariant) -> bool {
    is_canonical_portable_go_variant(variant)
        || matches!(
            variant,
            IntentionalBoundaryProjectModelVariant::Go {
                query: IntentionalBoundaryProjectModelGoQuery::StandaloneSource { .. },
                ..
            }
        )
}

fn go_query_argument(
    module_directory: &str,
    source_repository_path: &str,
) -> Result<String, ProjectModelDerivationError> {
    if module_directory == "." {
        return Ok(source_repository_path.to_string());
    }
    source_repository_path
        .strip_prefix(module_directory)
        .and_then(|suffix| suffix.strip_prefix('/'))
        .map(str::to_string)
        .ok_or_else(|| {
            go_error(
                ProjectModelDerivationErrorKind::InvalidInput,
                IntentionalBoundaryProjectModelFailurePhase::RepositoryValidation,
                Some(source_repository_path),
                "standalone Go source is outside its committed module",
            )
        })
}

fn run_go_project_model_command(
    command: GoProjectModelCommand<'_>,
) -> Result<GoCommandExecution, ProjectModelDerivationError> {
    let GoProjectModelCommand {
        root,
        cache,
        manifest_repository_path,
        logical_command,
        explicit_context,
        dependency_preparation_identity,
        nonzero_kind,
        label,
    } = command;
    let plan = prepare_go_command_plan(
        root,
        cache,
        manifest_repository_path,
        &logical_command,
        explicit_context,
        GoCommandNetworkPolicy::OfflineModel,
        "Go project-model runtime",
    )?;
    let toolchain_identity_sha256 =
        go_project_model_pipeline_identity(&plan.runtime_identity, dependency_preparation_identity)
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
