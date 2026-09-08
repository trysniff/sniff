use super::intentional_boundary_project_model::{
    compute_execution_id, compute_normalized_model_sha256, compute_target_id,
    finish_project_model_census, regular_inventory_entry,
};
#[cfg(test)]
use super::intentional_boundary_project_model_outcome::legacy_project_model_error;
use super::intentional_boundary_project_model_outcome::{
    ProjectModelDerivationError, ProjectModelDerivationErrorKind, project_model_error,
};
use super::{
    BoundaryGitEntryKind, IntentionalBoundaryProjectModelCensus,
    IntentionalBoundaryProjectModelExecution,
    IntentionalBoundaryProjectModelNonBoundaryReason as NonBoundaryReason,
    IntentionalBoundaryProjectModelProvider as Provider, IntentionalBoundaryProjectModelTarget,
    IntentionalBoundaryProjectModelTargetStatus as TargetStatus,
    IntentionalBoundaryProjectModelTypeScriptConfigRead,
    IntentionalBoundaryProjectModelTypeScriptProject, IntentionalBoundaryProjectModelVariant,
    IntentionalBoundaryRepositoryInventory, validate_intentional_boundary_repository_inventory,
};
use crate::semantic_indexer_manifest::{IndexerInstallSource, SemanticIndexerKind, pinned_indexer};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

#[path = "benchmark_intentional_boundary_project_model_typescript_runtime.rs"]
mod runtime;
#[path = "benchmark_intentional_boundary_project_model_typescript_validation.rs"]
mod validation;

pub(super) use validation::{
    validate_typescript_target_classification, validate_typescript_variant_inventory,
};

pub(super) const TYPESCRIPT_PROJECT_MODEL_COMMAND_CONTRACT: &str =
    "sniff-typescript-compiler-project-model-v1";
const TYPESCRIPT_PROJECT_MODEL_OUTPUT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub(super) struct TypeScriptCompilerExecutionOutput {
    pub(super) toolchain_identity_sha256: String,
    pub(super) stdout: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompilerOutput {
    schema_version: u32,
    typescript_version: String,
    worlds: Vec<CompilerWorld>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompilerWorld {
    root_config: Option<String>,
    inferred: bool,
    config_closure: Vec<String>,
    diagnostics: Vec<Value>,
    projects: Vec<CompilerProject>,
    selected_source_files: Vec<String>,
    ignored_source_files: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompilerProject {
    config_path: Option<String>,
    config_reads: Vec<String>,
    diagnostics: Vec<Value>,
    effective_options: Value,
    references: Vec<String>,
    selected_source_files: Vec<String>,
}

pub(in crate::benchmark::release) fn census_intentional_boundary_typescript_project_models_typed(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    required_source_paths: &[String],
) -> Result<IntentionalBoundaryProjectModelCensus, ProjectModelDerivationError> {
    validate_intentional_boundary_repository_inventory(repository, revision, root, inventory)
        .map_err(|detail| {
            typescript_error(
                ProjectModelDerivationErrorKind::InvalidInput,
                super::IntentionalBoundaryProjectModelFailurePhase::RepositoryValidation,
                None,
                detail,
            )
        })?;
    let required_sources = validate_required_sources(inventory, required_source_paths)?;
    if required_sources.is_empty() {
        return finish_project_model_census(inventory, Vec::new(), Vec::new()).map_err(|detail| {
            typescript_error(
                ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
                super::IntentionalBoundaryProjectModelFailurePhase::CensusAssembly,
                None,
                detail,
            )
        });
    }
    let configs = discover_root_config_candidates(inventory)?;
    let output =
        runtime::run_typescript_project_model(root, revision, &configs, &required_sources)?;
    parse_typescript_project_model(
        inventory,
        &configs,
        &required_sources,
        &output.toolchain_identity_sha256,
        output.stdout.as_bytes(),
    )
    .map_err(|detail| {
        typescript_error(
            ProjectModelDerivationErrorKind::ProviderOutputIncomplete,
            super::IntentionalBoundaryProjectModelFailurePhase::OutputValidation,
            None,
            detail,
        )
    })
}

#[cfg(test)]
pub(super) fn census_typescript_project_models_with_executor<F>(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    required_source_paths: &[String],
    mut executor: F,
) -> Result<IntentionalBoundaryProjectModelCensus, String>
where
    F: FnMut(&Path, &[String], &[String]) -> Result<TypeScriptCompilerExecutionOutput, String>,
{
    validate_intentional_boundary_repository_inventory(repository, revision, root, inventory)?;
    let required_sources = validate_required_sources(inventory, required_source_paths)
        .map_err(legacy_project_model_error)?;
    if required_sources.is_empty() {
        return finish_project_model_census(inventory, Vec::new(), Vec::new());
    }
    let configs = discover_root_config_candidates(inventory).map_err(legacy_project_model_error)?;
    let output = executor(root, &configs, &required_sources)?;
    parse_typescript_project_model(
        inventory,
        &configs,
        &required_sources,
        &output.toolchain_identity_sha256,
        output.stdout.as_bytes(),
    )
}

fn validate_required_sources(
    inventory: &IntentionalBoundaryRepositoryInventory,
    required_source_paths: &[String],
) -> Result<Vec<String>, ProjectModelDerivationError> {
    let mut sources = required_source_paths.to_vec();
    sources.sort();
    if sources.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(typescript_error(
            ProjectModelDerivationErrorKind::InvalidInput,
            super::IntentionalBoundaryProjectModelFailurePhase::RepositoryValidation,
            None,
            "TypeScript project-model source paths are repeated",
        ));
    }
    for source in &sources {
        let entry = regular_inventory_entry(inventory, source, "TypeScript project-model source")
            .map_err(|detail| {
            typescript_error(
                ProjectModelDerivationErrorKind::InvalidInput,
                super::IntentionalBoundaryProjectModelFailurePhase::RepositoryValidation,
                Some(source),
                detail,
            )
        })?;
        if !is_typescript_javascript_source(&entry.repository_path) {
            return Err(typescript_error(
                ProjectModelDerivationErrorKind::InvalidInput,
                super::IntentionalBoundaryProjectModelFailurePhase::RepositoryValidation,
                Some(source),
                "TypeScript project-model source has an unsupported extension",
            ));
        }
    }
    Ok(sources)
}

fn discover_root_config_candidates(
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Result<Vec<String>, ProjectModelDerivationError> {
    inventory
        .tracked_entries
        .iter()
        .filter(|entry| is_config_candidate(&entry.repository_path))
        .map(|entry| {
            if entry.kind != BoundaryGitEntryKind::RegularBlob {
                return Err(typescript_error(
                    ProjectModelDerivationErrorKind::UnsupportedProjectShape,
                    super::IntentionalBoundaryProjectModelFailurePhase::RepositoryValidation,
                    Some(&entry.repository_path),
                    "TypeScript compiler configuration is not a regular Git blob",
                ));
            }
            Ok(entry.repository_path.clone())
        })
        .collect()
}

fn parse_typescript_project_model(
    inventory: &IntentionalBoundaryRepositoryInventory,
    config_candidates: &[String],
    required_sources: &[String],
    toolchain_identity_sha256: &str,
    stdout: &[u8],
) -> Result<IntentionalBoundaryProjectModelCensus, String> {
    if toolchain_identity_sha256.len() != 64
        || !toolchain_identity_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("TypeScript project-model toolchain identity is invalid".to_string());
    }
    let output: CompilerOutput = serde_json::from_slice(stdout)
        .map_err(|error| format!("failed to parse TypeScript compiler project model: {error}"))?;
    let compiler_version = pinned_typescript_compiler_version()?;
    if output.schema_version != TYPESCRIPT_PROJECT_MODEL_OUTPUT_SCHEMA_VERSION
        || output.typescript_version != compiler_version
        || output.worlds.is_empty()
    {
        return Err("TypeScript compiler project-model identity changed".to_string());
    }
    let required = required_sources.iter().cloned().collect::<BTreeSet<_>>();
    let expected_configs = config_candidates.iter().cloned().collect::<BTreeSet<_>>();
    let mut covered = BTreeSet::new();
    let mut covered_configs = BTreeSet::new();
    let mut executions = Vec::new();
    let mut targets = Vec::new();
    let mut world_keys = BTreeSet::new();
    for world in output.worlds {
        let world_key = world
            .root_config
            .clone()
            .unwrap_or_else(|| "<inferred>".to_string());
        if !world_keys.insert(world_key.clone()) {
            return Err("TypeScript compiler emitted duplicate project worlds".to_string());
        }
        if config_candidates.is_empty() != world.inferred
            || world
                .root_config
                .as_ref()
                .is_some_and(|root| !expected_configs.contains(root))
        {
            return Err("TypeScript inferred project identity changed".to_string());
        }
        covered_configs.extend(world.config_closure.iter().cloned());
        covered_configs.extend(
            world
                .projects
                .iter()
                .flat_map(|project| project.config_reads.iter().cloned()),
        );
        let contribution = normalize_world(
            inventory,
            &required,
            toolchain_identity_sha256,
            compiler_version,
            world,
        )?;
        covered.extend(
            contribution
                .0
                .variant
                .typescript_sources()
                .ok_or_else(|| "TypeScript project-model variant changed kind".to_string())?
                .iter()
                .cloned(),
        );
        executions.push(contribution.0);
        targets.extend(contribution.1);
    }
    let missing = required
        .difference(&covered)
        .take(8)
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "TypeScript compiler projects selected no valid context for required sources {missing:?}"
        ));
    }
    if !expected_configs.is_subset(&covered_configs) {
        return Err("TypeScript compiler omitted a discovered configuration".to_string());
    }
    finish_project_model_census(inventory, executions, targets)
}

fn normalize_world(
    inventory: &IntentionalBoundaryRepositoryInventory,
    required_sources: &BTreeSet<String>,
    toolchain_identity_sha256: &str,
    compiler_version: &str,
    world: CompilerWorld,
) -> Result<
    (
        IntentionalBoundaryProjectModelExecution,
        Vec<IntentionalBoundaryProjectModelTarget>,
    ),
    String,
> {
    if !world.diagnostics.is_empty()
        || world
            .projects
            .iter()
            .any(|project| !project.diagnostics.is_empty())
    {
        return Err(format!(
            "TypeScript compiler project world {} contains configuration diagnostics",
            world.root_config.as_deref().unwrap_or("<inferred>")
        ));
    }
    require_sorted_unique(&world.config_closure, "TypeScript config closure")?;
    require_sorted_unique(&world.selected_source_files, "TypeScript selected sources")?;
    require_sorted_unique(&world.ignored_source_files, "TypeScript ignored sources")?;
    let selected = world
        .selected_source_files
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let ignored = world
        .ignored_source_files
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if !selected.is_disjoint(&ignored)
        || selected.union(&ignored).cloned().collect::<BTreeSet<_>>() != *required_sources
    {
        return Err("TypeScript compiler world changed its required-source partition".to_string());
    }
    let inferred = world.inferred;
    if inferred != world.root_config.is_none()
        || (inferred && (world.projects.len() != 1 || !world.config_closure.is_empty()))
    {
        return Err("TypeScript inferred project identity changed".to_string());
    }
    let anchor_path = match &world.root_config {
        Some(path) => {
            if world.config_closure.binary_search(path).is_err() {
                return Err("TypeScript root config is absent from its closure".to_string());
            }
            path.clone()
        }
        None => required_sources
            .iter()
            .next()
            .cloned()
            .ok_or_else(|| "TypeScript inferred project has no source anchor".to_string())?,
    };
    let anchor = regular_inventory_entry(inventory, &anchor_path, "TypeScript project root")?;
    let mut normalized_projects = Vec::new();
    let mut covered_configs = BTreeSet::new();
    let mut provisional_targets = Vec::new();
    for project in world.projects {
        let normalized = normalize_project(inventory, required_sources, inferred, project)?;
        if let Some(path) = &normalized.config_repository_path {
            covered_configs.insert(path.clone());
        }
        for read in &normalized.config_reads {
            covered_configs.insert(read.repository_path.clone());
        }
        let target_anchor = normalized
            .config_repository_path
            .as_deref()
            .unwrap_or(&anchor_path);
        let target_manifest = regular_inventory_entry(
            inventory,
            target_anchor,
            "TypeScript compiler-project target anchor",
        )?;
        provisional_targets.push(IntentionalBoundaryProjectModelTarget {
            target_id: String::new(),
            execution_id: String::new(),
            provider: Provider::TypeScriptCompilerApi,
            manifest_repository_path: target_anchor.to_string(),
            manifest_object_id: target_manifest.object_id.clone(),
            package_name: "typescript-compiler-project".to_string(),
            package_version: compiler_version.to_string(),
            target_name: normalized
                .config_repository_path
                .clone()
                .unwrap_or_else(|| "<inferred>".to_string()),
            provider_kinds: vec!["compiler_project".to_string()],
            provider_output_types: vec!["semantic_index".to_string()],
            source_repository_paths: normalized.source_repository_paths.clone(),
            ignored_source_repository_paths: required_sources
                .difference(&normalized.source_repository_paths.iter().cloned().collect())
                .cloned()
                .collect(),
            producer_tasks: Vec::new(),
            required_features: Vec::new(),
            target_status: TargetStatus::NonBoundary {
                reason: NonBoundaryReason::CompilerProject,
            },
        });
        normalized_projects.push(normalized);
    }
    normalized_projects.sort();
    if normalized_projects
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err("TypeScript compiler world contains duplicate projects".to_string());
    }
    let project_configs = normalized_projects
        .iter()
        .filter_map(|project| project.config_repository_path.clone())
        .collect::<Vec<_>>();
    if !inferred && project_configs != world.config_closure {
        return Err("TypeScript compiler world changed its project-reference closure".to_string());
    }
    covered_configs.insert(anchor_path.clone());
    let variant = IntentionalBoundaryProjectModelVariant::TypeScript {
        root_config_repository_path: world.root_config,
        compiler_version: compiler_version.to_string(),
        projects: normalized_projects,
        selected_source_repository_paths: world.selected_source_files,
        ignored_source_repository_paths: world.ignored_source_files,
    };
    provisional_targets.sort();
    let covered_manifest_repository_paths = covered_configs.into_iter().collect::<Vec<_>>();
    let normalized_model_sha256 = compute_normalized_model_sha256(
        Provider::TypeScriptCompilerApi,
        &covered_manifest_repository_paths,
        &provisional_targets,
    )?;
    let execution_id = compute_execution_id(
        Provider::TypeScriptCompilerApi,
        &anchor_path,
        &anchor.object_id,
        toolchain_identity_sha256,
        TYPESCRIPT_PROJECT_MODEL_COMMAND_CONTRACT,
        &variant,
        &normalized_model_sha256,
    )?;
    for target in &mut provisional_targets {
        target.execution_id = execution_id.clone();
        target.target_id = compute_target_id(target)?;
    }
    provisional_targets.sort();
    Ok((
        IntentionalBoundaryProjectModelExecution {
            execution_id,
            provider: Provider::TypeScriptCompilerApi,
            variant,
            invocation_anchor_repository_path: anchor_path,
            invocation_anchor_object_id: anchor.object_id.clone(),
            toolchain_identity_sha256: toolchain_identity_sha256.to_string(),
            command_contract: TYPESCRIPT_PROJECT_MODEL_COMMAND_CONTRACT.to_string(),
            normalized_model_sha256,
            covered_manifest_repository_paths,
            target_count: provisional_targets.len(),
        },
        provisional_targets,
    ))
}

fn normalize_project(
    inventory: &IntentionalBoundaryRepositoryInventory,
    required_sources: &BTreeSet<String>,
    inferred_world: bool,
    project: CompilerProject,
) -> Result<IntentionalBoundaryProjectModelTypeScriptProject, String> {
    if inferred_world != project.config_path.is_none()
        || (inferred_world && (!project.config_reads.is_empty() || !project.references.is_empty()))
    {
        return Err("TypeScript compiler project config identity changed".to_string());
    }
    require_sorted_unique(&project.config_reads, "TypeScript compiler config reads")?;
    require_sorted_unique(&project.references, "TypeScript project references")?;
    require_sorted_unique(&project.selected_source_files, "TypeScript project sources")?;
    if project
        .selected_source_files
        .iter()
        .any(|path| !required_sources.contains(path))
    {
        return Err("TypeScript compiler project selected a non-required source".to_string());
    }
    let (config_repository_path, config_object_id) = match project.config_path {
        Some(path) => {
            let entry = regular_inventory_entry(inventory, &path, "TypeScript compiler config")?;
            (Some(path), Some(entry.object_id.clone()))
        }
        None => (None, None),
    };
    let config_reads = project
        .config_reads
        .into_iter()
        .map(|repository_path| {
            let entry = regular_inventory_entry(
                inventory,
                &repository_path,
                "TypeScript compiler config dependency",
            )?;
            Ok(IntentionalBoundaryProjectModelTypeScriptConfigRead {
                repository_path,
                object_id: entry.object_id.clone(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    for reference in &project.references {
        regular_inventory_entry(inventory, reference, "TypeScript project reference")?;
    }
    let effective_compiler_options_json = serde_json::to_string(&project.effective_options)
        .map_err(|error| format!("failed to commit TypeScript compiler options: {error}"))?;
    Ok(IntentionalBoundaryProjectModelTypeScriptProject {
        config_repository_path,
        config_object_id,
        config_reads,
        project_references: project.references,
        effective_compiler_options_json,
        source_repository_paths: project.selected_source_files,
    })
}

fn require_sorted_unique(values: &[String], label: &str) -> Result<(), String> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(format!("{label} is repeated or not canonical"));
    }
    Ok(())
}

fn is_config_candidate(repository_path: &str) -> bool {
    let name = repository_path
        .rsplit('/')
        .next()
        .unwrap_or(repository_path);
    let lower = name.to_ascii_lowercase();
    lower == "tsconfig.json"
        || lower == "jsconfig.json"
        || (lower.starts_with("tsconfig.") && lower.ends_with(".json"))
        || (lower.starts_with("jsconfig.") && lower.ends_with(".json"))
}

fn is_typescript_javascript_source(repository_path: &str) -> bool {
    let lower = repository_path.to_ascii_lowercase();
    [".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx"]
        .iter()
        .any(|extension| lower.ends_with(extension))
}

fn pinned_typescript_compiler_version() -> Result<&'static str, String> {
    let spec = pinned_indexer(SemanticIndexerKind::TypeScriptJavaScript)?;
    let IndexerInstallSource::NpmTarballs { packages } = spec.source else {
        return Err("pinned scip-typescript installation is not an npm closure".to_string());
    };
    let mut matches = packages
        .iter()
        .filter(|package| package.name == "typescript");
    let package = matches
        .next()
        .ok_or_else(|| "pinned scip-typescript closure omitted TypeScript".to_string())?;
    if matches.next().is_some() {
        return Err("pinned scip-typescript closure repeats TypeScript".to_string());
    }
    Ok(package.version)
}

impl IntentionalBoundaryProjectModelVariant {
    fn typescript_sources(&self) -> Option<&[String]> {
        match self {
            Self::TypeScript {
                selected_source_repository_paths,
                ..
            } => Some(selected_source_repository_paths),
            _ => None,
        }
    }
}

fn typescript_error(
    kind: ProjectModelDerivationErrorKind,
    phase: super::IntentionalBoundaryProjectModelFailurePhase,
    invocation_anchor_repository_path: Option<&str>,
    detail: impl Into<String>,
) -> ProjectModelDerivationError {
    project_model_error(
        kind,
        Provider::TypeScriptCompilerApi,
        phase,
        invocation_anchor_repository_path,
        detail,
    )
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_project_model_typescript_tests.rs"]
mod tests;
