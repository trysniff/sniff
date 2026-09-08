#[cfg(test)]
use super::intentional_boundary_project_model::validate_intentional_boundary_project_model_census_commitment;
use super::intentional_boundary_project_model::{
    compute_execution_id, compute_normalized_model_sha256, compute_target_id,
    finish_project_model_census, is_sha256, regular_inventory_entry, valid_gradle_source_set_graph,
};
#[cfg(test)]
use super::{
    IntentionalBoundaryManifestDeclarationKind,
    IntentionalBoundaryProjectModelTargetStatus as TargetStatus,
    IntentionalBoundaryProjectModelUnresolvedReason as UnresolvedReason,
};
use super::{
    IntentionalBoundaryProjectModelCensus, IntentionalBoundaryProjectModelExecution,
    IntentionalBoundaryProjectModelGradleKotlinProject,
    IntentionalBoundaryProjectModelGradlePublication,
    IntentionalBoundaryProjectModelKotlinCompilation,
    IntentionalBoundaryProjectModelKotlinSourceSet, IntentionalBoundaryProjectModelKotlinTarget,
    IntentionalBoundaryProjectModelProducerTask,
    IntentionalBoundaryProjectModelProvider as Provider, IntentionalBoundaryProjectModelTarget,
    IntentionalBoundaryRepositoryInventory,
};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::Path;

const GRADLE_MODEL_CONTRACT: &str = "sniff-gradle-tooling-project-model-v6";
const GRADLE_TOOLING_API_VERSION: &str = "8.8";
pub(super) const GRADLE_TOOLING_COMMAND_CONTRACT: &str =
    "gradle-tooling-api-8.8-custom-model-prepared-offline-v7";

#[path = "benchmark_intentional_boundary_project_model_gradle_runtime.rs"]
mod runtime;
pub use runtime::census_intentional_boundary_gradle_project_models;
pub(super) use runtime::census_intentional_boundary_gradle_project_models_typed;
#[cfg(test)]
use runtime::{GradleToolingExecutionOutput, census_gradle_project_models_with_executor};

#[path = "benchmark_intentional_boundary_project_model_gradle_validation.rs"]
mod validation;
pub use validation::validate_intentional_boundary_gradle_tooling_model;

#[path = "benchmark_intentional_boundary_project_model_gradle_producers.rs"]
mod producers;
use producers::normalize_producer_tasks;

#[path = "benchmark_intentional_boundary_project_model_gradle_classification.rs"]
mod classification;
pub(super) use classification::validate_gradle_target_classification;
use classification::{classify_target, output_types};

#[path = "benchmark_intentional_boundary_project_model_gradle_paths.rs"]
mod paths;
use paths::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GradleToolingOutput {
    contract: String,
    tooling_api_version: String,
    gradle_version: String,
    settings_directory: String,
    projects: Vec<GradleToolingProject>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GradleToolingProject {
    project_path: String,
    project_name: String,
    group_name: String,
    project_version: String,
    project_directory: String,
    build_file: String,
    build_file_exists: bool,
    provider_kinds: Vec<String>,
    production_source_files: Vec<String>,
    producer_tasks: Vec<GradleToolingProducerTask>,
    component_names: Vec<String>,
    publications: Vec<GradleToolingPublication>,
    kotlin_source_sets: Vec<GradleToolingKotlinSourceSet>,
    kotlin_targets: Vec<GradleToolingKotlinTarget>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GradleToolingPublication {
    name: String,
    publication_type: String,
    group_id: Option<String>,
    artifact_id: Option<String>,
    version: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GradleToolingKotlinSourceSet {
    name: String,
    source_files: Vec<String>,
    depends_on_source_sets: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GradleToolingKotlinCompilation {
    name: String,
    default_source_set: String,
    source_sets: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GradleToolingKotlinTarget {
    name: String,
    platform_type: String,
    publishable: bool,
    component_names: Vec<String>,
    compilations: Vec<GradleToolingKotlinCompilation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GradleToolingProducerTask {
    task_path: String,
    task_type: String,
    output_files: Vec<String>,
    production_source_files: Vec<String>,
}

struct GradleModelContext<'a> {
    root: &'a Path,
    emitted_root: &'a str,
    inventory: &'a IntentionalBoundaryRepositoryInventory,
    invocation_settings_repository_path: &'a str,
    revision: &'a str,
}

pub fn parse_intentional_boundary_gradle_tooling_model(
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    invocation_settings_repository_path: &str,
    toolchain_identity_sha256: &str,
    stdout: &[u8],
) -> Result<IntentionalBoundaryProjectModelCensus, String> {
    if !is_sha256(toolchain_identity_sha256) {
        return Err("Gradle Tooling API identity is not SHA-256".to_string());
    }
    let canonical_root = canonical_path(root, "Gradle project-model repository root")?;
    let invocation_entry = regular_inventory_entry(
        inventory,
        invocation_settings_repository_path,
        "Gradle Tooling API invocation settings file",
    )?;
    if !matches!(
        invocation_settings_repository_path.rsplit('/').next(),
        Some("settings.gradle" | "settings.gradle.kts")
    ) {
        return Err("Gradle Tooling API invocation anchor is not a settings file".to_string());
    }
    let model: GradleToolingOutput = serde_json::from_slice(stdout)
        .map_err(|error| format!("failed to parse Gradle Tooling API JSON: {error}"))?;
    if model.contract != GRADLE_MODEL_CONTRACT
        || model.tooling_api_version != GRADLE_TOOLING_API_VERSION
        || model.gradle_version != GRADLE_TOOLING_API_VERSION
    {
        return Err("Gradle Tooling API model contract or pinned version changed".to_string());
    }
    let emitted_root = emitted_repository_root(
        &model.settings_directory,
        invocation_settings_repository_path,
    )?;
    let context = GradleModelContext {
        root: &canonical_root,
        emitted_root: &emitted_root,
        inventory,
        invocation_settings_repository_path,
        revision: &inventory.revision,
    };
    let mut project_paths = BTreeSet::new();
    let mut covered_manifests = BTreeSet::from([invocation_settings_repository_path.to_string()]);
    let mut targets = Vec::new();
    let mut kotlin_projects = Vec::new();
    for project in model.projects {
        if !project_paths.insert(project.project_path.clone()) {
            return Err(format!(
                "Gradle Tooling API repeated project path {}",
                project.project_path
            ));
        }
        let (build_manifest, target, kotlin_project) = normalize_project(&context, project)?;
        covered_manifests.insert(build_manifest);
        if let Some(target) = target {
            targets.push(target);
        }
        if let Some(kotlin_project) = kotlin_project {
            kotlin_projects.push(kotlin_project);
        }
    }
    targets.sort();
    kotlin_projects.sort();
    let covered_manifests = covered_manifests.into_iter().collect::<Vec<_>>();
    let variant = super::IntentionalBoundaryProjectModelVariant::Gradle { kotlin_projects };
    let normalized_model_sha256 =
        compute_normalized_model_sha256(Provider::GradleToolingApi, &covered_manifests, &targets)?;
    let execution_id = compute_execution_id(
        Provider::GradleToolingApi,
        invocation_settings_repository_path,
        &invocation_entry.object_id,
        toolchain_identity_sha256,
        GRADLE_TOOLING_COMMAND_CONTRACT,
        &variant,
        &normalized_model_sha256,
    )?;
    for target in &mut targets {
        target.execution_id = execution_id.clone();
        target.target_id = compute_target_id(target)?;
    }
    targets.sort();
    if targets.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("Gradle Tooling API produced duplicate normalized projects".to_string());
    }
    let execution = IntentionalBoundaryProjectModelExecution {
        execution_id,
        provider: Provider::GradleToolingApi,
        variant,
        invocation_anchor_repository_path: invocation_settings_repository_path.to_string(),
        invocation_anchor_object_id: invocation_entry.object_id.clone(),
        toolchain_identity_sha256: toolchain_identity_sha256.to_string(),
        command_contract: GRADLE_TOOLING_COMMAND_CONTRACT.to_string(),
        normalized_model_sha256,
        covered_manifest_repository_paths: covered_manifests,
        target_count: targets.len(),
    };
    finish_project_model_census(inventory, vec![execution], targets)
}

fn normalize_project(
    context: &GradleModelContext<'_>,
    project: GradleToolingProject,
) -> Result<
    (
        String,
        Option<IntentionalBoundaryProjectModelTarget>,
        Option<IntentionalBoundaryProjectModelGradleKotlinProject>,
    ),
    String,
> {
    if !valid_gradle_project_path(&project.project_path) || project.project_name.trim().is_empty() {
        return Err("Gradle Tooling API project identity is invalid".to_string());
    }
    let project_directory = emitted_host_path(
        context.root,
        context.emitted_root,
        &project.project_directory,
        "Gradle project directory",
        true,
    )?;
    let manifest_repository_path = if project.build_file_exists {
        let build_file = emitted_host_path(
            context.root,
            context.emitted_root,
            &project.build_file,
            "Gradle build file",
            false,
        )?;
        if !build_file.starts_with(&project_directory) {
            return Err("Gradle build file is outside its project directory".to_string());
        }
        repository_path(context.root, &build_file)?
    } else {
        context.invocation_settings_repository_path.to_string()
    };
    let manifest_entry = regular_inventory_entry(
        context.inventory,
        &manifest_repository_path,
        "Gradle project build file",
    )?;
    let kotlin_project = normalize_kotlin_project(context, &project)?;
    let mut provider_kinds = project.provider_kinds;
    provider_kinds.sort();
    if provider_kinds.is_empty() || provider_kinds.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("Gradle Tooling API provider kinds are empty or repeated".to_string());
    }
    let mut source_repository_paths = project
        .production_source_files
        .iter()
        .map(|path| {
            emitted_host_path(
                context.root,
                context.emitted_root,
                path,
                "Gradle production source",
                false,
            )
            .and_then(|path| repository_path(context.root, &path))
        })
        .collect::<Result<Vec<_>, String>>()?;
    source_repository_paths.sort();
    if source_repository_paths
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err("Gradle Tooling API repeated a production source file".to_string());
    }
    if source_repository_paths.is_empty() {
        return Ok((manifest_repository_path, None, kotlin_project));
    }
    let provider_output_types = output_types(&provider_kinds);
    let target_status =
        classify_target(context.inventory, &provider_kinds, &source_repository_paths);
    let producer_tasks = normalize_producer_tasks(
        context,
        &project_directory,
        &source_repository_paths,
        project.producer_tasks,
    )?;
    let group = project.group_name.trim();
    let package_name = if group.is_empty() || group == "unspecified" {
        format!("gradle:{}", project.project_path)
    } else {
        format!("{group}:{}", project.project_name)
    };
    let version = project.project_version.trim();
    let package_version = if version.is_empty() || version == "unspecified" {
        format!("git:{}", context.revision)
    } else {
        version.to_string()
    };
    Ok((
        manifest_repository_path.clone(),
        Some(IntentionalBoundaryProjectModelTarget {
            target_id: String::new(),
            execution_id: String::new(),
            provider: Provider::GradleToolingApi,
            manifest_repository_path,
            manifest_object_id: manifest_entry.object_id.clone(),
            package_name,
            package_version,
            target_name: project.project_path,
            provider_kinds,
            provider_output_types,
            source_repository_paths,
            ignored_source_repository_paths: Vec::new(),
            producer_tasks,
            required_features: Vec::new(),
            target_status,
        }),
        kotlin_project,
    ))
}

fn normalize_kotlin_project(
    context: &GradleModelContext<'_>,
    project: &GradleToolingProject,
) -> Result<Option<IntentionalBoundaryProjectModelGradleKotlinProject>, String> {
    if project.kotlin_source_sets.is_empty() && project.kotlin_targets.is_empty() {
        return Ok(None);
    }
    if project.kotlin_source_sets.is_empty() || project.kotlin_targets.is_empty() {
        return Err(format!(
            "Gradle Kotlin project {} omitted source sets or targets",
            project.project_path
        ));
    }
    let mut component_names = project.component_names.clone();
    component_names.sort();
    require_sorted_unique_non_empty_values(&component_names, "Gradle component")?;
    let mut publications = project
        .publications
        .iter()
        .map(|publication| {
            let coordinates = [
                publication.group_id.as_deref(),
                publication.artifact_id.as_deref(),
                publication.version.as_deref(),
            ];
            if publication.name.trim().is_empty()
                || publication.publication_type.trim().is_empty()
                || (coordinates.iter().any(|value| value.is_some())
                    && coordinates
                        .iter()
                        .any(|value| value.is_none_or(|value| value.trim().is_empty())))
            {
                return Err(format!(
                    "Gradle publication identity is incomplete in {}",
                    project.project_path
                ));
            }
            Ok(IntentionalBoundaryProjectModelGradlePublication {
                name: publication.name.clone(),
                publication_type: publication.publication_type.clone(),
                group_id: publication.group_id.clone(),
                artifact_id: publication.artifact_id.clone(),
                version: publication.version.clone(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    publications.sort();
    require_strictly_sorted(&publications, "Gradle publication")?;

    let mut source_sets = project
        .kotlin_source_sets
        .iter()
        .map(|source_set| {
            if source_set.name.trim().is_empty() {
                return Err(format!(
                    "Gradle Kotlin source set has no name in {}",
                    project.project_path
                ));
            }
            let mut source_repository_paths = source_set
                .source_files
                .iter()
                .map(|path| {
                    emitted_host_path(
                        context.root,
                        context.emitted_root,
                        path,
                        "Gradle Kotlin source-set source",
                        false,
                    )
                    .and_then(|path| repository_path(context.root, &path))
                })
                .collect::<Result<Vec<_>, String>>()?;
            source_repository_paths.sort();
            require_strictly_sorted(&source_repository_paths, "Gradle Kotlin source-set source")?;
            let mut depends_on_source_sets = source_set.depends_on_source_sets.clone();
            depends_on_source_sets.sort();
            require_sorted_unique_non_empty_values(
                &depends_on_source_sets,
                "Gradle Kotlin source-set dependency",
            )?;
            Ok(IntentionalBoundaryProjectModelKotlinSourceSet {
                name: source_set.name.clone(),
                source_repository_paths,
                depends_on_source_sets,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    source_sets.sort();
    require_strictly_sorted(&source_sets, "Gradle Kotlin source set")?;
    let source_set_names = source_sets
        .iter()
        .map(|source_set| source_set.name.as_str())
        .collect::<BTreeSet<_>>();
    for source_set in &source_sets {
        if source_set.depends_on_source_sets.iter().any(|dependency| {
            dependency == &source_set.name || !source_set_names.contains(dependency.as_str())
        }) {
            return Err(format!(
                "Gradle Kotlin source set {} has an unknown or cyclic self dependency",
                source_set.name
            ));
        }
    }
    let graph_project = IntentionalBoundaryProjectModelGradleKotlinProject {
        project_path: project.project_path.clone(),
        component_names: component_names.clone(),
        publications: publications.clone(),
        source_sets: source_sets.clone(),
        targets: Vec::new(),
    };
    if !valid_gradle_source_set_graph(&graph_project) {
        return Err(format!(
            "Gradle Kotlin source-set dependency graph is cyclic in {}",
            project.project_path
        ));
    }

    let mut targets = project
        .kotlin_targets
        .iter()
        .map(|target| {
            normalize_kotlin_target(
                &project.project_path,
                target,
                &source_set_names,
                &component_names,
            )
        })
        .collect::<Result<Vec<_>, String>>()?;
    targets.sort();
    require_strictly_sorted(&targets, "Gradle Kotlin target")?;
    Ok(Some(IntentionalBoundaryProjectModelGradleKotlinProject {
        project_path: project.project_path.clone(),
        component_names,
        publications,
        source_sets,
        targets,
    }))
}

fn normalize_kotlin_target(
    project_path: &str,
    target: &GradleToolingKotlinTarget,
    source_set_names: &BTreeSet<&str>,
    project_component_names: &[String],
) -> Result<IntentionalBoundaryProjectModelKotlinTarget, String> {
    if target.name.trim().is_empty() || target.platform_type.trim().is_empty() {
        return Err(format!(
            "Gradle Kotlin target identity is incomplete in {project_path}"
        ));
    }
    let mut component_names = target.component_names.clone();
    component_names.sort();
    require_sorted_unique_non_empty_values(&component_names, "Gradle Kotlin target component")?;
    if target.publishable && component_names.is_empty() {
        return Err(format!(
            "publishable Gradle Kotlin target {} has no software component",
            target.name
        ));
    }
    if component_names
        .iter()
        .any(|component| project_component_names.binary_search(component).is_err())
    {
        return Err(format!(
            "Gradle Kotlin target {} references an unknown project component",
            target.name
        ));
    }
    let mut compilations = target
        .compilations
        .iter()
        .map(|compilation| {
            let mut source_sets = compilation.source_sets.clone();
            source_sets.sort();
            require_sorted_unique_non_empty_values(
                &source_sets,
                "Gradle Kotlin compilation source set",
            )?;
            if compilation.name.trim().is_empty()
                || compilation.default_source_set.trim().is_empty()
                || !source_sets.contains(&compilation.default_source_set)
                || source_sets
                    .iter()
                    .any(|source_set| !source_set_names.contains(source_set.as_str()))
            {
                return Err(format!(
                    "Gradle Kotlin compilation identity or source-set closure is incomplete for {}:{}",
                    target.name, compilation.name
                ));
            }
            Ok(IntentionalBoundaryProjectModelKotlinCompilation {
                name: compilation.name.clone(),
                default_source_set: compilation.default_source_set.clone(),
                source_sets,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    compilations.sort();
    require_strictly_sorted(&compilations, "Gradle Kotlin compilation")?;
    if target.publishable
        && !compilations
            .iter()
            .any(|compilation| compilation.name == "main")
        && target.platform_type != "common"
    {
        return Err(format!(
            "publishable Gradle Kotlin target {} has no main compilation",
            target.name
        ));
    }
    Ok(IntentionalBoundaryProjectModelKotlinTarget {
        name: target.name.clone(),
        platform_type: target.platform_type.clone(),
        publishable: target.publishable,
        component_names,
        compilations,
    })
}

fn require_sorted_unique_non_empty_values(values: &[String], label: &str) -> Result<(), String> {
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(format!("{label} identity is empty"));
    }
    require_strictly_sorted(values, label)
}

fn require_strictly_sorted<T: Ord>(values: &[T], label: &str) -> Result<(), String> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(format!("{label} identity is repeated"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_project_model_gradle_tests.rs"]
mod tests;
