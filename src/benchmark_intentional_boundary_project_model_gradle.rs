#[cfg(test)]
use super::intentional_boundary_project_model::validate_intentional_boundary_project_model_census_commitment;
use super::intentional_boundary_project_model::{
    compute_execution_id, compute_normalized_model_sha256, compute_target_id,
    finish_project_model_census, is_sha256, regular_inventory_entry,
};
#[cfg(test)]
use super::{
    IntentionalBoundaryManifestDeclarationKind,
    IntentionalBoundaryProjectModelTargetStatus as TargetStatus,
    IntentionalBoundaryProjectModelUnresolvedReason as UnresolvedReason,
};
use super::{
    IntentionalBoundaryProjectModelCensus, IntentionalBoundaryProjectModelExecution,
    IntentionalBoundaryProjectModelProducerTask,
    IntentionalBoundaryProjectModelProvider as Provider, IntentionalBoundaryProjectModelTarget,
    IntentionalBoundaryRepositoryInventory,
};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::Path;

const GRADLE_MODEL_CONTRACT: &str = "sniff-gradle-tooling-project-model-v4";
const GRADLE_TOOLING_API_VERSION: &str = "8.8";
pub(super) const GRADLE_TOOLING_COMMAND_CONTRACT: &str =
    "gradle-tooling-api-8.8-custom-model-offline-v4";

#[path = "benchmark_intentional_boundary_project_model_gradle_runtime.rs"]
mod runtime;
pub use runtime::census_intentional_boundary_gradle_project_models;
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
    for project in model.projects {
        if !project_paths.insert(project.project_path.clone()) {
            return Err(format!(
                "Gradle Tooling API repeated project path {}",
                project.project_path
            ));
        }
        let (build_manifest, target) = normalize_project(&context, project)?;
        covered_manifests.insert(build_manifest);
        if let Some(target) = target {
            targets.push(target);
        }
    }
    targets.sort();
    let covered_manifests = covered_manifests.into_iter().collect::<Vec<_>>();
    let normalized_model_sha256 =
        compute_normalized_model_sha256(Provider::GradleToolingApi, &covered_manifests, &targets)?;
    let execution_id = compute_execution_id(
        Provider::GradleToolingApi,
        invocation_settings_repository_path,
        &invocation_entry.object_id,
        toolchain_identity_sha256,
        GRADLE_TOOLING_COMMAND_CONTRACT,
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
) -> Result<(String, Option<IntentionalBoundaryProjectModelTarget>), String> {
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
        return Ok((manifest_repository_path, None));
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
            producer_tasks,
            required_features: Vec::new(),
            target_status,
        }),
    ))
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_project_model_gradle_tests.rs"]
mod tests;
