#[cfg(test)]
use super::intentional_boundary_project_model::validate_intentional_boundary_project_model_census_commitment;
use super::intentional_boundary_project_model::{
    compute_execution_id, compute_normalized_model_sha256, compute_target_id,
    finish_project_model_census, is_sha256, regular_inventory_entry,
};
use super::{
    BoundaryGitEntryKind, IntentionalBoundaryManifestDeclarationKind,
    IntentionalBoundaryManifestTarget, IntentionalBoundaryProjectModelCensus,
    IntentionalBoundaryProjectModelExecution, IntentionalBoundaryProjectModelProvider as Provider,
    IntentionalBoundaryProjectModelTarget,
    IntentionalBoundaryProjectModelTargetStatus as TargetStatus,
    IntentionalBoundaryProjectModelUnresolvedReason as UnresolvedReason,
    IntentionalBoundaryRepositoryInventory,
};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

const GRADLE_MODEL_CONTRACT: &str = "sniff-gradle-tooling-project-model-v2";
const GRADLE_TOOLING_API_VERSION: &str = "8.8";
pub(super) const GRADLE_TOOLING_COMMAND_CONTRACT: &str =
    "gradle-tooling-api-8.8-custom-model-offline-v2";

#[path = "benchmark_intentional_boundary_project_model_gradle_runtime.rs"]
mod runtime;
pub use runtime::census_intentional_boundary_gradle_project_models;
#[cfg(test)]
use runtime::{GradleToolingExecutionOutput, census_gradle_project_models_with_executor};

#[path = "benchmark_intentional_boundary_project_model_gradle_validation.rs"]
mod validation;
pub use validation::validate_intentional_boundary_gradle_tooling_model;

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
            required_features: Vec::new(),
            target_status,
        }),
    ))
}

fn classify_target(
    inventory: &IntentionalBoundaryRepositoryInventory,
    provider_kinds: &[String],
    source_repository_paths: &[String],
) -> TargetStatus {
    if source_repository_paths.is_empty() {
        return unresolved(
            UnresolvedReason::SourceSetEmpty,
            "Gradle project has no Tooling API production source files".to_string(),
        );
    }
    for repository_path in source_repository_paths {
        let Some(entry) = inventory
            .tracked_entries
            .iter()
            .find(|entry| entry.repository_path == *repository_path)
        else {
            return unresolved(
                UnresolvedReason::SourceNotTracked,
                "Gradle production source is not present in the immutable Git inventory"
                    .to_string(),
            );
        };
        if entry.kind != BoundaryGitEntryKind::RegularBlob {
            return unresolved(
                UnresolvedReason::SourceNotRegularBlob,
                "Gradle production source is not a regular Git blob".to_string(),
            );
        }
    }
    let has_application = provider_kinds.iter().any(|kind| kind == "application");
    let has_library = provider_kinds.iter().any(|kind| {
        matches!(
            kind.as_str(),
            "gradle_plugin" | "java_library" | "publication"
        )
    });
    let has_unknown = provider_kinds.iter().any(|kind| {
        !matches!(
            kind.as_str(),
            "application" | "gradle_plugin" | "java_library" | "publication" | "unclassified"
        )
    });
    if has_unknown || provider_kinds == ["unclassified"] {
        return unresolved(
            UnresolvedReason::UnknownTargetKind,
            "Gradle project has no explicit application, library, plugin, or publication contract"
                .to_string(),
        );
    }
    if has_application == has_library {
        return unresolved(
            UnresolvedReason::ConflictingTargetKinds,
            "Gradle project has conflicting or missing boundary plugin roles".to_string(),
        );
    }
    boundary(
        if has_application {
            IntentionalBoundaryManifestDeclarationKind::RuntimeEntrypoint
        } else {
            IntentionalBoundaryManifestDeclarationKind::PublishedModule
        },
        source_repository_paths,
    )
}

fn output_types(provider_kinds: &[String]) -> Vec<String> {
    let mut values = Vec::new();
    if provider_kinds.iter().any(|kind| kind == "application") {
        values.push("jvm_application".to_string());
    }
    if provider_kinds.iter().any(|kind| {
        matches!(
            kind.as_str(),
            "gradle_plugin" | "java_library" | "publication"
        )
    }) {
        values.push("jvm_library".to_string());
    }
    if values.is_empty() {
        values.push("jvm_classes".to_string());
    }
    values
}

pub(super) fn validate_gradle_target_classification(
    inventory: &IntentionalBoundaryRepositoryInventory,
    target: &IntentionalBoundaryProjectModelTarget,
) -> bool {
    target.provider == Provider::GradleToolingApi
        && target.required_features.is_empty()
        && target.provider_output_types == output_types(&target.provider_kinds)
        && target.target_status
            == classify_target(
                inventory,
                &target.provider_kinds,
                &target.source_repository_paths,
            )
}

fn boundary(
    declaration_kind: IntentionalBoundaryManifestDeclarationKind,
    repository_paths: &[String],
) -> TargetStatus {
    TargetStatus::Boundary {
        declaration_kind,
        target: IntentionalBoundaryManifestTarget::RepositoryPaths {
            repository_paths: repository_paths.to_vec(),
        },
    }
}

fn unresolved(reason: UnresolvedReason, detail: String) -> TargetStatus {
    TargetStatus::Unresolved { reason, detail }
}

fn valid_gradle_project_path(path: &str) -> bool {
    path == ":"
        || path
            .strip_prefix(':')
            .is_some_and(|value| !value.is_empty() && value.split(':').all(valid_gradle_name))
}

fn valid_gradle_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|character| !character.is_control() && !matches!(character, ':' | '/' | '\\'))
}

fn canonical_path(path: &Path, label: &str) -> Result<PathBuf, String> {
    fs::canonicalize(path)
        .map(strip_windows_verbatim_prefix)
        .map_err(|error| format!("failed to resolve {label}: {error}"))
}

fn emitted_repository_root(
    settings_directory: &str,
    invocation_settings_repository_path: &str,
) -> Result<String, String> {
    let settings_directory = settings_directory.replace('\\', "/");
    let invocation_directory = invocation_settings_repository_path
        .rsplit_once('/')
        .map_or("", |(directory, _)| directory);
    if invocation_directory.is_empty() {
        let root = settings_directory.trim_end_matches('/');
        return (!root.is_empty())
            .then(|| root.to_string())
            .ok_or_else(|| "Gradle Tooling API emitted an invalid repository root".to_string());
    }
    let suffix = format!("/{invocation_directory}");
    if !path_ends_with(&settings_directory, &suffix) {
        return Err(
            "Gradle settings directory does not match the invocation settings file".to_string(),
        );
    }
    let root = settings_directory[..settings_directory.len() - suffix.len()].trim_end_matches('/');
    if root.is_empty() {
        return Err("Gradle Tooling API emitted an invalid repository root".to_string());
    }
    Ok(root.to_string())
}

fn emitted_host_path(
    root: &Path,
    emitted_root: &str,
    raw: &str,
    label: &str,
    allow_root: bool,
) -> Result<PathBuf, String> {
    let raw = raw.replace('\\', "/");
    let emitted_root = emitted_root.trim_end_matches('/');
    let relative = if path_eq(&raw, emitted_root) {
        ""
    } else {
        let prefix = format!("{emitted_root}/");
        if !path_starts_with(&raw, &prefix) {
            return Err(format!("{label} is outside the emitted repository"));
        }
        &raw[prefix.len()..]
    };
    let relative_path = Path::new(relative);
    if (!allow_root && relative.is_empty())
        || relative_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("{label} is not safely repository-relative"));
    }
    let path = canonical_path(&root.join(relative_path), label)?;
    if !path.starts_with(root) {
        return Err(format!("{label} escaped the immutable repository"));
    }
    Ok(path)
}

fn path_eq(left: &str, right: &str) -> bool {
    if cfg!(windows) {
        left.eq_ignore_ascii_case(right)
    } else {
        left == right
    }
}

fn path_starts_with(path: &str, prefix: &str) -> bool {
    if cfg!(windows) {
        path.get(..prefix.len())
            .is_some_and(|value| value.eq_ignore_ascii_case(prefix))
    } else {
        path.starts_with(prefix)
    }
}

fn path_ends_with(path: &str, suffix: &str) -> bool {
    if cfg!(windows) {
        path.to_ascii_lowercase()
            .ends_with(&suffix.to_ascii_lowercase())
    } else {
        path.ends_with(suffix)
    }
}

fn repository_path(root: &Path, raw: &Path) -> Result<String, String> {
    let path = canonical_path(raw, "Gradle project-model path")?;
    let relative = path
        .strip_prefix(root)
        .map_err(|_| "Gradle project-model path is outside repository".to_string())?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("Gradle project-model path is not safely repository-relative".to_string());
    }
    Ok(relative.to_string_lossy().replace('\\', "/"))
}

fn strip_windows_verbatim_prefix(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        use std::path::Prefix;
        let mut components = path.components();
        let Some(Component::Prefix(prefix)) = components.next() else {
            return path;
        };
        match prefix.kind() {
            Prefix::VerbatimDisk(letter) => {
                let mut normalized = PathBuf::from(format!("{}:\\", letter as char));
                normalized.extend(
                    components.filter(|component| !matches!(component, Component::RootDir)),
                );
                normalized
            }
            _ => path,
        }
    }
    #[cfg(not(windows))]
    {
        path
    }
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_project_model_gradle_tests.rs"]
mod tests;
