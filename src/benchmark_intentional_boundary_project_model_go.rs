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
    IntentionalBoundaryRepositoryInventory, validate_intentional_boundary_repository_inventory,
};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

pub(super) const GO_LIST_COMMAND_CONTRACT: &str = "go-list-json-find-mod-readonly-workspace-off-v1";

#[path = "benchmark_intentional_boundary_project_model_go_runtime.rs"]
mod runtime;
pub use runtime::census_intentional_boundary_go_project_models;
#[cfg(test)]
use runtime::{GoListExecutionOutput, census_go_project_models_with_executor};

#[path = "benchmark_intentional_boundary_project_model_go_validation.rs"]
mod validation;
pub use validation::validate_intentional_boundary_go_list;

#[derive(Deserialize)]
struct GoListPackage {
    #[serde(rename = "Dir")]
    dir: String,
    #[serde(rename = "ImportPath")]
    import_path: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(default, rename = "GoFiles")]
    go_files: Vec<String>,
    #[serde(default, rename = "CgoFiles")]
    cgo_files: Vec<String>,
    #[serde(default, rename = "IgnoredGoFiles")]
    ignored_go_files: Vec<String>,
    #[serde(rename = "Module")]
    module: Option<GoListModule>,
    #[serde(default, rename = "Incomplete")]
    incomplete: bool,
    #[serde(rename = "Error")]
    error: Option<GoListError>,
}

#[derive(Deserialize)]
struct GoListModule {
    #[serde(rename = "Path")]
    path: String,
    #[serde(default, rename = "Version")]
    version: String,
    #[serde(rename = "Dir")]
    dir: String,
    #[serde(rename = "GoMod")]
    go_mod: String,
    #[serde(default, rename = "Main")]
    main: bool,
}

#[derive(Deserialize)]
struct GoListError {
    #[serde(rename = "Err")]
    message: String,
}

struct GoPackageContext<'a> {
    root: &'a Path,
    inventory: &'a IntentionalBoundaryRepositoryInventory,
    manifest_repository_path: &'a str,
    manifest_object_id: &'a str,
    revision: &'a str,
}

pub fn parse_intentional_boundary_go_list(
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    invocation_manifest_repository_path: &str,
    toolchain_identity_sha256: &str,
    stdout: &[u8],
) -> Result<IntentionalBoundaryProjectModelCensus, String> {
    if !is_sha256(toolchain_identity_sha256) {
        return Err("Go toolchain identity is not SHA-256".to_string());
    }
    let canonical_root = canonical_path(root, "Go project-model repository root")?;
    let invocation_entry = regular_inventory_entry(
        inventory,
        invocation_manifest_repository_path,
        "Go project-model invocation manifest",
    )?;
    if invocation_manifest_repository_path.rsplit('/').next() != Some("go.mod") {
        return Err("Go project-model invocation anchor is not go.mod".to_string());
    }
    let context = GoPackageContext {
        root: &canonical_root,
        inventory,
        manifest_repository_path: invocation_manifest_repository_path,
        manifest_object_id: &invocation_entry.object_id,
        revision: &inventory.revision,
    };
    let mut targets = Vec::new();
    let mut import_paths = BTreeSet::new();
    let packages = serde_json::Deserializer::from_slice(stdout).into_iter::<GoListPackage>();
    for package in packages {
        let package = package
            .map_err(|error| format!("failed to parse concatenated go list JSON: {error}"))?;
        if package.incomplete || package.error.is_some() {
            let detail = package.error.map_or_else(
                || "package was marked incomplete".to_string(),
                |error| error.message,
            );
            return Err(format!("go list reported an incomplete package: {detail}"));
        }
        if !import_paths.insert(package.import_path.clone()) {
            return Err(format!(
                "go list repeated package import path {}",
                package.import_path
            ));
        }
        targets.push(normalize_package(&context, package)?);
    }
    targets.sort();
    let covered_manifests = vec![invocation_manifest_repository_path.to_string()];
    let normalized_model_sha256 =
        compute_normalized_model_sha256(Provider::GoList, &covered_manifests, &targets)?;
    let execution_id = compute_execution_id(
        Provider::GoList,
        invocation_manifest_repository_path,
        &invocation_entry.object_id,
        toolchain_identity_sha256,
        GO_LIST_COMMAND_CONTRACT,
        &normalized_model_sha256,
    )?;
    for target in &mut targets {
        target.execution_id = execution_id.clone();
        target.target_id = compute_target_id(target)?;
    }
    targets.sort();
    if targets.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("go list produced duplicate normalized packages".to_string());
    }
    let execution = IntentionalBoundaryProjectModelExecution {
        execution_id,
        provider: Provider::GoList,
        invocation_anchor_repository_path: invocation_manifest_repository_path.to_string(),
        invocation_anchor_object_id: invocation_entry.object_id.clone(),
        toolchain_identity_sha256: toolchain_identity_sha256.to_string(),
        command_contract: GO_LIST_COMMAND_CONTRACT.to_string(),
        normalized_model_sha256,
        covered_manifest_repository_paths: covered_manifests,
        target_count: targets.len(),
    };
    finish_project_model_census(inventory, vec![execution], targets)
}

fn normalize_package(
    context: &GoPackageContext<'_>,
    package: GoListPackage,
) -> Result<IntentionalBoundaryProjectModelTarget, String> {
    let module = package
        .module
        .ok_or_else(|| "go list package omitted module ownership".to_string())?;
    if !module.main {
        return Err(format!(
            "go list package is not owned by the invoked main module: {}",
            package.import_path
        ));
    }
    if module.path.trim().is_empty()
        || package.import_path.trim().is_empty()
        || package.name.trim().is_empty()
        || (package.import_path != module.path
            && !package
                .import_path
                .strip_prefix(&module.path)
                .is_some_and(|suffix| suffix.starts_with('/')))
    {
        return Err("go list package identity is inconsistent with its module".to_string());
    }
    let module_directory = canonical_path(Path::new(&module.dir), "Go module directory")?;
    let package_directory = canonical_path(Path::new(&package.dir), "Go package directory")?;
    if !module_directory.starts_with(context.root)
        || !package_directory.starts_with(&module_directory)
    {
        return Err("go list package directory is outside its immutable module".to_string());
    }
    let emitted_manifest = repository_path(context.root, Path::new(&module.go_mod))?;
    if emitted_manifest != context.manifest_repository_path {
        return Err(format!(
            "go list module manifest changed: expected {}, found {emitted_manifest}",
            context.manifest_repository_path
        ));
    }

    let mut source_names = package.go_files;
    source_names.extend(package.cgo_files);
    source_names.extend(package.ignored_go_files);
    source_names.sort();
    if source_names.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("go list repeated a production source filename".to_string());
    }
    let source_repository_paths =
        normalize_source_set(context.root, &package_directory, &source_names)?;
    let provider_kind = if package.name == "main" {
        "main"
    } else {
        "package"
    };
    let provider_kinds = vec![provider_kind.to_string()];
    let provider_output_types = vec![if provider_kind == "main" {
        "executable".to_string()
    } else {
        "package_archive".to_string()
    }];
    let target_status =
        classify_target(context.inventory, &provider_kinds, &source_repository_paths);
    let package_version = if module.version.trim().is_empty() {
        format!("git:{}", context.revision)
    } else {
        module.version
    };
    Ok(IntentionalBoundaryProjectModelTarget {
        target_id: String::new(),
        execution_id: String::new(),
        provider: Provider::GoList,
        manifest_repository_path: context.manifest_repository_path.to_string(),
        manifest_object_id: context.manifest_object_id.to_string(),
        package_name: module.path,
        package_version,
        target_name: package.import_path,
        provider_kinds,
        provider_output_types,
        source_repository_paths,
        required_features: Vec::new(),
        target_status,
    })
}

fn normalize_source_set(
    root: &Path,
    package_directory: &Path,
    source_names: &[String],
) -> Result<Vec<String>, String> {
    let mut paths = Vec::with_capacity(source_names.len());
    for source_name in source_names {
        let source_path = Path::new(source_name);
        if source_path.extension().and_then(|value| value.to_str()) != Some("go")
            || source_path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
            || source_path.components().count() != 1
        {
            return Err(format!(
                "go list returned an unsafe production source filename: {source_name}"
            ));
        }
        let repository_path = repository_path(root, &package_directory.join(source_path))?;
        paths.push(repository_path);
    }
    paths.sort();
    Ok(paths)
}

fn classify_target(
    inventory: &IntentionalBoundaryRepositoryInventory,
    provider_kinds: &[String],
    source_repository_paths: &[String],
) -> TargetStatus {
    if source_repository_paths.is_empty() {
        return unresolved(
            UnresolvedReason::SourceSetEmpty,
            "Go package has no compiler-reported production source files".to_string(),
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
                "Go package source is not present in the immutable Git inventory".to_string(),
            );
        };
        if entry.kind != BoundaryGitEntryKind::RegularBlob {
            return unresolved(
                UnresolvedReason::SourceNotRegularBlob,
                "Go package source is not a regular Git blob".to_string(),
            );
        }
    }
    match provider_kinds {
        [kind] if kind == "main" => boundary(
            IntentionalBoundaryManifestDeclarationKind::RuntimeEntrypoint,
            source_repository_paths,
        ),
        [kind] if kind == "package" => boundary(
            IntentionalBoundaryManifestDeclarationKind::PublishedModule,
            source_repository_paths,
        ),
        [_] => unresolved(
            UnresolvedReason::UnknownTargetKind,
            "Go package kind is not covered by the frozen provider contract".to_string(),
        ),
        _ => unresolved(
            UnresolvedReason::ConflictingTargetKinds,
            "Go package has conflicting or missing package kinds".to_string(),
        ),
    }
}

pub(super) fn validate_go_target_classification(
    inventory: &IntentionalBoundaryRepositoryInventory,
    target: &IntentionalBoundaryProjectModelTarget,
) -> bool {
    if target.provider != Provider::GoList
        || !target.required_features.is_empty()
        || target.provider_kinds.len() != 1
        || target.provider_output_types.len() != 1
    {
        return false;
    }
    let output_matches = match target.provider_kinds[0].as_str() {
        "main" => target.provider_output_types[0] == "executable",
        "package" => target.provider_output_types[0] == "package_archive",
        _ => false,
    };
    output_matches
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

fn canonical_path(path: &Path, label: &str) -> Result<PathBuf, String> {
    fs::canonicalize(path)
        .map(strip_windows_verbatim_prefix)
        .map_err(|error| format!("failed to resolve {label}: {error}"))
}

fn repository_path(root: &Path, raw: &Path) -> Result<String, String> {
    let path = canonical_path(raw, "Go project-model path")?;
    let relative = path
        .strip_prefix(root)
        .map_err(|_| "Go project-model path is outside repository".to_string())?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("Go project-model path is not safely repository-relative".to_string());
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
#[path = "benchmark_intentional_boundary_project_model_go_tests.rs"]
mod tests;
