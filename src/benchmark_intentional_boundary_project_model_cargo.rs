use super::non_blind_history_runtime::{HistoricalRuntimePlanError, prepare_historical_runtime};
use super::{
    BoundaryGitEntryKind, INTENTIONAL_BOUNDARY_PROJECT_MODEL_CENSUS_SCHEMA_VERSION,
    IntentionalBoundaryManifestDeclarationKind, IntentionalBoundaryManifestTarget,
    IntentionalBoundaryProjectModelCensus, IntentionalBoundaryProjectModelExecution,
    IntentionalBoundaryProjectModelNonBoundaryReason as NonBoundaryReason,
    IntentionalBoundaryProjectModelProvider as Provider, IntentionalBoundaryProjectModelTarget,
    IntentionalBoundaryProjectModelTargetStatus as TargetStatus,
    IntentionalBoundaryProjectModelUnresolvedReason as UnresolvedReason,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundaryTrackedEntry,
    validate_intentional_boundary_repository_inventory,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

const PROJECT_MODEL_CONTRACT: &str = "sniffbench-intentional-boundary-project-model-v1";
const CARGO_COMMAND_CONTRACT: &str = "cargo-metadata-format-v1-no-deps-offline-v1";
const CARGO_METADATA_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const CARGO_METADATA_OUTPUT_LIMIT: usize = 16 * 1024 * 1024;
static CARGO_RUNTIME_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct CargoMetadataRuntime(PathBuf);

impl CargoMetadataRuntime {
    fn create(root: &Path) -> Result<Self, String> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                format!("system clock cannot allocate Cargo metadata runtime: {error}")
            })?
            .as_nanos();
        for _ in 0..128 {
            let sequence = CARGO_RUNTIME_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = root.join(format!(
                ".sniff-cargo-metadata-{}-{timestamp}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(format!(
                        "failed to create private Cargo metadata runtime: {error}"
                    ));
                }
            }
        }
        Err("failed to allocate a unique private Cargo metadata runtime".to_string())
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for CargoMetadataRuntime {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct CargoMetadataExecutionOutput {
    toolchain_identity_sha256: String,
    stdout: String,
}

#[derive(Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
    workspace_members: Vec<String>,
    workspace_root: String,
    version: u32,
}

#[derive(Deserialize)]
struct CargoPackage {
    id: String,
    name: String,
    version: String,
    manifest_path: String,
    targets: Vec<CargoTarget>,
}

#[derive(Deserialize)]
struct CargoTarget {
    name: String,
    kind: Vec<String>,
    crate_types: Vec<String>,
    src_path: String,
    #[serde(default, rename = "required-features")]
    required_features: Vec<String>,
}

struct CargoPackageContext<'a> {
    root: &'a Path,
    emitted_repository_root: &'a str,
    inventory: &'a IntentionalBoundaryRepositoryInventory,
    manifest_repository_path: &'a str,
    manifest_object_id: &'a str,
    package_name: &'a str,
    package_version: &'a str,
}

#[derive(serde::Serialize)]
struct NormalizedCargoTarget<'a> {
    manifest_repository_path: &'a str,
    manifest_object_id: &'a str,
    package_name: &'a str,
    package_version: &'a str,
    target_name: &'a str,
    provider_kinds: &'a [String],
    provider_crate_types: &'a [String],
    source_repository_path: &'a Option<String>,
    required_features: &'a [String],
    target_status: &'a TargetStatus,
}

pub fn census_intentional_boundary_cargo_project_models(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Result<IntentionalBoundaryProjectModelCensus, String> {
    census_cargo_project_models_with_executor(
        repository,
        revision,
        root,
        inventory,
        run_cargo_metadata,
    )
}

fn census_cargo_project_models_with_executor<F>(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    mut executor: F,
) -> Result<IntentionalBoundaryProjectModelCensus, String>
where
    F: FnMut(&Path, &str) -> Result<CargoMetadataExecutionOutput, String>,
{
    validate_intentional_boundary_repository_inventory(repository, revision, root, inventory)?;
    let cargo_manifests = inventory
        .tracked_entries
        .iter()
        .filter(|entry| entry.repository_path.rsplit('/').next() == Some("Cargo.toml"))
        .map(|entry| {
            if entry.kind != BoundaryGitEntryKind::RegularBlob {
                return Err(format!(
                    "Cargo manifest is not a regular Git blob: {}",
                    entry.repository_path
                ));
            }
            Ok(entry.repository_path.clone())
        })
        .collect::<Result<BTreeSet<_>, String>>()?;
    let mut covered_manifests = BTreeSet::new();
    let mut executions = Vec::new();
    let mut targets = Vec::new();
    for manifest_path in &cargo_manifests {
        if covered_manifests.contains(manifest_path) {
            continue;
        }
        let output = executor(root, manifest_path);
        let post_execution_inventory = validate_intentional_boundary_repository_inventory(
            repository, revision, root, inventory,
        );
        if let Err(error) = post_execution_inventory {
            return Err(format!(
                "Cargo metadata changed the immutable repository: {error}"
            ));
        }
        let output = output?;
        let contribution = parse_intentional_boundary_cargo_metadata(
            root,
            inventory,
            manifest_path,
            &output.toolchain_identity_sha256,
            output.stdout.as_bytes(),
        )?;
        let [execution] = contribution.executions.as_slice() else {
            return Err("Cargo project-model contribution changed cardinality".to_string());
        };
        for covered in &execution.covered_manifest_repository_paths {
            if !cargo_manifests.contains(covered) {
                return Err(format!(
                    "Cargo metadata covered an unrecognized manifest: {covered}"
                ));
            }
            covered_manifests.insert(covered.clone());
        }
        executions.extend(contribution.executions);
        targets.extend(contribution.targets);
    }
    if covered_manifests != cargo_manifests {
        return Err("Cargo metadata omitted a tracked Cargo manifest".to_string());
    }
    validate_intentional_boundary_repository_inventory(repository, revision, root, inventory)?;
    finish_census(inventory, executions, targets)
}

fn run_cargo_metadata(
    root: &Path,
    manifest_repository_path: &str,
) -> Result<CargoMetadataExecutionOutput, String> {
    let runtime = CargoMetadataRuntime::create(root)?;
    let cache = runtime.path().join("cache");
    fs::create_dir(&cache)
        .map_err(|error| format!("failed to create private Cargo metadata cache: {error}"))?;
    let logical_command = vec![
        "cargo".to_string(),
        "metadata".to_string(),
        "--format-version".to_string(),
        "1".to_string(),
        "--no-deps".to_string(),
        "--offline".to_string(),
        "--manifest-path".to_string(),
        manifest_repository_path.to_string(),
    ];
    let mut plan = prepare_historical_runtime(root, &cache, &logical_command)
        .map_err(project_model_runtime_error)?;
    plan.command.allow_network = false;
    #[cfg(target_os = "macos")]
    {
        plan.command.allow_local_network = false;
    }
    plan.command.timeout = CARGO_METADATA_TIMEOUT;
    plan.command.output_limit = CARGO_METADATA_OUTPUT_LIMIT;
    let toolchain_identity_sha256 = plan.runtime_identity;
    let output = crate::sandbox::run(&plan.command)
        .map_err(|error| format!("sandboxed Cargo metadata failed: {error}"))?;
    if output.timed_out {
        return Err("sandboxed Cargo metadata timed out".to_string());
    }
    if output.status_code != Some(0) {
        return Err(format!(
            "sandboxed Cargo metadata exited with status {}",
            output
                .status_code
                .map_or_else(|| "unknown".to_string(), |status| status.to_string())
        ));
    }
    Ok(CargoMetadataExecutionOutput {
        toolchain_identity_sha256,
        stdout: output.stdout,
    })
}

fn project_model_runtime_error(error: HistoricalRuntimePlanError) -> String {
    match error {
        HistoricalRuntimePlanError::Unavailable(message) => {
            format!("Cargo metadata runtime is unavailable: {message}")
        }
        HistoricalRuntimePlanError::Invalid(message) => {
            format!("Cargo metadata runtime is invalid: {message}")
        }
    }
}

pub fn parse_intentional_boundary_cargo_metadata(
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    invocation_manifest_repository_path: &str,
    toolchain_identity_sha256: &str,
    stdout: &[u8],
) -> Result<IntentionalBoundaryProjectModelCensus, String> {
    if !is_sha256(toolchain_identity_sha256) {
        return Err("Cargo metadata toolchain identity is not SHA-256".to_string());
    }
    let canonical_root =
        strip_windows_verbatim_prefix(fs::canonicalize(root).map_err(|error| {
            format!("failed to resolve Cargo metadata repository root: {error}")
        })?);
    let invocation_entry = regular_inventory_entry(
        inventory,
        invocation_manifest_repository_path,
        "Cargo metadata invocation manifest",
    )?;
    let metadata: CargoMetadata = serde_json::from_slice(stdout)
        .map_err(|error| format!("failed to parse Cargo metadata format 1 JSON: {error}"))?;
    if metadata.version != 1 {
        return Err(format!(
            "Cargo metadata output format changed to {}",
            metadata.version
        ));
    }
    let emitted_repository_root = emitted_repository_root(
        &metadata.workspace_root,
        invocation_manifest_repository_path,
    )?;
    let workspace_member_count = metadata.workspace_members.len();
    let workspace_members = metadata
        .workspace_members
        .into_iter()
        .collect::<BTreeSet<_>>();
    if workspace_members.len() != workspace_member_count {
        return Err("Cargo metadata repeated a workspace member identity".to_string());
    }
    let package_ids = metadata
        .packages
        .iter()
        .map(|package| package.id.as_str())
        .collect::<BTreeSet<_>>();
    if package_ids.len() != metadata.packages.len() {
        return Err("Cargo metadata repeated a package identity".to_string());
    }
    if !workspace_members
        .iter()
        .all(|id| package_ids.contains(id.as_str()))
    {
        return Err("Cargo metadata omitted a workspace member package".to_string());
    }

    let mut targets = Vec::new();
    let mut covered_manifests = BTreeSet::new();
    for package in metadata
        .packages
        .into_iter()
        .filter(|package| workspace_members.contains(&package.id))
    {
        let manifest_repository_path = repository_path(
            &canonical_root,
            &emitted_repository_root,
            &package.manifest_path,
        )
        .map_err(|_| "Cargo workspace manifest is outside the repository".to_string())?;
        let manifest_entry = regular_inventory_entry(
            inventory,
            &manifest_repository_path,
            "Cargo workspace manifest",
        )?;
        covered_manifests.insert(manifest_repository_path.clone());
        let context = CargoPackageContext {
            root: &canonical_root,
            emitted_repository_root: &emitted_repository_root,
            inventory,
            manifest_repository_path: &manifest_repository_path,
            manifest_object_id: &manifest_entry.object_id,
            package_name: &package.name,
            package_version: &package.version,
        };
        for target in package.targets {
            targets.push(normalize_target(&context, target)?);
        }
    }
    covered_manifests.insert(invocation_manifest_repository_path.to_string());
    targets.sort();

    let normalized_model_sha256 = hash_json(&(
        "sniffbench-intentional-boundary-cargo-normalized-model-v1",
        &covered_manifests,
        targets.iter().map(normalized_target).collect::<Vec<_>>(),
    ))?;
    let execution_id = format!(
        "ibpme-v1:{}",
        hash_json(&(
            "sniffbench-intentional-boundary-project-model-execution-v1",
            Provider::CargoMetadata,
            invocation_manifest_repository_path,
            &invocation_entry.object_id,
            toolchain_identity_sha256,
            CARGO_COMMAND_CONTRACT,
            &normalized_model_sha256,
        ))?
    );
    for target in &mut targets {
        target.execution_id = execution_id.clone();
        target.target_id = compute_target_id(target)?;
    }
    targets.sort();
    if targets.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("Cargo metadata produced duplicate normalized targets".to_string());
    }
    let execution = IntentionalBoundaryProjectModelExecution {
        execution_id,
        provider: Provider::CargoMetadata,
        invocation_anchor_repository_path: invocation_manifest_repository_path.to_string(),
        invocation_anchor_object_id: invocation_entry.object_id.clone(),
        toolchain_identity_sha256: toolchain_identity_sha256.to_string(),
        command_contract: CARGO_COMMAND_CONTRACT.to_string(),
        normalized_model_sha256,
        covered_manifest_repository_paths: covered_manifests.into_iter().collect(),
        target_count: targets.len(),
    };
    finish_census(inventory, vec![execution], targets)
}

pub fn validate_intentional_boundary_cargo_metadata(
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    invocation_manifest_repository_path: &str,
    toolchain_identity_sha256: &str,
    stdout: &[u8],
    census: &IntentionalBoundaryProjectModelCensus,
) -> Result<(), String> {
    let expected = parse_intentional_boundary_cargo_metadata(
        root,
        inventory,
        invocation_manifest_repository_path,
        toolchain_identity_sha256,
        stdout,
    )?;
    if census != &expected {
        return Err("intentional-boundary Cargo project model changed".to_string());
    }
    Ok(())
}

fn normalize_target(
    context: &CargoPackageContext<'_>,
    target: CargoTarget,
) -> Result<IntentionalBoundaryProjectModelTarget, String> {
    let mut provider_kinds = target.kind;
    provider_kinds.sort();
    provider_kinds.dedup();
    let mut provider_crate_types = target.crate_types;
    provider_crate_types.sort();
    provider_crate_types.dedup();
    let mut required_features = target.required_features;
    required_features.sort();
    required_features.dedup();
    let source_path = repository_path(
        context.root,
        context.emitted_repository_root,
        &target.src_path,
    );
    let source_repository_path = source_path.as_ref().ok().cloned();
    let target_status = classify_target(
        context.inventory,
        &provider_kinds,
        source_path.as_ref().ok().map(String::as_str),
    );
    Ok(IntentionalBoundaryProjectModelTarget {
        target_id: String::new(),
        execution_id: String::new(),
        provider: Provider::CargoMetadata,
        manifest_repository_path: context.manifest_repository_path.to_string(),
        manifest_object_id: context.manifest_object_id.to_string(),
        package_name: context.package_name.to_string(),
        package_version: context.package_version.to_string(),
        target_name: target.name,
        provider_kinds,
        provider_crate_types,
        source_repository_path,
        required_features,
        target_status,
    })
}

fn classify_target(
    inventory: &IntentionalBoundaryRepositoryInventory,
    kinds: &[String],
    source_repository_path: Option<&str>,
) -> TargetStatus {
    let Some(source_repository_path) = source_repository_path else {
        return unresolved(
            UnresolvedReason::SourceOutsideRepository,
            "Cargo target source is outside the immutable repository".to_string(),
        );
    };
    let source_entry = inventory
        .tracked_entries
        .iter()
        .find(|entry| entry.repository_path == source_repository_path);
    let Some(source_entry) = source_entry else {
        return unresolved(
            UnresolvedReason::SourceNotTracked,
            "Cargo target source is not present in the immutable Git inventory".to_string(),
        );
    };
    if source_entry.kind != BoundaryGitEntryKind::RegularBlob {
        return unresolved(
            UnresolvedReason::SourceNotRegularBlob,
            "Cargo target source is not a regular Git blob".to_string(),
        );
    }
    let recognized = kinds
        .iter()
        .map(|kind| match kind.as_str() {
            "lib" | "rlib" | "dylib" | "cdylib" | "staticlib" | "proc-macro" => "library",
            "bin" => "binary",
            "custom-build" => "build",
            "example" => "example",
            "test" => "test",
            "bench" => "bench",
            _ => "unknown",
        })
        .collect::<BTreeSet<_>>();
    let roles = recognized.iter().copied().collect::<Vec<_>>();
    let [role] = roles.as_slice() else {
        return unresolved(
            UnresolvedReason::ConflictingTargetKinds,
            "Cargo target has conflicting or missing target kinds".to_string(),
        );
    };
    match *role {
        "library" => boundary(
            IntentionalBoundaryManifestDeclarationKind::PublishedModule,
            source_repository_path,
        ),
        "binary" => boundary(
            IntentionalBoundaryManifestDeclarationKind::RuntimeEntrypoint,
            source_repository_path,
        ),
        "build" => boundary(
            IntentionalBoundaryManifestDeclarationKind::BuildScript,
            source_repository_path,
        ),
        "example" => TargetStatus::NonBoundary {
            reason: NonBoundaryReason::ExampleTarget,
        },
        "test" => TargetStatus::NonBoundary {
            reason: NonBoundaryReason::TestTarget,
        },
        "bench" => TargetStatus::NonBoundary {
            reason: NonBoundaryReason::BenchmarkTarget,
        },
        _ => unresolved(
            UnresolvedReason::UnknownTargetKind,
            "Cargo target kind is not covered by the frozen provider contract".to_string(),
        ),
    }
}

fn boundary(
    declaration_kind: IntentionalBoundaryManifestDeclarationKind,
    repository_path: &str,
) -> TargetStatus {
    TargetStatus::Boundary {
        declaration_kind,
        target: IntentionalBoundaryManifestTarget::RepositoryPath {
            repository_path: repository_path.to_string(),
        },
    }
}

fn unresolved(reason: UnresolvedReason, detail: String) -> TargetStatus {
    TargetStatus::Unresolved { reason, detail }
}

fn regular_inventory_entry<'a>(
    inventory: &'a IntentionalBoundaryRepositoryInventory,
    repository_path: &str,
    label: &str,
) -> Result<&'a IntentionalBoundaryTrackedEntry, String> {
    let entry = inventory
        .tracked_entries
        .iter()
        .find(|entry| entry.repository_path == repository_path)
        .ok_or_else(|| format!("{label} is absent from the immutable Git inventory"))?;
    if entry.kind != BoundaryGitEntryKind::RegularBlob {
        return Err(format!("{label} is not a regular Git blob"));
    }
    Ok(entry)
}

fn emitted_repository_root(
    workspace_root: &str,
    invocation_manifest_repository_path: &str,
) -> Result<String, String> {
    let workspace_root = workspace_root.replace('\\', "/");
    let invocation_directory = invocation_manifest_repository_path
        .rsplit_once('/')
        .map_or("", |(directory, _)| directory);
    if invocation_directory.is_empty() {
        return Ok(workspace_root.trim_end_matches('/').to_string());
    }
    let suffix = format!("/{invocation_directory}");
    let matches = if cfg!(windows) {
        workspace_root
            .to_ascii_lowercase()
            .ends_with(&suffix.to_ascii_lowercase())
    } else {
        workspace_root.ends_with(&suffix)
    };
    if !matches {
        return Err(
            "Cargo workspace root does not match the invocation manifest directory".to_string(),
        );
    }
    Ok(workspace_root[..workspace_root.len() - suffix.len()].to_string())
}

fn repository_path(root: &Path, emitted_root: &str, raw: &str) -> Result<String, String> {
    let raw = raw.replace('\\', "/");
    let emitted_root = emitted_root.trim_end_matches('/');
    let prefix = format!("{emitted_root}/");
    let matches = if cfg!(windows) {
        raw.get(..prefix.len())
            .is_some_and(|value| value.eq_ignore_ascii_case(&prefix))
    } else {
        raw.starts_with(&prefix)
    };
    if !matches {
        return Err("project-model path is outside repository".to_string());
    }
    let emitted_relative = &raw[prefix.len()..];
    let relative_path = Path::new(emitted_relative);
    if emitted_relative.is_empty()
        || relative_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("project-model path is not safely repository-relative".to_string());
    }
    let path = strip_windows_verbatim_prefix(
        fs::canonicalize(root.join(relative_path))
            .map_err(|_| "project-model path cannot be resolved".to_string())?,
    );
    let relative = path
        .strip_prefix(root)
        .map_err(|_| "project-model path is outside repository".to_string())?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("project-model path is not safely repository-relative".to_string());
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

fn normalized_target(target: &IntentionalBoundaryProjectModelTarget) -> NormalizedCargoTarget<'_> {
    NormalizedCargoTarget {
        manifest_repository_path: &target.manifest_repository_path,
        manifest_object_id: &target.manifest_object_id,
        package_name: &target.package_name,
        package_version: &target.package_version,
        target_name: &target.target_name,
        provider_kinds: &target.provider_kinds,
        provider_crate_types: &target.provider_crate_types,
        source_repository_path: &target.source_repository_path,
        required_features: &target.required_features,
        target_status: &target.target_status,
    }
}

fn compute_target_id(target: &IntentionalBoundaryProjectModelTarget) -> Result<String, String> {
    Ok(format!(
        "ibpmt-v1:{}",
        hash_json(&(
            "sniffbench-intentional-boundary-project-model-target-v1",
            &target.execution_id,
            normalized_target(target),
        ))?
    ))
}

fn finish_census(
    inventory: &IntentionalBoundaryRepositoryInventory,
    mut executions: Vec<IntentionalBoundaryProjectModelExecution>,
    mut targets: Vec<IntentionalBoundaryProjectModelTarget>,
) -> Result<IntentionalBoundaryProjectModelCensus, String> {
    executions.sort();
    targets.sort();
    if executions.windows(2).any(|pair| pair[0] >= pair[1])
        || targets.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err("project-model census contains duplicate records".to_string());
    }
    let execution_ids = executions
        .iter()
        .map(|execution| execution.execution_id.as_str())
        .collect::<BTreeSet<_>>();
    if targets
        .iter()
        .any(|target| !execution_ids.contains(target.execution_id.as_str()))
        || executions.iter().any(|execution| {
            execution.target_count
                != targets
                    .iter()
                    .filter(|target| target.execution_id == execution.execution_id)
                    .count()
        })
    {
        return Err("project-model target execution commitment changed".to_string());
    }
    let execution_count_by_provider =
        executions
            .iter()
            .fold(BTreeMap::new(), |mut counts, execution| {
                *counts.entry(execution.provider).or_insert(0) += 1;
                counts
            });
    let target_count_by_status = targets.iter().fold(BTreeMap::new(), |mut counts, target| {
        let status = match target.target_status {
            TargetStatus::Boundary { .. } => "boundary",
            TargetStatus::NonBoundary { .. } => "non_boundary",
            TargetStatus::Unresolved { .. } => "unresolved",
        };
        *counts.entry(status.to_string()).or_insert(0) += 1;
        counts
    });
    let mut census = IntentionalBoundaryProjectModelCensus {
        schema_version: INTENTIONAL_BOUNDARY_PROJECT_MODEL_CENSUS_SCHEMA_VERSION,
        project_model_contract: PROJECT_MODEL_CONTRACT.to_string(),
        repository: inventory.repository.clone(),
        revision: inventory.revision.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        executions,
        targets,
        execution_count_by_provider,
        target_count_by_status,
        project_model_census_sha256: String::new(),
    };
    census.project_model_census_sha256 = hash_json(&(
        census.schema_version,
        &census.project_model_contract,
        &census.repository,
        &census.revision,
        &census.inventory_sha256,
        &census.executions,
        &census.targets,
        &census.execution_count_by_provider,
        &census.target_count_by_status,
    ))?;
    Ok(census)
}

fn hash_json(value: &impl serde::Serialize) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("failed to commit project-model facts: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_project_model_cargo_tests.rs"]
mod tests;
