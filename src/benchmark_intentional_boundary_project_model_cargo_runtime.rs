use super::super::non_blind_history_runtime::{
    HistoricalRuntimePlanError, prepare_historical_runtime,
};
use super::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CARGO_SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const CARGO_METADATA_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const CARGO_METADATA_OUTPUT_LIMIT: usize = 16 * 1024 * 1024;
static CARGO_RUNTIME_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct CargoMetadataSnapshot {
    allocation_root: PathBuf,
    checkout_root: PathBuf,
}

impl CargoMetadataSnapshot {
    fn create(source_root: &Path, revision: &str) -> Result<Self, String> {
        let allocation_root =
            allocate_runtime_directory(&std::env::temp_dir(), "sniff-cargo-metadata-snapshot")?;
        let checkout_root = allocation_root.join("checkout");
        let hooks = allocation_root.join("empty-hooks");
        let global_config = allocation_root.join("gitconfig");
        fs::create_dir(&hooks)
            .map_err(|error| format!("failed to create empty Git hooks directory: {error}"))?;
        fs::write(&global_config, b"")
            .map_err(|error| format!("failed to create empty Git configuration: {error}"))?;

        let clone = run_snapshot_git(
            &allocation_root,
            &hooks,
            &global_config,
            [
                "clone".into(),
                "--shared".into(),
                "--no-checkout".into(),
                "--no-tags".into(),
                source_root.as_os_str().to_owned(),
                checkout_root.as_os_str().to_owned(),
            ],
        );
        if let Err(error) = clone {
            let _ = fs::remove_dir_all(&allocation_root);
            return Err(error);
        }
        let checkout = run_snapshot_git(
            &checkout_root,
            &hooks,
            &global_config,
            [
                "checkout".into(),
                "--force".into(),
                "--detach".into(),
                revision.into(),
            ],
        );
        if let Err(error) = checkout {
            let _ = fs::remove_dir_all(&allocation_root);
            return Err(error);
        }
        Ok(Self {
            allocation_root,
            checkout_root,
        })
    }

    fn path(&self) -> &Path {
        &self.checkout_root
    }
}

impl Drop for CargoMetadataSnapshot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.allocation_root);
    }
}

struct CargoMetadataCallRuntime(PathBuf);

impl CargoMetadataCallRuntime {
    fn create(root: &Path) -> Result<Self, String> {
        allocate_runtime_directory(root, ".sniff-cargo-metadata-call").map(Self)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for CargoMetadataCallRuntime {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(super) struct CargoMetadataExecutionOutput {
    pub(super) toolchain_identity_sha256: String,
    pub(super) stdout: String,
}

pub fn census_intentional_boundary_cargo_project_models(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
) -> Result<IntentionalBoundaryProjectModelCensus, String> {
    validate_intentional_boundary_repository_inventory(repository, revision, root, inventory)?;
    let snapshot = CargoMetadataSnapshot::create(root, revision)?;
    census_cargo_project_models_at_execution_root(
        repository,
        revision,
        root,
        snapshot.path(),
        inventory,
        run_cargo_metadata,
    )
}

#[cfg(test)]
pub(super) fn census_cargo_project_models_with_executor<F>(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    executor: F,
) -> Result<IntentionalBoundaryProjectModelCensus, String>
where
    F: FnMut(&Path, &str) -> Result<CargoMetadataExecutionOutput, String>,
{
    census_cargo_project_models_at_execution_root(
        repository, revision, root, root, inventory, executor,
    )
}

fn census_cargo_project_models_at_execution_root<F>(
    repository: &str,
    revision: &str,
    immutable_root: &Path,
    execution_root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    mut executor: F,
) -> Result<IntentionalBoundaryProjectModelCensus, String>
where
    F: FnMut(&Path, &str) -> Result<CargoMetadataExecutionOutput, String>,
{
    validate_intentional_boundary_repository_inventory(
        repository,
        revision,
        immutable_root,
        inventory,
    )?;
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
        let output = executor(execution_root, manifest_path);
        let post_execution_inventory = validate_intentional_boundary_repository_inventory(
            repository,
            revision,
            immutable_root,
            inventory,
        );
        if let Err(error) = post_execution_inventory {
            return Err(format!(
                "Cargo metadata changed the immutable repository: {error}"
            ));
        }
        let output = output?;
        let contribution = parse_intentional_boundary_cargo_metadata(
            execution_root,
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
    validate_intentional_boundary_repository_inventory(
        repository,
        revision,
        immutable_root,
        inventory,
    )?;
    finish_census(inventory, executions, targets)
}

fn run_cargo_metadata(
    root: &Path,
    manifest_repository_path: &str,
) -> Result<CargoMetadataExecutionOutput, String> {
    let runtime = CargoMetadataCallRuntime::create(root)?;
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

fn allocate_runtime_directory(parent: &Path, label: &str) -> Result<PathBuf, String> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock cannot allocate Cargo metadata runtime: {error}"))?
        .as_nanos();
    for _ in 0..128 {
        let sequence = CARGO_RUNTIME_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(
            "{label}-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
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

fn run_snapshot_git(
    workdir: &Path,
    hooks: &Path,
    global_config: &Path,
    args: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<(), String> {
    let mut command = Command::new("git");
    command
        .current_dir(workdir)
        .arg("-c")
        .arg(format!("core.hooksPath={}", hooks.display()))
        .args(args)
        .env("GIT_CONFIG_GLOBAL", global_config)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GCM_INTERACTIVE", "Never");
    let output = crate::bounded_process::run_with_output_limit(
        &mut command,
        CARGO_SNAPSHOT_TIMEOUT,
        CARGO_METADATA_OUTPUT_LIMIT,
    )
    .map_err(|error| format!("failed to materialize Cargo metadata snapshot: {error}"))?;
    if output.timed_out {
        return Err("Cargo metadata snapshot materialization timed out".to_string());
    }
    if output.stdout_truncated || output.stderr_truncated {
        return Err("Cargo metadata snapshot Git output exceeded its limit".to_string());
    }
    if !output.status.success() {
        return Err(format!(
            "Cargo metadata snapshot Git command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
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
