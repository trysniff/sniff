use super::super::intentional_boundary_runtime_snapshot::IntentionalBoundaryRuntimeSnapshot;
use super::super::non_blind_history_runtime::prepare_historical_runtime;
use super::super::non_blind_history_runtime_support::{resolve_on_path, sandbox_repository_path};
use super::{
    BoundaryGitEntryKind, HistoricalV2NodeConsumerMode, HistoricalV2NodePackageDocument,
    HistoricalV2NodePackageExposure, IntentionalBoundaryRepositoryInventory,
};
use crate::semantic_indexer_installation::{InstalledIndexer, SemanticIndexerStore};
use crate::semantic_indexer_manifest::{PinnedIndexer, SemanticIndexerKind, pinned_indexer};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[path = "benchmark_history_v2_node_consumer_profile_runtime_integrity.rs"]
mod integrity;

use integrity::*;

const SIDECAR: &[u8] = include_bytes!("../assets/node-consumer-profile.mjs");
const TIMEOUT: Duration = Duration::from_secs(5 * 60);
const OUTPUT_LIMIT: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub(super) struct ConsumerProfileExecutionOutput {
    pub(super) node_runtime_sha256: String,
    pub(super) toolchain_identity_sha256: String,
    pub(super) stdout: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SidecarInput<'a> {
    schema_version: u32,
    specifier: &'a str,
    mode: &'a str,
    containing_file: &'a str,
    compiler_options: &'a Value,
    path_mappings: Vec<PathMapping>,
    exposures: Vec<SidecarExposure<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PathMapping {
    runtime_prefix: String,
    repository_prefix: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SidecarExposure<'a> {
    exposure_id: &'a str,
    target_repository_path: &'a str,
    package_relative_target: String,
}

struct ConsumerRuntime(PathBuf);

impl ConsumerRuntime {
    fn create(root: &Path, label: &str) -> Result<Self, String> {
        let path = root.join(label);
        fs::create_dir(&path).map_err(|error| {
            format!("failed to create Node consumer-profile runtime {label}: {error}")
        })?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

pub(super) struct NodeConsumerProfileRuntime {
    snapshot: IntentionalBoundaryRuntimeSnapshot,
    session: ConsumerRuntime,
    store: SemanticIndexerStore,
    spec: PinnedIndexer,
    installed: InstalledIndexer,
    typescript: PathBuf,
    node: PathBuf,
    node_runtime_sha256: String,
}

impl NodeConsumerProfileRuntime {
    pub(super) fn create(root: &Path, revision: &str) -> Result<Self, String> {
        let snapshot = IntentionalBoundaryRuntimeSnapshot::create(
            root,
            revision,
            "sniff-node-consumer-profile-snapshot",
        )?;
        let session =
            ConsumerRuntime::create(snapshot.path(), ".sniff-node-consumer-profile-session")?;
        let spec = pinned_indexer(SemanticIndexerKind::TypeScriptJavaScript)?;
        let store = SemanticIndexerStore::for_user()?;
        let installed = store.verify(spec)?;
        let typescript = installed
            .root
            .join("node_modules")
            .join("typescript")
            .join("lib")
            .join("typescript.js");
        if !typescript.is_file() {
            return Err("pinned TypeScript compiler API entrypoint is missing".to_string());
        }
        let host_node = resolve_on_path("node").map_err(|error| match error {
            super::super::non_blind_history_runtime::HistoricalRuntimePlanError::Unavailable(
                detail,
            )
            | super::super::non_blind_history_runtime::HistoricalRuntimePlanError::Invalid(
                detail,
            ) => detail,
        })?;
        #[cfg(windows)]
        let node = stage_windows_node(session.path(), &host_node)?;
        #[cfg(not(windows))]
        let node = host_node;
        let node_runtime_sha256 = file_sha256(&node, "Node consumer-profile runtime")?;
        Ok(Self {
            snapshot,
            session,
            store,
            spec,
            installed,
            typescript,
            node,
            node_runtime_sha256,
        })
    }

    pub(super) fn verify_unchanged(&self) -> Result<(), String> {
        verify_file_unchanged(
            &self.node,
            "Node consumer-profile runtime",
            &self.node_runtime_sha256,
        )?;
        self.store
            .verify(self.spec)
            .map(|_| ())
            .map_err(|error| format!("TypeScript installation changed during resolution: {error}"))
    }
}

impl Drop for ConsumerRuntime {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run_node_consumer_profile(
    session: &NodeConsumerProfileRuntime,
    inventory: &IntentionalBoundaryRepositoryInventory,
    document: &HistoricalV2NodePackageDocument,
    specifier: &str,
    mode: HistoricalV2NodeConsumerMode,
    compiler_options: &Value,
    exposures: &[&HistoricalV2NodePackageExposure],
) -> Result<ConsumerProfileExecutionOutput, String> {
    let snapshot = &session.snapshot;
    let runtime =
        ConsumerRuntime::create(session.session.path(), ".sniff-node-consumer-profile-call")?;
    let cache = runtime.path().join("cache");
    fs::create_dir(&cache)
        .map_err(|error| format!("failed to create Node consumer-profile cache: {error}"))?;

    let package_directory = package_directory(&document.manifest_repository_path)?;
    let package_name = document
        .package_name
        .as_deref()
        .ok_or_else(|| "Node package consumer has no package name".to_string())?;
    let package_name_path = package_name_path(package_name)?;
    let runtime_consumer = runtime.path().join("runtime-consumer");
    let runtime_installed = runtime_consumer
        .join("node_modules")
        .join(&package_name_path);
    copy_package(
        snapshot.path(),
        inventory,
        &package_directory,
        &runtime_installed,
    )?;
    materialize_declared_runtime_targets(&runtime_installed, &package_directory, exposures)?;
    let mut path_mappings = vec![PathMapping {
        runtime_prefix: repository_path(snapshot.path(), &runtime_installed)?,
        repository_prefix: package_directory.clone(),
    }];
    let mut compiler_mirror = None;
    let containing_file = if document.has_exports {
        if package_directory.is_empty() {
            format!(".sniff-consumer-profile-{}/consumer.ts", std::process::id())
        } else {
            format!(
                "{package_directory}/.sniff-consumer-profile-{}/consumer.ts",
                std::process::id()
            )
        }
    } else {
        let compiler_consumer = runtime.path().join("compiler-consumer");
        let compiler_installed = compiler_consumer
            .join("node_modules")
            .join(&package_name_path);
        copy_package(
            snapshot.path(),
            inventory,
            &package_directory,
            &compiler_installed,
        )?;
        compiler_mirror = Some(compiler_installed.clone());
        path_mappings.push(PathMapping {
            runtime_prefix: repository_path(snapshot.path(), &compiler_installed)?,
            repository_prefix: package_directory.clone(),
        });
        repository_path(snapshot.path(), &compiler_consumer.join("consumer.ts"))?
    };
    path_mappings.sort_by(|left, right| right.runtime_prefix.cmp(&left.runtime_prefix));
    let sidecar_directory = runtime_consumer;

    let sidecar = sidecar_directory.join("node-consumer-profile.mjs");
    fs::write(&sidecar, SIDECAR)
        .map_err(|error| format!("failed to stage Node consumer-profile sidecar: {error}"))?;
    let input_path = runtime.path().join("input.json");
    let input = serde_json::to_vec(&SidecarInput {
        schema_version: 1,
        specifier,
        mode: match mode {
            HistoricalV2NodeConsumerMode::Import => "import",
            HistoricalV2NodeConsumerMode::Require => "require",
        },
        containing_file: &containing_file,
        compiler_options,
        path_mappings,
        exposures: exposures
            .iter()
            .map(|exposure| {
                package_relative_target(&package_directory, &exposure.target_repository_path).map(
                    |package_relative_target| SidecarExposure {
                        exposure_id: &exposure.exposure_id,
                        target_repository_path: &exposure.target_repository_path,
                        package_relative_target,
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?,
    })
    .map_err(|error| format!("failed to encode Node consumer-profile input: {error}"))?;
    fs::write(&input_path, input)
        .map_err(|error| format!("failed to stage Node consumer-profile input: {error}"))?;

    let runtime_mirror_sha256 = directory_tree_sha256(&runtime_installed)?;
    let compiler_mirror_sha256 = compiler_mirror
        .as_deref()
        .map(directory_tree_sha256)
        .transpose()?;

    #[cfg(windows)]
    let logical_program = session.node.to_string_lossy().into_owned();
    #[cfg(not(windows))]
    let logical_program = "node".to_string();
    let mut logical_command = vec![logical_program];
    if cfg!(windows) {
        logical_command.extend([
            "--preserve-symlinks".to_string(),
            "--preserve-symlinks-main".to_string(),
        ]);
    }
    for condition in custom_conditions(compiler_options)? {
        logical_command.push(format!("--conditions={condition}"));
    }
    logical_command.extend([
        sandbox_repository_path(snapshot.path(), &sidecar),
        session.typescript.to_string_lossy().into_owned(),
        sandbox_repository_path(snapshot.path(), &input_path),
    ]);
    let mut plan =
        prepare_historical_runtime(snapshot.path(), &cache, &logical_command).map_err(|error| {
            match error {
            super::super::non_blind_history_runtime::HistoricalRuntimePlanError::Unavailable(
                detail,
            )
            | super::super::non_blind_history_runtime::HistoricalRuntimePlanError::Invalid(
                detail,
            ) => detail,
        }
        })?;
    plan.command.allow_network = false;
    #[cfg(target_os = "macos")]
    {
        plan.command.allow_local_network = false;
    }
    plan.command.timeout = TIMEOUT;
    plan.command.output_limit = OUTPUT_LIMIT;
    plan.command
        .read_only_paths
        .push(session.installed.root.clone());
    plan.command.read_only_paths.sort();
    plan.command.read_only_paths.dedup();

    let sidecar_sha256 = file_sha256(&sidecar, "Node consumer-profile sidecar")?;
    let input_sha256 = file_sha256(&input_path, "Node consumer-profile input")?;
    let toolchain_identity_sha256 = format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&(
                "sniff-node-consumer-profile-toolchain-v2",
                &plan.runtime_identity,
                &session.installed.tree_sha256,
                &session.node_runtime_sha256,
                &sidecar_sha256,
                &input_sha256,
                &runtime_mirror_sha256,
                &compiler_mirror_sha256,
            ))
            .map_err(|error| format!(
                "failed to commit Node consumer-profile toolchain: {error}"
            ))?
        )
    );
    let run_result = crate::sandbox::run(&plan.command);
    verify_file_unchanged(
        &session.node,
        "Node consumer-profile runtime",
        &session.node_runtime_sha256,
    )?;
    verify_file_unchanged(&sidecar, "Node consumer-profile sidecar", &sidecar_sha256)?;
    verify_file_unchanged(&input_path, "Node consumer-profile input", &input_sha256)?;
    verify_directory_unchanged(
        &runtime_installed,
        "Node runtime consumer mirror",
        &runtime_mirror_sha256,
    )?;
    if let (Some(path), Some(expected)) = (
        compiler_mirror.as_deref(),
        compiler_mirror_sha256.as_deref(),
    ) {
        verify_directory_unchanged(path, "TypeScript compiler consumer mirror", expected)?;
    }
    let output =
        run_result.map_err(|error| format!("Node consumer-profile sandbox failed: {error:?}"))?;
    if output.timed_out {
        return Err("Node consumer-profile execution timed out".to_string());
    }
    if output.status_code != Some(0) {
        return Err(format!(
            "Node consumer-profile execution failed: {}",
            output.stderr
        ));
    }
    Ok(ConsumerProfileExecutionOutput {
        node_runtime_sha256: session.node_runtime_sha256.clone(),
        toolchain_identity_sha256,
        stdout: output.stdout,
    })
}

fn package_directory(manifest_repository_path: &str) -> Result<String, String> {
    let Some(prefix) = manifest_repository_path.strip_suffix("package.json") else {
        return Err("Node consumer profile received a non-package manifest".to_string());
    };
    Ok(prefix.trim_end_matches('/').to_string())
}

fn package_relative_target(package_directory: &str, target: &str) -> Result<String, String> {
    let relative = if package_directory.is_empty() {
        target
    } else {
        target
            .strip_prefix(&format!("{package_directory}/"))
            .ok_or_else(|| format!("Node consumer target escaped package directory: {target}"))?
    };
    Ok(format!("./{relative}"))
}

fn package_name_path(package_name: &str) -> Result<PathBuf, String> {
    let segments = package_name.split('/').collect::<Vec<_>>();
    if segments.is_empty()
        || segments.len() > 2
        || package_name.contains('\\')
        || package_name.contains(':')
        || package_name.chars().any(char::is_control)
        || segments.iter().any(|segment| {
            segment.is_empty()
                || *segment == "."
                || *segment == ".."
                || segment.eq_ignore_ascii_case("node_modules")
        })
        || (segments.len() == 1 && segments[0].starts_with('@'))
        || (segments.len() == 2 && (!segments[0].starts_with('@') || segments[0].len() == 1))
    {
        return Err("Node package name cannot form a synthetic consumer path".to_string());
    }
    Ok(segments.iter().collect())
}

fn copy_package(
    snapshot_root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    package_directory: &str,
    installed: &Path,
) -> Result<(), String> {
    let prefix = if package_directory.is_empty() {
        String::new()
    } else {
        format!("{package_directory}/")
    };
    let mut copied = 0_usize;
    for entry in &inventory.tracked_entries {
        let relative = entry
            .repository_path
            .strip_prefix(&prefix)
            .filter(|relative| !relative.is_empty());
        let Some(relative) = relative else {
            continue;
        };
        if !matches!(
            entry.kind,
            BoundaryGitEntryKind::RegularBlob | BoundaryGitEntryKind::ExecutableBlob
        ) {
            return Err(format!(
                "Node package synthetic install contains a non-regular entry: {}",
                entry.repository_path
            ));
        }
        let source = snapshot_root.join(&entry.repository_path);
        let target = installed.join(relative);
        let parent = target
            .parent()
            .ok_or_else(|| "Node package synthetic install target has no parent".to_string())?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create synthetic package directory: {error}"))?;
        fs::copy(&source, &target)
            .map_err(|error| format!("failed to copy synthetic package entry: {error}"))?;
        copied += 1;
    }
    if copied == 0 {
        return Err("Node package synthetic install copied no tracked files".to_string());
    }
    Ok(())
}

fn materialize_declared_runtime_targets(
    installed: &Path,
    package_directory: &str,
    exposures: &[&HistoricalV2NodePackageExposure],
) -> Result<(), String> {
    for exposure in exposures {
        let relative = if package_directory.is_empty() {
            exposure.target_repository_path.as_str()
        } else {
            exposure
                .target_repository_path
                .strip_prefix(&format!("{package_directory}/"))
                .ok_or_else(|| "Node runtime target escaped its synthetic package".to_string())?
        };
        let target = installed.join(relative);
        if target.exists() {
            let metadata = fs::symlink_metadata(&target).map_err(|error| {
                format!("failed to inspect declared Node runtime target: {error}")
            })?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(format!(
                    "declared Node runtime target is not a regular file: {}",
                    exposure.target_repository_path
                ));
            }
            continue;
        }
        let parent = target
            .parent()
            .ok_or_else(|| "Node runtime target has no parent".to_string())?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create Node runtime target parent: {error}"))?;
        fs::write(&target, []).map_err(|error| {
            format!("failed to materialize declared Node runtime target: {error}")
        })?;
    }
    Ok(())
}

fn custom_conditions(options: &Value) -> Result<Vec<String>, String> {
    let Some(value) = options.get("customConditions") else {
        return Ok(Vec::new());
    };
    let array = value
        .as_array()
        .ok_or_else(|| "TypeScript customConditions is not an array".to_string())?;
    let mut conditions = array
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty() && !value.contains('='))
                .map(str::to_string)
                .ok_or_else(|| "TypeScript custom condition is invalid".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    conditions.sort();
    conditions.dedup();
    Ok(conditions)
}

fn repository_path(root: &Path, path: &Path) -> Result<String, String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| "Node consumer runtime path escaped its snapshot".to_string())?;
    let value = relative.to_string_lossy().replace('\\', "/");
    if value.is_empty() || value.starts_with("../") {
        return Err("Node consumer runtime path is invalid".to_string());
    }
    Ok(value)
}

#[cfg(windows)]
fn stage_windows_node(directory: &Path, source: &Path) -> Result<PathBuf, String> {
    let staged = directory.join("node.exe");
    fs::copy(source, &staged)
        .map_err(|error| format!("failed to stage Node consumer-profile runtime: {error}"))?;
    fs::canonicalize(&staged)
        .map_err(|error| format!("failed to resolve Node consumer-profile runtime: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_package_path_accepts_only_canonical_npm_names() {
        assert_eq!(
            package_name_path("plain-package").unwrap(),
            PathBuf::from("plain-package")
        );
        assert_eq!(
            package_name_path("@scope/package").unwrap(),
            PathBuf::from("@scope").join("package")
        );
        for invalid in [
            "@scope",
            "scope/package",
            "../escape",
            "package\\escape",
            "C:package",
            "node_modules",
            "@scope/node_modules",
        ] {
            assert!(package_name_path(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn mirror_commitment_detects_file_mutation() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("nested")).unwrap();
        let file = root.path().join("nested/package.js");
        fs::write(&file, "export const value = 1;\n").unwrap();
        let before = directory_tree_sha256(root.path()).unwrap();
        fs::write(file, "export const value = 2;\n").unwrap();
        let after = directory_tree_sha256(root.path()).unwrap();
        assert_ne!(before, after);
    }
}
