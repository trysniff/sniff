use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const SCHEMA_VERSION: u32 = 3;
const CONTRACT: &str = "sniff-semantic-indexer-recovery-v3";
const PREVIOUS_SCHEMA_VERSION: u32 = 2;
const PREVIOUS_CONTRACT: &str = "sniff-semantic-indexer-recovery-v2";
const LEGACY_SCHEMA_VERSION: u32 = 1;
const LEGACY_CONTRACT: &str = "sniff-semantic-indexer-recovery-v1";
const MARKER: &str = ".sniff-indexer-recovery.json";
const EXTERNAL_RUNTIME_PREFIX: &str = "sniff-semantic-indexer-";
const EXTERNAL_OWNER_FILE: &str = ".sniff-indexer-owner";
static EXTERNAL_WORKSPACE_COUNTER: AtomicU64 = AtomicU64::new(0);
pub(super) const INDEXER_CACHE_DIR: &str = ".sniff-indexer-cache";
pub(super) const INDEXER_TEMP_DIR: &str = ".sniff-indexer-tmp";
pub(super) const INDEXER_REPOSITORY_WORKSPACE: &str = "repository-workspace";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RecoveryPathKind {
    File,
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryPath {
    relative_path: String,
    kind: RecoveryPathKind,
    existed_before: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalWorkspaceOwnership {
    temp_root: String,
    token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryMarker {
    schema_version: u32,
    recovery_contract: String,
    paths: Vec<RecoveryPath>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    external_workspace: Option<ExternalWorkspaceOwnership>,
    marker_sha256: String,
}

pub(super) struct SemanticIndexerRecoveryGuard {
    root: PathBuf,
    marker: RecoveryMarker,
}

impl SemanticIndexerRecoveryGuard {
    pub(super) fn begin(root: &Path) -> Result<Self, String> {
        let root = fs::canonicalize(root)
            .map_err(|error| format!("failed to resolve semantic recovery root: {error}"))?;
        let marker_path = root.join(MARKER);
        if marker_path.exists() {
            return Err(format!(
                "semantic index recovery is required before indexing {}",
                root.display()
            ));
        }
        reject_preexisting_private_runtime_paths(&root)?;
        let external_workspace = reserve_external_workspace(&root)?;
        let mut marker = RecoveryMarker {
            schema_version: SCHEMA_VERSION,
            recovery_contract: CONTRACT.to_string(),
            paths: recovery_paths()
                .into_iter()
                .map(|(relative_path, kind)| RecoveryPath {
                    existed_before: root.join(relative_path).exists(),
                    relative_path: relative_path.to_string(),
                    kind,
                })
                .collect(),
            external_workspace: Some(external_workspace),
            marker_sha256: String::new(),
        };
        marker.marker_sha256 = marker_sha256(&marker)?;
        if let Err(error) = write_marker(&marker_path, &marker) {
            let cleanup = cleanup_external_workspace(&root, &marker);
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(format!(
                    "{error}; additionally, external semantic workspace cleanup failed: {cleanup_error}"
                )),
            };
        }
        sync_directory(&root)?;
        Ok(Self { root, marker })
    }

    pub(super) fn prepare_indexer_run(&self) -> Result<PathBuf, String> {
        self.require_current_marker()?;
        cleanup_runtime_paths(&self.root, &self.marker)?;
        cleanup_external_workspace(&self.root, &self.marker)?;
        create_owned_external_workspace(&self.root, &self.marker)?;
        self.execution_root()
    }

    pub(super) fn finish_indexer_run(&self) -> Result<(), String> {
        self.require_current_marker()?;
        cleanup_external_workspace(&self.root, &self.marker)?;
        cleanup_runtime_paths(&self.root, &self.marker)?;
        sync_directory(&self.root)
    }

    pub(super) fn finish(self) -> Result<(), String> {
        self.require_current_marker()?;
        cleanup_generated_paths(&self.root, &self.marker)?;
        remove_marker(&self.root)
    }

    fn require_current_marker(&self) -> Result<(), String> {
        let marker_path = self.root.join(MARKER);
        let persisted: RecoveryMarker = serde_json::from_slice(
            &fs::read(&marker_path)
                .map_err(|error| format!("failed to read semantic recovery marker: {error}"))?,
        )
        .map_err(|error| format!("invalid semantic recovery marker: {error}"))?;
        validate_marker(&persisted)?;
        if persisted != self.marker {
            return Err("semantic recovery marker changed while indexing".to_string());
        }
        Ok(())
    }

    pub(super) fn require_owned_execution_root(&self, path: &Path) -> Result<(), String> {
        self.require_current_marker()?;
        require_external_workspace_ownership(&self.root, &self.marker)?;
        let expected = self.execution_root()?;
        let observed = normalize_windows_path(fs::canonicalize(path).map_err(|error| {
            format!(
                "failed to resolve isolated semantic workspace {}: {error}",
                path.display()
            )
        })?);
        let expected = normalize_windows_path(fs::canonicalize(&expected).map_err(|error| {
            format!(
                "failed to resolve owned semantic workspace {}: {error}",
                expected.display()
            )
        })?);
        if observed != expected {
            return Err(format!(
                "refusing to use an unowned semantic workspace: {}",
                path.display()
            ));
        }
        Ok(())
    }

    fn execution_root(&self) -> Result<PathBuf, String> {
        Ok(external_runtime_path(&self.root, &self.marker)?.join(INDEXER_REPOSITORY_WORKSPACE))
    }
}

pub(crate) fn recover_interrupted_semantic_indexing(root: &Path) -> Result<bool, String> {
    let root = fs::canonicalize(root)
        .map_err(|error| format!("failed to resolve semantic recovery root: {error}"))?;
    let marker_path = root.join(MARKER);
    if !marker_path.exists() {
        return Ok(false);
    }
    let marker: RecoveryMarker = serde_json::from_slice(
        &fs::read(&marker_path)
            .map_err(|error| format!("failed to read semantic recovery marker: {error}"))?,
    )
    .map_err(|error| format!("invalid semantic recovery marker: {error}"))?;
    validate_marker(&marker)?;
    cleanup_generated_paths(&root, &marker)?;
    remove_marker(&root)?;
    Ok(true)
}

fn recovery_paths() -> [(&'static str, RecoveryPathKind); 6] {
    [
        ("index.scip", RecoveryPathKind::File),
        (INDEXER_TEMP_DIR, RecoveryPathKind::Directory),
        (INDEXER_CACHE_DIR, RecoveryPathKind::Directory),
        (".sniff-jsconfig.json", RecoveryPathKind::File),
        ("scip-pyrightconfig.json", RecoveryPathKind::File),
        ("tsconfig.json", RecoveryPathKind::File),
    ]
}

fn legacy_recovery_paths() -> [(&'static str, RecoveryPathKind); 5] {
    [
        ("index.scip", RecoveryPathKind::File),
        (INDEXER_TEMP_DIR, RecoveryPathKind::Directory),
        (INDEXER_CACHE_DIR, RecoveryPathKind::Directory),
        (".sniff-jsconfig.json", RecoveryPathKind::File),
        ("scip-pyrightconfig.json", RecoveryPathKind::File),
    ]
}

fn cleanup_generated_paths(root: &Path, marker: &RecoveryMarker) -> Result<(), String> {
    validate_marker(marker)?;
    if marker.schema_version == LEGACY_SCHEMA_VERSION && root.join("tsconfig.json").exists() {
        return Err(format!(
            "legacy semantic recovery marker cannot prove whether {} was generated; refusing automatic cleanup",
            root.join("tsconfig.json").display()
        ));
    }
    cleanup_external_workspace(root, marker)?;
    for entry in &marker.paths {
        if entry.existed_before {
            continue;
        }
        cleanup_generated_path(root, entry)?;
    }
    Ok(())
}

fn reserve_external_workspace(root: &Path) -> Result<ExternalWorkspaceOwnership, String> {
    let temp_root =
        normalize_windows_path(fs::canonicalize(std::env::temp_dir()).map_err(|error| {
            format!("failed to resolve operating-system temp directory: {error}")
        })?);
    reject_repository_nested_temp_root(root, &temp_root)?;
    for _ in 0..64 {
        let token = external_workspace_token(root);
        let ownership = ExternalWorkspaceOwnership {
            temp_root: temp_root.to_string_lossy().into_owned(),
            token,
        };
        let runtime = external_runtime_path_from_ownership(&ownership)?;
        match fs::create_dir(&runtime) {
            Ok(()) => {
                if let Err(error) = write_external_owner(&runtime, &ownership.token) {
                    let _ = fs::remove_dir(&runtime);
                    return Err(error);
                }
                sync_directory(&temp_root)?;
                return Ok(ownership);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "failed to reserve external semantic workspace {}: {error}",
                    runtime.display()
                ));
            }
        }
    }
    Err("failed to reserve a unique external semantic workspace after 64 attempts".to_string())
}

fn external_workspace_token(root: &Path) -> String {
    let mut digest = Sha256::new();
    digest.update(root.to_string_lossy().as_bytes());
    digest.update(std::process::id().to_le_bytes());
    digest.update(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes(),
    );
    digest.update(
        EXTERNAL_WORKSPACE_COUNTER
            .fetch_add(1, Ordering::Relaxed)
            .to_le_bytes(),
    );
    format!("{:x}", digest.finalize())
}

fn create_owned_external_workspace(root: &Path, marker: &RecoveryMarker) -> Result<(), String> {
    let ownership = marker.external_workspace.as_ref().ok_or_else(|| {
        "semantic recovery marker omitted external workspace ownership".to_string()
    })?;
    let runtime = external_runtime_path(root, marker)?;
    fs::create_dir(&runtime).map_err(|error| {
        format!(
            "failed to create external semantic workspace {}: {error}",
            runtime.display()
        )
    })?;
    if let Err(error) = write_external_owner(&runtime, &ownership.token) {
        let _ = fs::remove_dir(&runtime);
        return Err(error);
    }
    sync_directory(
        runtime
            .parent()
            .ok_or_else(|| "external semantic workspace has no parent directory".to_string())?,
    )
}

fn write_external_owner(runtime: &Path, token: &str) -> Result<(), String> {
    let owner = runtime.join(EXTERNAL_OWNER_FILE);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&owner)
        .map_err(|error| {
            format!(
                "failed to create external semantic workspace ownership marker {}: {error}",
                owner.display()
            )
        })?;
    file.write_all(token.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            format!(
                "failed to persist external semantic workspace ownership marker {}: {error}",
                owner.display()
            )
        })?;
    sync_directory(runtime)
}

fn cleanup_external_workspace(root: &Path, marker: &RecoveryMarker) -> Result<(), String> {
    if marker.schema_version != SCHEMA_VERSION {
        return Ok(());
    }
    let runtime = external_runtime_path(root, marker)?;
    match fs::symlink_metadata(&runtime) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "failed to inspect external semantic workspace {}: {error}",
                runtime.display()
            ));
        }
    }
    require_external_workspace_ownership(root, marker)?;
    make_generated_directory_removable(&runtime)?;
    fs::remove_dir_all(&runtime).map_err(|error| {
        format!(
            "failed to remove external semantic workspace {}: {error}",
            runtime.display()
        )
    })?;
    sync_directory(
        runtime
            .parent()
            .ok_or_else(|| "external semantic workspace has no parent directory".to_string())?,
    )
}

fn require_external_workspace_ownership(
    root: &Path,
    marker: &RecoveryMarker,
) -> Result<(), String> {
    let ownership = marker.external_workspace.as_ref().ok_or_else(|| {
        "semantic recovery marker omitted external workspace ownership".to_string()
    })?;
    let runtime = external_runtime_path(root, marker)?;
    let metadata = fs::symlink_metadata(&runtime).map_err(|error| {
        format!(
            "failed to inspect external semantic workspace {}: {error}",
            runtime.display()
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "refusing to use external semantic workspace with changed type: {}",
            runtime.display()
        ));
    }
    let owner = runtime.join(EXTERNAL_OWNER_FILE);
    let owner_metadata = fs::symlink_metadata(&owner).map_err(|error| {
        format!(
            "failed to inspect external semantic workspace ownership marker {}: {error}",
            owner.display()
        )
    })?;
    if !owner_metadata.is_file() || owner_metadata.file_type().is_symlink() {
        return Err(format!(
            "external semantic workspace ownership marker is not a plain file: {}",
            owner.display()
        ));
    }
    let observed = fs::read_to_string(&owner).map_err(|error| {
        format!(
            "failed to read external semantic workspace ownership marker {}: {error}",
            owner.display()
        )
    })?;
    if observed != ownership.token {
        return Err("external semantic workspace ownership marker changed".to_string());
    }
    Ok(())
}

fn external_runtime_path(root: &Path, marker: &RecoveryMarker) -> Result<PathBuf, String> {
    validate_marker(marker)?;
    let ownership = marker.external_workspace.as_ref().ok_or_else(|| {
        "semantic recovery marker omitted external workspace ownership".to_string()
    })?;
    let declared_temp = PathBuf::from(&ownership.temp_root);
    let current_temp =
        normalize_windows_path(fs::canonicalize(std::env::temp_dir()).map_err(|error| {
            format!("failed to resolve operating-system temp directory: {error}")
        })?);
    let declared_temp =
        normalize_windows_path(fs::canonicalize(&declared_temp).map_err(|error| {
            format!(
                "failed to resolve recorded semantic temp directory {}: {error}",
                declared_temp.display()
            )
        })?);
    if declared_temp != current_temp {
        return Err("semantic recovery temp directory changed".to_string());
    }
    reject_repository_nested_temp_root(root, &declared_temp)?;
    external_runtime_path_from_ownership(ownership)
}

fn external_runtime_path_from_ownership(
    ownership: &ExternalWorkspaceOwnership,
) -> Result<PathBuf, String> {
    if ownership.token.len() != 64
        || !ownership
            .token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("semantic recovery marker has an invalid external workspace token".to_string());
    }
    let temp_root = PathBuf::from(&ownership.temp_root);
    if !temp_root.is_absolute() {
        return Err("semantic recovery marker has a relative external temp root".to_string());
    }
    Ok(temp_root.join(format!("{EXTERNAL_RUNTIME_PREFIX}{}", ownership.token)))
}

fn reject_repository_nested_temp_root(root: &Path, temp_root: &Path) -> Result<(), String> {
    let root = normalize_windows_path(fs::canonicalize(root).map_err(|error| {
        format!(
            "failed to resolve semantic recovery root {}: {error}",
            root.display()
        )
    })?);
    if temp_root == root || temp_root.starts_with(&root) {
        return Err(format!(
            "operating-system temp directory {} is inside repository {}; compiler isolation requires an external temp root",
            temp_root.display(),
            root.display()
        ));
    }
    Ok(())
}

fn normalize_windows_path(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{}", rest));
    }
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        return PathBuf::from(rest);
    }
    path
}

fn reject_preexisting_private_runtime_paths(root: &Path) -> Result<(), String> {
    for relative_path in [INDEXER_TEMP_DIR, INDEXER_CACHE_DIR] {
        let path = root.join(relative_path);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(format!(
                    "refusing to reuse an unexpected semantic indexer runtime path {}; remove it before indexing",
                    path.display()
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "failed to inspect semantic indexer runtime path {}: {error}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

fn cleanup_runtime_paths(root: &Path, marker: &RecoveryMarker) -> Result<(), String> {
    validate_marker(marker)?;
    for relative_path in [INDEXER_TEMP_DIR, INDEXER_CACHE_DIR] {
        let entry = marker
            .paths
            .iter()
            .find(|entry| entry.relative_path == relative_path)
            .ok_or_else(|| format!("semantic recovery marker omitted {relative_path}"))?;
        if entry.existed_before {
            return Err(format!(
                "semantic recovery marker does not own private runtime path {}",
                root.join(relative_path).display()
            ));
        }
        cleanup_generated_path(root, entry)?;
    }
    Ok(())
}

fn cleanup_generated_path(root: &Path, entry: &RecoveryPath) -> Result<(), String> {
    let path = root.join(&entry.relative_path);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "failed to inspect semantic recovery path {}: {error}",
                path.display()
            ));
        }
    };
    match entry.kind {
        RecoveryPathKind::File if metadata.file_type().is_file() => fs::remove_file(&path),
        RecoveryPathKind::Directory if metadata.file_type().is_dir() => {
            make_generated_directory_removable(&path)?;
            fs::remove_dir_all(&path)
        }
        _ => {
            return Err(format!(
                "refusing to remove semantic recovery path with changed type: {}",
                path.display()
            ));
        }
    }
    .map_err(|error| {
        format!(
            "failed to remove semantic recovery path {}: {error}",
            path.display()
        )
    })
}

fn make_generated_directory_removable(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "failed to inspect generated semantic directory {}: {error}",
            path.display()
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "refusing to change permissions on non-directory semantic path: {}",
            path.display()
        ));
    }
    make_directory_owner_accessible(path, &metadata)?;
    for child in fs::read_dir(path).map_err(|error| {
        format!(
            "failed to enumerate generated semantic directory {}: {error}",
            path.display()
        )
    })? {
        let child = child.map_err(|error| {
            format!(
                "failed to enumerate generated semantic directory {}: {error}",
                path.display()
            )
        })?;
        let child_path = child.path();
        let child_metadata = fs::symlink_metadata(&child_path).map_err(|error| {
            format!(
                "failed to inspect generated semantic path {}: {error}",
                child_path.display()
            )
        })?;
        if child_metadata.file_type().is_symlink() {
            continue;
        }
        if child_metadata.is_dir() {
            make_generated_directory_removable(&child_path)?;
        } else {
            make_file_owner_removable(&child_path, &child_metadata)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn make_directory_owner_accessible(path: &Path, metadata: &fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode();
    let permissions = fs::Permissions::from_mode(mode | 0o700);
    fs::set_permissions(path, permissions).map_err(|error| {
        format!(
            "failed to restore owner access to generated semantic directory {}: {error}",
            path.display()
        )
    })
}

#[cfg(unix)]
fn make_file_owner_removable(_path: &Path, _metadata: &fs::Metadata) -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
fn make_directory_owner_accessible(path: &Path, metadata: &fs::Metadata) -> Result<(), String> {
    clear_windows_readonly(path, metadata)
}

#[cfg(windows)]
fn make_file_owner_removable(path: &Path, metadata: &fs::Metadata) -> Result<(), String> {
    clear_windows_readonly(path, metadata)
}

#[cfg(windows)]
#[allow(clippy::permissions_set_readonly_false)]
fn clear_windows_readonly(path: &Path, metadata: &fs::Metadata) -> Result<(), String> {
    let mut permissions = metadata.permissions();
    if !permissions.readonly() {
        return Ok(());
    }
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions).map_err(|error| {
        format!(
            "failed to clear read-only generated semantic path {}: {error}",
            path.display()
        )
    })
}

fn write_marker(path: &Path, marker: &RecoveryMarker) -> Result<(), String> {
    let bytes = serde_json::to_vec(marker)
        .map_err(|error| format!("failed to serialize semantic recovery marker: {error}"))?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("failed to create semantic recovery marker: {error}"))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("failed to persist semantic recovery marker: {error}"))
}

fn remove_marker(root: &Path) -> Result<(), String> {
    fs::remove_file(root.join(MARKER))
        .map_err(|error| format!("failed to remove semantic recovery marker: {error}"))?;
    sync_directory(root)
}

fn validate_marker(marker: &RecoveryMarker) -> Result<(), String> {
    let expected_paths = match (marker.schema_version, marker.recovery_contract.as_str()) {
        (SCHEMA_VERSION, CONTRACT) => recovery_paths().into_iter().collect::<Vec<_>>(),
        (PREVIOUS_SCHEMA_VERSION, PREVIOUS_CONTRACT) => {
            recovery_paths().into_iter().collect::<Vec<_>>()
        }
        (LEGACY_SCHEMA_VERSION, LEGACY_CONTRACT) => {
            legacy_recovery_paths().into_iter().collect::<Vec<_>>()
        }
        _ => return Err("semantic recovery marker changed".to_string()),
    };
    let actual_paths = marker
        .paths
        .iter()
        .map(|path| (path.relative_path.as_str(), path.kind))
        .collect::<Vec<_>>();
    let ownership_matches_schema = match marker.schema_version {
        SCHEMA_VERSION => marker.external_workspace.is_some(),
        PREVIOUS_SCHEMA_VERSION | LEGACY_SCHEMA_VERSION => marker.external_workspace.is_none(),
        _ => false,
    };
    if marker.marker_sha256 != marker_sha256(marker)?
        || actual_paths != expected_paths
        || !ownership_matches_schema
    {
        return Err("semantic recovery marker changed".to_string());
    }
    if let Some(ownership) = &marker.external_workspace {
        external_runtime_path_from_ownership(ownership)?;
    }
    Ok(())
}

fn marker_sha256(marker: &RecoveryMarker) -> Result<String, String> {
    let mut committed = marker.clone();
    committed.marker_sha256.clear();
    serde_json::to_vec(&committed)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit semantic recovery marker: {error}"))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("failed to sync semantic recovery directory: {error}"))
}

#[cfg(windows)]
fn sync_directory(path: &Path) -> Result<(), String> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("failed to sync semantic recovery directory: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finish_removes_only_paths_created_after_the_marker() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("index.scip"), b"original").unwrap();
        let guard = SemanticIndexerRecoveryGuard::begin(root.path()).unwrap();
        fs::create_dir(root.path().join(".sniff-indexer-tmp")).unwrap();
        fs::write(root.path().join(".sniff-jsconfig.json"), b"generated").unwrap();
        fs::write(root.path().join("tsconfig.json"), b"generated").unwrap();

        guard.finish().unwrap();

        assert_eq!(
            fs::read(root.path().join("index.scip")).unwrap(),
            b"original"
        );
        assert!(!root.path().join(".sniff-indexer-tmp").exists());
        assert!(!root.path().join(".sniff-jsconfig.json").exists());
        assert!(!root.path().join("tsconfig.json").exists());
        assert!(!root.path().join(MARKER).exists());
    }

    #[test]
    fn finish_removes_read_only_go_module_cache_entries() {
        let root = tempfile::tempdir().unwrap();
        let guard = SemanticIndexerRecoveryGuard::begin(root.path()).unwrap();
        let module = root
            .path()
            .join(".sniff-indexer-tmp/go/pkg/mod/example.com/module@v1.0.0");
        fs::create_dir_all(&module).unwrap();
        let source = module.join("module.go");
        fs::write(&source, b"package module\n").unwrap();
        let mut file_permissions = fs::metadata(&source).unwrap().permissions();
        file_permissions.set_readonly(true);
        fs::set_permissions(&source, file_permissions).unwrap();
        let mut directory_permissions = fs::metadata(&module).unwrap().permissions();
        directory_permissions.set_readonly(true);
        fs::set_permissions(&module, directory_permissions).unwrap();

        guard.finish().unwrap();

        assert!(!root.path().join(".sniff-indexer-tmp").exists());
        assert!(!root.path().join(MARKER).exists());
    }

    #[test]
    fn begin_rejects_a_preexisting_private_runtime_path_without_claiming_it() {
        let root = tempfile::tempdir().unwrap();
        let private = root.path().join(INDEXER_TEMP_DIR);
        fs::create_dir(&private).unwrap();
        fs::write(private.join("owner.txt"), b"not sniff").unwrap();

        let error = SemanticIndexerRecoveryGuard::begin(root.path())
            .err()
            .unwrap();

        assert!(error.contains("unexpected semantic indexer runtime path"));
        assert_eq!(fs::read(private.join("owner.txt")).unwrap(), b"not sniff");
        assert!(!root.path().join(MARKER).exists());
    }

    #[test]
    fn preparing_a_run_replaces_only_marker_owned_interrupted_runtime_state() {
        let root = tempfile::tempdir().unwrap();
        let guard = SemanticIndexerRecoveryGuard::begin(root.path()).unwrap();
        let private = root.path().join(INDEXER_TEMP_DIR);
        fs::create_dir(&private).unwrap();
        fs::write(private.join("stale"), b"generated after marker").unwrap();

        let execution_root = guard.prepare_indexer_run().unwrap();

        assert!(!private.exists());
        assert!(!execution_root.exists());
        assert!(!execution_root.starts_with(root.path()));
        let runtime = execution_root.parent().unwrap().to_path_buf();
        assert!(runtime.join(EXTERNAL_OWNER_FILE).is_file());
        guard.finish_indexer_run().unwrap();
        assert!(!runtime.exists());
        guard.finish().unwrap();
    }

    #[test]
    fn explicit_run_cleanup_allows_another_run_after_read_only_go_modules() {
        let root = tempfile::tempdir().unwrap();
        let guard = SemanticIndexerRecoveryGuard::begin(root.path()).unwrap();
        let execution_root = guard.prepare_indexer_run().unwrap();
        let module = execution_root
            .join(INDEXER_TEMP_DIR)
            .join("go/pkg/mod/example.com/module@v1.0.0");
        fs::create_dir_all(&module).unwrap();
        let source = module.join("module.go");
        fs::write(&source, b"package module\n").unwrap();
        let mut file_permissions = fs::metadata(&source).unwrap().permissions();
        file_permissions.set_readonly(true);
        fs::set_permissions(&source, file_permissions).unwrap();
        let mut directory_permissions = fs::metadata(&module).unwrap().permissions();
        directory_permissions.set_readonly(true);
        fs::set_permissions(&module, directory_permissions).unwrap();

        guard.finish_indexer_run().unwrap();
        let next_execution_root = guard.prepare_indexer_run().unwrap();

        assert_eq!(next_execution_root, execution_root);
        assert!(!next_execution_root.exists());
        guard.finish_indexer_run().unwrap();
        guard.finish().unwrap();
    }

    #[test]
    fn interrupted_dependency_preparation_remains_marker_recoverable() {
        let root = tempfile::tempdir().unwrap();
        let guard = SemanticIndexerRecoveryGuard::begin(root.path()).unwrap();
        let execution_root = guard.prepare_indexer_run().unwrap();
        let module = execution_root
            .join(INDEXER_TEMP_DIR)
            .join("go/pkg/mod/example.com/module@v1.0.0/module.go");
        fs::create_dir_all(module.parent().unwrap()).unwrap();
        fs::write(&module, b"package module\n").unwrap();
        drop(guard);

        assert!(recover_interrupted_semantic_indexing(root.path()).unwrap());
        assert!(!execution_root.parent().unwrap().exists());
        assert!(!root.path().join(MARKER).exists());
    }

    #[cfg(unix)]
    #[test]
    fn finish_unlinks_generated_symlinks_without_touching_their_targets() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let external_file = external.path().join("proof.txt");
        fs::write(&external_file, b"preserved").unwrap();
        let guard = SemanticIndexerRecoveryGuard::begin(root.path()).unwrap();
        let generated = root.path().join(".sniff-indexer-tmp");
        fs::create_dir(&generated).unwrap();
        symlink(external.path(), generated.join("external-link")).unwrap();

        guard.finish().unwrap();

        assert_eq!(fs::read(&external_file).unwrap(), b"preserved");
        assert!(!generated.exists());
    }

    #[test]
    fn finish_preserves_a_preexisting_typescript_config() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("tsconfig.json"), b"original").unwrap();
        let guard = SemanticIndexerRecoveryGuard::begin(root.path()).unwrap();

        guard.finish().unwrap();

        assert_eq!(
            fs::read(root.path().join("tsconfig.json")).unwrap(),
            b"original"
        );
        assert!(!root.path().join(MARKER).exists());
    }

    #[test]
    fn interrupted_run_is_recovered_from_its_committed_marker() {
        let root = tempfile::tempdir().unwrap();
        let guard = SemanticIndexerRecoveryGuard::begin(root.path()).unwrap();
        fs::create_dir(root.path().join(".sniff-indexer-cache")).unwrap();
        fs::write(root.path().join("index.scip"), b"generated").unwrap();
        fs::write(root.path().join("tsconfig.json"), b"generated").unwrap();
        drop(guard);

        assert!(recover_interrupted_semantic_indexing(root.path()).unwrap());
        assert!(!root.path().join(".sniff-indexer-cache").exists());
        assert!(!root.path().join("index.scip").exists());
        assert!(!root.path().join("tsconfig.json").exists());
        assert!(!recover_interrupted_semantic_indexing(root.path()).unwrap());
    }

    #[test]
    fn legacy_marker_without_an_ambiguous_typescript_config_is_recoverable() {
        let root = tempfile::tempdir().unwrap();
        let mut marker = RecoveryMarker {
            schema_version: LEGACY_SCHEMA_VERSION,
            recovery_contract: LEGACY_CONTRACT.to_string(),
            paths: legacy_recovery_paths()
                .into_iter()
                .map(|(relative_path, kind)| RecoveryPath {
                    relative_path: relative_path.to_string(),
                    kind,
                    existed_before: false,
                })
                .collect(),
            external_workspace: None,
            marker_sha256: String::new(),
        };
        marker.marker_sha256 = marker_sha256(&marker).unwrap();
        write_marker(&root.path().join(MARKER), &marker).unwrap();
        fs::write(root.path().join("index.scip"), b"generated").unwrap();

        assert!(recover_interrupted_semantic_indexing(root.path()).unwrap());
        assert!(!root.path().join("index.scip").exists());
        assert!(!root.path().join(MARKER).exists());
    }

    #[test]
    fn previous_v2_marker_remains_recoverable() {
        let root = tempfile::tempdir().unwrap();
        let mut marker = RecoveryMarker {
            schema_version: PREVIOUS_SCHEMA_VERSION,
            recovery_contract: PREVIOUS_CONTRACT.to_string(),
            paths: recovery_paths()
                .into_iter()
                .map(|(relative_path, kind)| RecoveryPath {
                    relative_path: relative_path.to_string(),
                    kind,
                    existed_before: false,
                })
                .collect(),
            external_workspace: None,
            marker_sha256: String::new(),
        };
        marker.marker_sha256 = marker_sha256(&marker).unwrap();
        write_marker(&root.path().join(MARKER), &marker).unwrap();
        fs::write(root.path().join("index.scip"), b"generated").unwrap();

        assert!(recover_interrupted_semantic_indexing(root.path()).unwrap());
        assert!(!root.path().join("index.scip").exists());
        assert!(!root.path().join(MARKER).exists());
    }

    #[test]
    fn legacy_marker_with_an_ambiguous_typescript_config_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let mut marker = RecoveryMarker {
            schema_version: LEGACY_SCHEMA_VERSION,
            recovery_contract: LEGACY_CONTRACT.to_string(),
            paths: legacy_recovery_paths()
                .into_iter()
                .map(|(relative_path, kind)| RecoveryPath {
                    relative_path: relative_path.to_string(),
                    kind,
                    existed_before: false,
                })
                .collect(),
            external_workspace: None,
            marker_sha256: String::new(),
        };
        marker.marker_sha256 = marker_sha256(&marker).unwrap();
        write_marker(&root.path().join(MARKER), &marker).unwrap();
        fs::write(root.path().join("tsconfig.json"), b"unknown provenance").unwrap();

        let error = recover_interrupted_semantic_indexing(root.path()).unwrap_err();

        assert!(error.contains("cannot prove"));
        assert!(root.path().join("tsconfig.json").exists());
        assert!(root.path().join(MARKER).exists());
    }

    #[test]
    fn tampered_marker_fails_closed_without_deleting_paths() {
        let root = tempfile::tempdir().unwrap();
        let guard = SemanticIndexerRecoveryGuard::begin(root.path()).unwrap();
        fs::write(root.path().join("index.scip"), b"generated").unwrap();
        drop(guard);
        let marker_path = root.path().join(MARKER);
        let mut marker: serde_json::Value =
            serde_json::from_slice(&fs::read(&marker_path).unwrap()).unwrap();
        marker["schema_version"] = serde_json::json!(99);
        fs::write(&marker_path, serde_json::to_vec(&marker).unwrap()).unwrap();

        assert!(recover_interrupted_semantic_indexing(root.path()).is_err());
        assert!(root.path().join("index.scip").exists());
    }

    #[test]
    fn tampered_external_owner_fails_closed_without_deleting_source_copy() {
        let root = tempfile::tempdir().unwrap();
        let guard = SemanticIndexerRecoveryGuard::begin(root.path()).unwrap();
        let execution_root = guard.prepare_indexer_run().unwrap();
        fs::create_dir(&execution_root).unwrap();
        let proof = execution_root.join("source.rs");
        fs::write(&proof, b"fn preserved() {}").unwrap();
        let owner = execution_root.parent().unwrap().join(EXTERNAL_OWNER_FILE);
        let token = fs::read_to_string(&owner).unwrap();
        fs::write(&owner, b"changed").unwrap();
        drop(guard);

        let error = recover_interrupted_semantic_indexing(root.path()).unwrap_err();

        assert!(error.contains("ownership marker changed"));
        assert!(proof.is_file());
        assert!(root.path().join(MARKER).is_file());

        fs::write(owner, token).unwrap();
        assert!(recover_interrupted_semantic_indexing(root.path()).unwrap());
    }
}
