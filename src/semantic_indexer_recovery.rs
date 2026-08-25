use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const SCHEMA_VERSION: u32 = 2;
const CONTRACT: &str = "sniff-semantic-indexer-recovery-v2";
const LEGACY_SCHEMA_VERSION: u32 = 1;
const LEGACY_CONTRACT: &str = "sniff-semantic-indexer-recovery-v1";
const MARKER: &str = ".sniff-indexer-recovery.json";

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
struct RecoveryMarker {
    schema_version: u32,
    recovery_contract: String,
    paths: Vec<RecoveryPath>,
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
            marker_sha256: String::new(),
        };
        marker.marker_sha256 = marker_sha256(&marker)?;
        write_marker(&marker_path, &marker)?;
        sync_directory(&root)?;
        Ok(Self { root, marker })
    }

    pub(super) fn finish(self) -> Result<(), String> {
        cleanup_generated_paths(&self.root, &self.marker)?;
        remove_marker(&self.root)
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
        (".sniff-indexer-tmp", RecoveryPathKind::Directory),
        (".sniff-indexer-cache", RecoveryPathKind::Directory),
        (".sniff-jsconfig.json", RecoveryPathKind::File),
        ("scip-pyrightconfig.json", RecoveryPathKind::File),
        ("tsconfig.json", RecoveryPathKind::File),
    ]
}

fn legacy_recovery_paths() -> [(&'static str, RecoveryPathKind); 5] {
    [
        ("index.scip", RecoveryPathKind::File),
        (".sniff-indexer-tmp", RecoveryPathKind::Directory),
        (".sniff-indexer-cache", RecoveryPathKind::Directory),
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
    for entry in &marker.paths {
        if entry.existed_before {
            continue;
        }
        let path = root.join(&entry.relative_path);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
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
        })?;
    }
    Ok(())
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
    if marker.marker_sha256 != marker_sha256(marker)? || actual_paths != expected_paths {
        return Err("semantic recovery marker changed".to_string());
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
}
