use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const SCHEMA_VERSION: u32 = 1;
const CONTRACT: &str = "sniff-semantic-indexer-recovery-v1";
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

fn recovery_paths() -> [(&'static str, RecoveryPathKind); 5] {
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
    let expected_paths = recovery_paths().into_iter().collect::<Vec<_>>();
    let actual_paths = marker
        .paths
        .iter()
        .map(|path| (path.relative_path.as_str(), path.kind))
        .collect::<Vec<_>>();
    if marker.schema_version != SCHEMA_VERSION
        || marker.recovery_contract != CONTRACT
        || marker.marker_sha256 != marker_sha256(marker)?
        || actual_paths != expected_paths
    {
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

        guard.finish().unwrap();

        assert_eq!(
            fs::read(root.path().join("index.scip")).unwrap(),
            b"original"
        );
        assert!(!root.path().join(".sniff-indexer-tmp").exists());
        assert!(!root.path().join(".sniff-jsconfig.json").exists());
        assert!(!root.path().join(MARKER).exists());
    }

    #[test]
    fn interrupted_run_is_recovered_from_its_committed_marker() {
        let root = tempfile::tempdir().unwrap();
        let guard = SemanticIndexerRecoveryGuard::begin(root.path()).unwrap();
        fs::create_dir(root.path().join(".sniff-indexer-cache")).unwrap();
        fs::write(root.path().join("index.scip"), b"generated").unwrap();
        drop(guard);

        assert!(recover_interrupted_semantic_indexing(root.path()).unwrap());
        assert!(!root.path().join(".sniff-indexer-cache").exists());
        assert!(!root.path().join("index.scip").exists());
        assert!(!recover_interrupted_semantic_indexing(root.path()).unwrap());
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
