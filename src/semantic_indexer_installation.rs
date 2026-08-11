use crate::semantic_indexer_manifest::{
    INDEXER_INSTALL_CONTRACT, IndexerInstallSource, PinnedIndexer, SemanticIndexerKind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const INSTALL_RECORD: &str = "sniff-indexer-install.json";
const INSTALL_RECORD_VERSION: u32 = 1;
const MAX_RECORD_BYTES: u64 = 64 * 1024;
const MAX_TREE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_TREE_FILES: usize = 50_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IndexerInstallationRecord {
    version: u32,
    install_contract: String,
    kind: SemanticIndexerKind,
    indexer_version: String,
    source_identity: String,
    entrypoint: String,
    tree_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InstalledIndexer {
    pub(crate) root: PathBuf,
    pub(crate) entrypoint: PathBuf,
}

#[derive(Debug, Clone)]
pub(crate) struct SemanticIndexerStore {
    root: PathBuf,
}

impl SemanticIndexerStore {
    pub(crate) fn for_user() -> Result<Self, String> {
        Ok(Self::at(
            crate::semantic_cache::cache_base_directory()?.join("indexers"),
        ))
    }

    pub(crate) fn at(root: PathBuf) -> Self {
        Self { root }
    }

    pub(crate) fn installation_root(&self, spec: PinnedIndexer) -> PathBuf {
        self.root
            .join(INDEXER_INSTALL_CONTRACT)
            .join(spec.install_directory_name())
            .join(spec.version)
    }

    pub(crate) fn verify(&self, spec: PinnedIndexer) -> Result<InstalledIndexer, String> {
        self.verify_at(spec, &self.installation_root(spec))
    }

    pub(crate) fn verify_at(
        &self,
        spec: PinnedIndexer,
        root: &Path,
    ) -> Result<InstalledIndexer, String> {
        let record_path = root.join(INSTALL_RECORD);
        let record = read_record(&record_path)?;
        validate_record(spec, &record)?;
        let actual_hash = hash_tree(root)?;
        if actual_hash != record.tree_sha256 {
            return Err(format!(
                "{} installation checksum mismatch at {}; reinstall the pinned indexer",
                spec.display_name,
                root.display()
            ));
        }
        let entrypoint = root.join(&record.entrypoint);
        let metadata = fs::symlink_metadata(&entrypoint).map_err(|error| {
            format!(
                "{} entrypoint is missing at {}: {error}",
                spec.display_name,
                entrypoint.display()
            )
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(format!(
                "{} entrypoint is not a regular file: {}",
                spec.display_name,
                entrypoint.display()
            ));
        }
        Ok(InstalledIndexer {
            root: root.to_path_buf(),
            entrypoint,
        })
    }

    #[allow(dead_code)]
    pub(crate) fn seal(&self, spec: PinnedIndexer) -> Result<InstalledIndexer, String> {
        let root = self.installation_root(spec);
        self.seal_at(spec, &root)
    }

    pub(crate) fn seal_at(
        &self,
        spec: PinnedIndexer,
        root: &Path,
    ) -> Result<InstalledIndexer, String> {
        let entrypoint_relative = spec.entrypoint_relative_path();
        validate_relative_path(&entrypoint_relative)?;
        let entrypoint = root.join(&entrypoint_relative);
        let metadata = fs::symlink_metadata(&entrypoint).map_err(|error| {
            format!(
                "cannot seal {} because its entrypoint is missing at {}: {error}",
                spec.display_name,
                entrypoint.display()
            )
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(format!(
                "cannot seal non-regular {} entrypoint {}",
                spec.display_name,
                entrypoint.display()
            ));
        }
        let record = IndexerInstallationRecord {
            version: INSTALL_RECORD_VERSION,
            install_contract: INDEXER_INSTALL_CONTRACT.to_string(),
            kind: spec.kind,
            indexer_version: spec.version.to_string(),
            source_identity: source_identity(spec),
            entrypoint: normalize_path(&entrypoint_relative),
            tree_sha256: hash_tree(root)?,
        };
        write_record(&root.join(INSTALL_RECORD), &record)?;
        self.verify_at(spec, root)
    }

    pub(crate) fn promote_staged(
        &self,
        spec: PinnedIndexer,
        staged_root: &Path,
    ) -> Result<InstalledIndexer, String> {
        let final_root = self.installation_root(spec);
        let parent = final_root.parent().ok_or_else(|| {
            format!(
                "semantic indexer installation has no parent: {}",
                final_root.display()
            )
        })?;
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "failed to create semantic indexer parent {}: {error}",
                parent.display()
            )
        })?;
        if final_root.exists() {
            return Err(format!(
                "pinned {} installation already exists at {}; remove it explicitly before reinstalling",
                spec.display_name,
                final_root.display()
            ));
        }
        fs::rename(staged_root, &final_root).map_err(|error| {
            format!(
                "failed to promote {} installation into {}: {error}",
                spec.display_name,
                final_root.display()
            )
        })?;
        self.verify(spec)
    }
}

fn read_record(path: &Path) -> Result<IndexerInstallationRecord, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "pinned semantic indexer is not installed at {}: {error}",
            path.display()
        )
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "semantic indexer installation record is not a regular file: {}",
            path.display()
        ));
    }
    if metadata.len() > MAX_RECORD_BYTES {
        return Err(format!(
            "semantic indexer installation record exceeds {} bytes: {}",
            MAX_RECORD_BYTES,
            path.display()
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|file| file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|error| {
            format!(
                "failed to read semantic indexer installation record {}: {error}",
                path.display()
            )
        })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "semantic indexer installation record is corrupt at {}: {error}",
            path.display()
        )
    })
}

fn validate_record(spec: PinnedIndexer, record: &IndexerInstallationRecord) -> Result<(), String> {
    let expected_entrypoint = normalize_path(&spec.entrypoint_relative_path());
    if record.version != INSTALL_RECORD_VERSION
        || record.install_contract != INDEXER_INSTALL_CONTRACT
        || record.kind != spec.kind
        || record.indexer_version != spec.version
        || record.source_identity != source_identity(spec)
        || record.entrypoint != expected_entrypoint
    {
        return Err(format!(
            "{} installation identity mismatch; reinstall version {}",
            spec.display_name, spec.version
        ));
    }
    validate_relative_path(Path::new(&record.entrypoint))
}

fn source_identity(spec: PinnedIndexer) -> String {
    let source = match spec.source {
        IndexerInstallSource::Npm {
            package,
            integrity_sha512,
        } => format!("npm:{package}@{}:sha512-{integrity_sha512}", spec.version),
        IndexerInstallSource::GoModule { module, commit, .. } => {
            format!("go:{module}@v{}:{commit}", spec.version)
        }
        IndexerInstallSource::Download(download) => {
            format!("download:{}:sha256-{}", download.url, download.sha256)
        }
    };
    #[cfg(windows)]
    if spec.kind == SemanticIndexerKind::Kotlin {
        return format!(
            "{source}:sniff-windows-patch-{}",
            crate::semantic_indexer_manifest::WINDOWS_SCIP_JAVA_PATCH_ID
        );
    }
    #[cfg(windows)]
    if spec.kind == SemanticIndexerKind::Go {
        return format!(
            "{source}:sniff-windows-patch-{}",
            crate::semantic_indexer_manifest::WINDOWS_SCIP_GO_PATCH_ID
        );
    }
    source
}

fn hash_tree(root: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    if files.len() > MAX_TREE_FILES {
        return Err(format!(
            "semantic indexer installation exceeds {MAX_TREE_FILES} files at {}",
            root.display()
        ));
    }
    let mut total_bytes = 0_u64;
    let mut digest = Sha256::new();
    for (relative, absolute, size) in files {
        total_bytes = total_bytes.saturating_add(size);
        if total_bytes > MAX_TREE_BYTES {
            return Err(format!(
                "semantic indexer installation exceeds {MAX_TREE_BYTES} bytes at {}",
                root.display()
            ));
        }
        digest.update((relative.len() as u64).to_le_bytes());
        digest.update(relative.as_bytes());
        digest.update(size.to_le_bytes());
        let mut file = File::open(&absolute).map_err(|error| {
            format!(
                "failed to hash semantic indexer file {}: {error}",
                absolute.display()
            )
        })?;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer).map_err(|error| {
                format!(
                    "failed to hash semantic indexer file {}: {error}",
                    absolute.display()
                )
            })?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
    }
    let digest = digest.finalize();
    Ok(format!("{digest:x}"))
}

fn collect_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<(String, PathBuf, u64)>,
) -> Result<(), String> {
    let entries = fs::read_dir(directory).map_err(|error| {
        format!(
            "failed to inspect semantic indexer directory {}: {error}",
            directory.display()
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "failed to inspect semantic indexer directory {}: {error}",
                directory.display()
            )
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!(
                "failed to inspect semantic indexer path {}: {error}",
                path.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "semantic indexer installation contains a symlink: {}",
                path.display()
            ));
        }
        if metadata.is_dir() {
            collect_files(root, &path, files)?;
        } else if metadata.is_file() && path != root.join(INSTALL_RECORD) {
            let relative = path.strip_prefix(root).map_err(|_| {
                format!("semantic indexer path escaped its root: {}", path.display())
            })?;
            files.push((normalize_path(relative), path, metadata.len()));
        } else if !metadata.is_file() {
            return Err(format!(
                "semantic indexer installation contains a non-file entry: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn validate_relative_path(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() || path.is_absolute() || path.to_string_lossy().contains('\0') {
        return Err(format!(
            "semantic indexer entrypoint is not a safe relative path: {}",
            path.display()
        ));
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(format!(
            "semantic indexer entrypoint escapes its installation: {}",
            path.display()
        ));
    }
    Ok(())
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn write_record(path: &Path, record: &IndexerInstallationRecord) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| {
        format!(
            "semantic indexer installation record has no parent: {}",
            path.display()
        )
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "failed to create semantic indexer directory {}: {error}",
            parent.display()
        )
    })?;
    #[cfg(unix)]
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|error| {
        format!(
            "failed to secure semantic indexer directory {}: {error}",
            parent.display()
        )
    })?;
    let bytes = serde_json::to_vec(record)
        .map_err(|error| format!("failed to serialize indexer installation record: {error}"))?;
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    let temp = parent.join(format!(
        ".{INSTALL_RECORD}.{}.{}.tmp",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let result = (|| {
        let mut file = options.open(&temp).map_err(|error| {
            format!(
                "failed to create indexer installation record {}: {error}",
                temp.display()
            )
        })?;
        file.write_all(&bytes).map_err(|error| {
            format!(
                "failed to write indexer installation record {}: {error}",
                temp.display()
            )
        })?;
        file.sync_all().map_err(|error| {
            format!(
                "failed to sync indexer installation record {}: {error}",
                temp.display()
            )
        })?;
        drop(file);
        fs::rename(&temp, path).map_err(|error| {
            format!(
                "failed to commit indexer installation record {}: {error}",
                path.display()
            )
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
#[path = "tests/semantic_indexer_installation.rs"]
mod tests;
