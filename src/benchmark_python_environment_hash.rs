use super::files::{is_executable, normalize_path};
use super::{MAX_TREE_BYTES, MAX_TREE_FILES};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

pub(crate) fn python_environment_tree_sha256(root: &Path) -> Result<String, String> {
    let canonical_root = fs::canonicalize(root).map_err(|error| {
        format!(
            "failed to resolve materialized Python environment {}: {error}",
            root.display()
        )
    })?;
    let mut entries = Vec::new();
    collect_environment_entries(root, root, &canonical_root, &mut entries)?;
    entries.sort_by(|left, right| left.relative.cmp(&right.relative));
    if entries.len() > MAX_TREE_FILES {
        return Err(format!(
            "materialized Python environment exceeds {MAX_TREE_FILES} entries"
        ));
    }
    let mut total_bytes = 0_u64;
    let mut digest = Sha256::new();
    for entry in entries {
        total_bytes = total_bytes.saturating_add(entry.size);
        if total_bytes > MAX_TREE_BYTES {
            return Err(format!(
                "materialized Python environment exceeds {MAX_TREE_BYTES} bytes"
            ));
        }
        digest.update((entry.relative.len() as u64).to_le_bytes());
        digest.update(entry.relative.as_bytes());
        digest.update([entry.kind]);
        digest.update(entry.size.to_le_bytes());
        digest.update([u8::from(entry.executable)]);
        if let Some(target) = entry.symlink_target {
            digest.update((target.len() as u64).to_le_bytes());
            digest.update(target.as_bytes());
        } else {
            let absolute = entry.absolute.ok_or_else(|| {
                "materialized Python environment entry lost its file path".to_string()
            })?;
            let mut file = File::open(&absolute).map_err(|error| {
                format!(
                    "failed to hash materialized Python environment file {}: {error}",
                    absolute.display()
                )
            })?;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = file.read(&mut buffer).map_err(|error| {
                    format!(
                        "failed to hash materialized Python environment file {}: {error}",
                        absolute.display()
                    )
                })?;
                if read == 0 {
                    break;
                }
                digest.update(&buffer[..read]);
            }
        }
    }
    Ok(format!("{:x}", digest.finalize()))
}

struct EnvironmentTreeEntry {
    relative: String,
    kind: u8,
    size: u64,
    executable: bool,
    absolute: Option<PathBuf>,
    symlink_target: Option<String>,
}

fn collect_environment_entries(
    root: &Path,
    directory: &Path,
    canonical_root: &Path,
    entries: &mut Vec<EnvironmentTreeEntry>,
) -> Result<(), String> {
    for entry in fs::read_dir(directory).map_err(|error| {
        format!(
            "failed to inspect materialized Python environment {}: {error}",
            directory.display()
        )
    })? {
        let entry = entry.map_err(|error| {
            format!("failed to inspect materialized Python environment entry: {error}")
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!(
                "failed to inspect materialized Python environment path {}: {error}",
                path.display()
            )
        })?;
        let relative = normalize_path(path.strip_prefix(root).map_err(|_| {
            format!(
                "materialized Python environment path escaped its root: {}",
                path.display()
            )
        })?);
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(&path).map_err(|error| {
                format!(
                    "failed to read materialized Python environment link {}: {error}",
                    path.display()
                )
            })?;
            if target.is_absolute()
                || fs::canonicalize(&path)
                    .map(|resolved| !resolved.starts_with(canonical_root))
                    .unwrap_or(true)
            {
                return Err(format!(
                    "materialized Python environment link escapes its root: {}",
                    path.display()
                ));
            }
            entries.push(EnvironmentTreeEntry {
                relative,
                kind: 2,
                size: 0,
                executable: false,
                absolute: None,
                symlink_target: Some(normalize_path(&target)),
            });
        } else if metadata.is_dir() {
            collect_environment_entries(root, &path, canonical_root, entries)?;
        } else if metadata.is_file() {
            entries.push(EnvironmentTreeEntry {
                relative,
                kind: 1,
                size: metadata.len(),
                executable: is_executable(&metadata),
                absolute: Some(path),
                symlink_target: None,
            });
        } else {
            return Err(format!(
                "materialized Python environment contains a non-file entry: {}",
                path.display()
            ));
        }
    }
    Ok(())
}
