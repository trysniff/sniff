use super::{SNAPSHOT_TEMP_FILE, SnapshotCheckpoint};
use std::collections::BTreeSet;
#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

const MAX_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;

pub(super) fn ensure_plain_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(format!(
                "historical-v2 semantic progress path is not a plain directory: {}",
                path.display()
            ));
        }
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "failed to inspect historical-v2 semantic progress directory: {error}"
            ));
        }
    }
    fs::create_dir(path).map_err(|error| {
        format!(
            "failed to create historical-v2 semantic progress directory {}: {error}",
            path.display()
        )
    })
}

pub(super) fn remove_incomplete_file(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(format!(
            "historical-v2 semantic progress temporary entry is not a plain file: {}",
            path.display()
        )),
        Ok(_) => fs::remove_file(path).map_err(|error| {
            format!(
                "failed to remove interrupted historical-v2 semantic progress {}: {error}",
                path.display()
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to inspect historical-v2 semantic progress temporary entry: {error}"
        )),
    }
}

pub(super) fn read_checkpoint(path: &Path) -> Result<SnapshotCheckpoint, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!("failed to inspect historical-v2 semantic snapshot checkpoint: {error}")
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_SNAPSHOT_BYTES
    {
        return Err(
            "historical-v2 semantic snapshot checkpoint is not a bounded plain file".to_string(),
        );
    }
    serde_json::from_slice(&fs::read(path).map_err(|error| {
        format!("failed to read historical-v2 semantic snapshot checkpoint: {error}")
    })?)
    .map_err(|error| format!("invalid historical-v2 semantic snapshot checkpoint: {error}"))
}

pub(super) fn write_atomic_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let temp = path.with_file_name(SNAPSHOT_TEMP_FILE);
    remove_incomplete_file(&temp)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)
        .map_err(|error| {
            format!("failed to create historical-v2 semantic snapshot transaction: {error}")
        })?;
    file.write_all(bytes)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            format!("failed to persist historical-v2 semantic snapshot transaction: {error}")
        })?;
    require_absent(path, "historical-v2 semantic snapshot destination")?;
    fs::rename(&temp, path).map_err(|error| {
        format!("failed to publish historical-v2 semantic snapshot checkpoint: {error}")
    })?;
    sync_directory(
        path.parent().ok_or_else(|| {
            "historical-v2 semantic snapshot checkpoint has no parent".to_string()
        })?,
    )
}

fn require_absent(path: &Path, label: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(format!("{label} already exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("failed to inspect {label}: {error}")),
    }
}

pub(super) fn require_entries(root: &Path, expected: &[&str], label: &str) -> Result<(), String> {
    let actual = entry_names(root, label)?;
    let expected = expected.iter().map(|value| value.to_string()).collect();
    if actual != expected {
        return Err(format!("{label} contains unexpected or missing entries"));
    }
    Ok(())
}

pub(super) fn require_allowed_entries(
    root: &Path,
    allowed: &[&str],
    label: &str,
) -> Result<(), String> {
    let actual = entry_names(root, label)?;
    let allowed = allowed
        .iter()
        .map(|value| value.to_string())
        .collect::<BTreeSet<_>>();
    if let Some(unexpected) = actual.difference(&allowed).next() {
        return Err(format!("{label} contains unexpected entry {unexpected}"));
    }
    Ok(())
}

fn entry_names(root: &Path, label: &str) -> Result<BTreeSet<String>, String> {
    fs::read_dir(root)
        .map_err(|error| format!("failed to inspect {label}: {error}"))?
        .map(|entry| {
            let entry = entry.map_err(|error| format!("failed to inspect {label}: {error}"))?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| format!("failed to inspect {label} entry: {error}"))?;
            if metadata.file_type().is_symlink() {
                return Err(format!("{label} contains a symlink"));
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| format!("{label} contains a non-UTF-8 entry"))
        })
        .collect()
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            format!("failed to synchronize historical-v2 semantic progress directory: {error}")
        })
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}
