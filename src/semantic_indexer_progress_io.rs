use serde::Deserialize;
use std::collections::BTreeSet;
#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const MAX_CHECKPOINT_BYTES: u64 = 512 * 1024 * 1024;

pub(super) fn ensure_plain_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(format!(
                "semantic progress path is not a plain directory: {}",
                path.display()
            ));
        }
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "failed to inspect semantic progress directory {}: {error}",
                path.display()
            ));
        }
    }
    fs::create_dir(path).map_err(|error| {
        format!(
            "failed to create semantic progress directory {}: {error}",
            path.display()
        )
    })
}

pub(super) fn remove_incomplete_file(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(format!(
            "semantic progress temporary entry is not a plain file: {}",
            path.display()
        )),
        Ok(_) => fs::remove_file(path).map_err(|error| {
            format!(
                "failed to remove incomplete semantic progress file {}: {error}",
                path.display()
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to inspect semantic progress temporary file {}: {error}",
            path.display()
        )),
    }
}

pub(super) fn write_atomic_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("semantic progress path has no parent: {}", path.display()))?;
    let temp = PathBuf::from(format!("{}.tmp", path.to_string_lossy()));
    remove_incomplete_file(&temp)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)
        .map_err(|error| {
            format!(
                "failed to create semantic progress temporary file {}: {error}",
                temp.display()
            )
        })?;
    file.write_all(bytes)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            format!(
                "failed to persist semantic progress temporary file {}: {error}",
                temp.display()
            )
        })?;
    require_absent(path, "semantic progress destination")?;
    fs::rename(&temp, path).map_err(|error| {
        format!(
            "failed to publish semantic progress file {}: {error}",
            path.display()
        )
    })?;
    sync_directory(parent)
}

fn require_absent(path: &Path, label: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(format!("{label} already exists: {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to inspect {label} {}: {error}",
            path.display()
        )),
    }
}

pub(super) fn read_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    label: &str,
) -> Result<T, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {label} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_CHECKPOINT_BYTES
    {
        return Err(format!(
            "{label} is not a bounded plain file: {}",
            path.display()
        ));
    }
    serde_json::from_slice(
        &fs::read(path).map_err(|error| format!("failed to read {label}: {error}"))?,
    )
    .map_err(|error| format!("invalid {label} {}: {error}", path.display()))
}

pub(super) fn require_exact_entries(
    root: &Path,
    expected: &BTreeSet<&str>,
    label: &str,
) -> Result<(), String> {
    let actual = directory_entry_names(root, label)?;
    let expected = expected.iter().map(|value| value.to_string()).collect();
    if actual != expected {
        return Err(format!("{label} contains unexpected or missing entries"));
    }
    Ok(())
}

pub(super) fn require_allowed_entries(
    root: &Path,
    allowed: &BTreeSet<String>,
    label: &str,
) -> Result<(), String> {
    let actual = directory_entry_names(root, label)?;
    if let Some(unexpected) = actual.difference(allowed).next() {
        return Err(format!("{label} contains unexpected entry {unexpected}"));
    }
    Ok(())
}

fn directory_entry_names(root: &Path, label: &str) -> Result<BTreeSet<String>, String> {
    fs::read_dir(root)
        .map_err(|error| format!("failed to inspect {label}: {error}"))?
        .map(|entry| {
            let entry = entry.map_err(|error| format!("failed to inspect {label}: {error}"))?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| format!("failed to inspect {label} entry: {error}"))?;
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "{label} contains a symlink: {}",
                    entry.path().display()
                ));
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
            format!(
                "failed to synchronize semantic progress directory {}: {error}",
                path.display()
            )
        })
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}
