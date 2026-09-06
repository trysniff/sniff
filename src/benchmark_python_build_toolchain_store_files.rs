use super::{MAX_RECORD_BYTES, MAX_TREE_BYTES, MAX_TREE_FILES, PythonBuildToolchainRecord};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub(super) fn hash_regular_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|error| format!("failed to hash Python wheel {}: {error}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("failed to hash Python wheel {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

pub(super) fn hash_tree(root: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    if files.len() > MAX_TREE_FILES {
        return Err(format!(
            "Python build environment exceeds {MAX_TREE_FILES} files at {}",
            root.display()
        ));
    }
    let mut total_bytes = 0_u64;
    let mut digest = Sha256::new();
    for (relative, absolute, size, executable) in files {
        total_bytes = total_bytes.saturating_add(size);
        if total_bytes > MAX_TREE_BYTES {
            return Err(format!(
                "Python build environment exceeds {MAX_TREE_BYTES} bytes at {}",
                root.display()
            ));
        }
        digest.update((relative.len() as u64).to_le_bytes());
        digest.update(relative.as_bytes());
        digest.update(size.to_le_bytes());
        digest.update([u8::from(executable)]);
        let mut file = File::open(&absolute).map_err(|error| {
            format!(
                "failed to hash Python build-toolchain file {}: {error}",
                absolute.display()
            )
        })?;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer).map_err(|error| {
                format!(
                    "failed to hash Python build-toolchain file {}: {error}",
                    absolute.display()
                )
            })?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
    }
    Ok(format!("{:x}", digest.finalize()))
}

pub(super) fn collect_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<(String, PathBuf, u64, bool)>,
) -> Result<(), String> {
    for entry in fs::read_dir(directory).map_err(|error| {
        format!(
            "failed to inspect Python build-toolchain directory {}: {error}",
            directory.display()
        )
    })? {
        let entry = entry.map_err(|error| {
            format!(
                "failed to inspect Python build-toolchain directory {}: {error}",
                directory.display()
            )
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!(
                "failed to inspect Python build-toolchain path {}: {error}",
                path.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "Python build toolchain contains a symbolic link: {}",
                path.display()
            ));
        }
        if metadata.is_dir() {
            collect_files(root, &path, files)?;
        } else if metadata.is_file() {
            let relative = path.strip_prefix(root).map_err(|_| {
                format!(
                    "Python build-toolchain path escaped its root: {}",
                    path.display()
                )
            })?;
            files.push((
                normalize_path(relative),
                path,
                metadata.len(),
                is_executable(&metadata),
            ));
        } else {
            return Err(format!(
                "Python build toolchain contains a non-file entry: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

pub(super) fn copy_tree(source: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir(destination).map_err(|error| {
        format!(
            "failed to create Python build-toolchain staging directory {}: {error}",
            destination.display()
        )
    })?;
    for entry in fs::read_dir(source).map_err(|error| {
        format!(
            "failed to inspect prepared Python build toolchain {}: {error}",
            source.display()
        )
    })? {
        let entry = entry.map_err(|error| {
            format!(
                "failed to inspect prepared Python build toolchain {}: {error}",
                source.display()
            )
        })?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path).map_err(|error| {
            format!(
                "failed to inspect prepared Python build-toolchain path {}: {error}",
                source_path.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "prepared Python build toolchain contains a symbolic link: {}",
                source_path.display()
            ));
        }
        if metadata.is_dir() {
            copy_tree(&source_path, &destination_path)?;
        } else if metadata.is_file() {
            fs::copy(&source_path, &destination_path).map_err(|error| {
                format!(
                    "failed to copy Python build-toolchain file {}: {error}",
                    source_path.display()
                )
            })?;
            fs::set_permissions(&destination_path, metadata.permissions()).map_err(|error| {
                format!(
                    "failed to preserve Python build-toolchain permissions for {}: {error}",
                    destination_path.display()
                )
            })?;
        } else {
            return Err(format!(
                "prepared Python build toolchain contains a non-file entry: {}",
                source_path.display()
            ));
        }
    }
    Ok(())
}

pub(super) fn read_bounded_regular_file(
    path: &Path,
    limit: u64,
    label: &str,
) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect Python build-toolchain {label}: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err(format!(
            "Python build-toolchain {label} is not a bounded regular file: {}",
            path.display()
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|file| file.take(limit + 1).read_to_end(&mut bytes))
        .map_err(|error| format!("failed to read Python build-toolchain {label}: {error}"))?;
    if bytes.len() as u64 > limit {
        return Err(format!(
            "Python build-toolchain {label} exceeds {limit} bytes"
        ));
    }
    Ok(bytes)
}

pub(super) fn validate_relative_path(path: &Path, label: &str) -> Result<(), String> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.to_string_lossy().contains(['\0', '\\'])
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "Python build-toolchain {label} is not a canonical relative path: {}",
            path.display()
        ));
    }
    Ok(())
}

pub(super) fn write_record(path: &Path, record: &PythonBuildToolchainRecord) -> Result<(), String> {
    let bytes = serde_json::to_vec(record)
        .map_err(|error| format!("failed to serialize Python build-toolchain record: {error}"))?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err("Python build-toolchain record exceeds its size limit".to_string());
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).map_err(|error| {
        format!(
            "failed to create Python build-toolchain record {}: {error}",
            path.display()
        )
    })?;
    file.write_all(&bytes).map_err(|error| {
        format!(
            "failed to write Python build-toolchain record {}: {error}",
            path.display()
        )
    })?;
    file.sync_all().map_err(|error| {
        format!(
            "failed to sync Python build-toolchain record {}: {error}",
            path.display()
        )
    })
}

#[cfg(unix)]
pub(super) fn is_executable(metadata: &fs::Metadata) -> bool {
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
pub(super) fn is_executable(_metadata: &fs::Metadata) -> bool {
    false
}

pub(super) fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

pub(super) fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to hash Python build-toolchain identity: {error}"))
}

pub(super) fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(super) fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
