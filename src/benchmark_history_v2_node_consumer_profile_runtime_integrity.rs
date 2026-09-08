use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

const MAX_MIRROR_FILES: usize = 100_000;
const MAX_MIRROR_BYTES: u64 = 1024 * 1024 * 1024;

pub(super) fn file_sha256(path: &Path, label: &str) -> Result<String, String> {
    let file = File::open(path)
        .map_err(|error| format!("failed to open {label} {}: {error}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| format!("failed to hash {label} {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

pub(super) fn verify_file_unchanged(
    path: &Path,
    label: &str,
    expected: &str,
) -> Result<(), String> {
    if file_sha256(path, label)? == expected {
        Ok(())
    } else {
        Err(format!(
            "{label} changed during consumer-profile resolution"
        ))
    }
}

pub(super) fn directory_tree_sha256(root: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    collect_mirror_files(root, root, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    if files.len() > MAX_MIRROR_FILES {
        return Err(format!(
            "Node consumer mirror exceeds {MAX_MIRROR_FILES} files"
        ));
    }
    let mut total_bytes = 0_u64;
    let mut digest = Sha256::new();
    for (relative, path, size) in files {
        total_bytes = total_bytes.saturating_add(size);
        if total_bytes > MAX_MIRROR_BYTES {
            return Err(format!(
                "Node consumer mirror exceeds {MAX_MIRROR_BYTES} bytes"
            ));
        }
        digest.update((relative.len() as u64).to_le_bytes());
        digest.update(relative.as_bytes());
        digest.update(size.to_le_bytes());
        let mut reader = BufReader::new(File::open(&path).map_err(|error| {
            format!(
                "failed to open Node consumer mirror file {}: {error}",
                path.display()
            )
        })?);
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = reader.read(&mut buffer).map_err(|error| {
                format!(
                    "failed to hash Node consumer mirror file {}: {error}",
                    path.display()
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

fn collect_mirror_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<(String, PathBuf, u64)>,
) -> Result<(), String> {
    for entry in fs::read_dir(directory).map_err(|error| {
        format!(
            "failed to inspect Node consumer mirror {}: {error}",
            directory.display()
        )
    })? {
        let entry = entry
            .map_err(|error| format!("failed to inspect Node consumer mirror entry: {error}"))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!(
                "failed to inspect Node consumer mirror path {}: {error}",
                path.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "Node consumer mirror contains a symbolic link: {}",
                path.display()
            ));
        }
        if metadata.is_dir() {
            collect_mirror_files(root, &path, files)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "Node consumer mirror file escaped its root".to_string())?
                .to_string_lossy()
                .replace('\\', "/");
            files.push((relative, path, metadata.len()));
        } else {
            return Err(format!(
                "Node consumer mirror contains a non-file entry: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

pub(super) fn verify_directory_unchanged(
    root: &Path,
    label: &str,
    expected: &str,
) -> Result<(), String> {
    if directory_tree_sha256(root)? == expected {
        Ok(())
    } else {
        Err(format!(
            "{label} changed during consumer-profile resolution"
        ))
    }
}
