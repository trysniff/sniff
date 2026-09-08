use super::fs_safety::reject_link_or_reparse;
use sha2::{Digest, Sha256};
use std::fs;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

const MAX_CACHE_ENTRIES: usize = 500_000;
const MAX_CACHE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

pub(super) fn transfer_cache(source: &Path, destination: &Path) -> Result<String, String> {
    if destination.exists() {
        return Err(format!(
            "refusing to overwrite Kotlin dependency cache {}",
            destination.display()
        ));
    }
    let source = fs::canonicalize(source).map_err(|error| {
        format!(
            "failed to resolve prepared Kotlin dependency cache {}: {error}",
            source.display()
        )
    })?;
    prune_ephemeral_cache_state(&source)?;
    let tree_sha256 = validate_cache_tree(&source)?;
    let destination_parent = destination.parent().ok_or_else(|| {
        format!(
            "Kotlin dependency cache destination has no parent: {}",
            destination.display()
        )
    })?;
    fs::create_dir_all(destination_parent).map_err(|error| {
        format!(
            "failed to create Kotlin dependency cache parent {}: {error}",
            destination_parent.display()
        )
    })?;
    fs::rename(&source, destination).map_err(|error| {
        format!(
            "failed to promote the validated Kotlin dependency cache from {} to {}: {error}",
            source.display(),
            destination.display()
        )
    })?;
    Ok(tree_sha256)
}

fn prune_ephemeral_cache_state(cache: &Path) -> Result<(), String> {
    for directory in [cache.join(".tmp"), cache.join("project-cache")] {
        if directory.exists() {
            fs::remove_dir_all(&directory).map_err(|error| {
                format!(
                    "failed to remove preparation-only Gradle state {}: {error}",
                    directory.display()
                )
            })?;
        }
    }
    let properties = cache.join("gradle.properties");
    if properties.exists() {
        fs::remove_file(&properties).map_err(|error| {
            format!(
                "failed to remove preparation-only Gradle properties {}: {error}",
                properties.display()
            )
        })?;
    }
    Ok(())
}

fn validate_cache_tree(cache: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(cache).map_err(|error| {
        format!(
            "failed to inspect prepared cache {}: {error}",
            cache.display()
        )
    })?;
    reject_link_or_reparse(cache, &metadata)?;
    if !metadata.is_dir() {
        return Err(format!(
            "prepared cache is not a directory: {}",
            cache.display()
        ));
    }
    let mut pending = vec![cache.to_path_buf()];
    let mut files = Vec::new();
    let mut entries = 0usize;
    let mut bytes = 0u64;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|error| {
            format!(
                "failed to inspect prepared cache {}: {error}",
                directory.display()
            )
        })? {
            let entry = entry.map_err(|error| {
                format!(
                    "failed to enumerate prepared cache {}: {error}",
                    directory.display()
                )
            })?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                format!(
                    "failed to inspect prepared cache entry {}: {error}",
                    path.display()
                )
            })?;
            reject_link_or_reparse(&path, &metadata)?;
            entries = entries.saturating_add(1);
            bytes = bytes.saturating_add(metadata.len());
            if entries > MAX_CACHE_ENTRIES || bytes > MAX_CACHE_BYTES {
                return Err(format!(
                    "prepared Kotlin dependency cache exceeds {MAX_CACHE_ENTRIES} entries or {MAX_CACHE_BYTES} bytes"
                ));
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                let relative = path
                    .strip_prefix(cache)
                    .map_err(|_| "prepared Gradle cache entry escaped its root".to_string())?
                    .to_str()
                    .ok_or_else(|| {
                        format!(
                            "prepared Gradle cache path is not UTF-8: {}",
                            path.display()
                        )
                    })?
                    .replace('\\', "/");
                files.push((relative, path, metadata.len()));
            } else {
                return Err(format!(
                    "prepared Kotlin dependency cache contains a non-file entry: {}",
                    path.display()
                ));
            }
        }
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut digest = Sha256::new();
    for (relative, path, size) in files {
        digest.update((relative.len() as u64).to_le_bytes());
        digest.update(relative.as_bytes());
        digest.update(size.to_le_bytes());
        let mut reader = BufReader::new(File::open(&path).map_err(|error| {
            format!(
                "failed to open prepared Gradle cache file {}: {error}",
                path.display()
            )
        })?);
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = reader.read(&mut buffer).map_err(|error| {
                format!(
                    "failed to hash prepared Gradle cache file {}: {error}",
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
