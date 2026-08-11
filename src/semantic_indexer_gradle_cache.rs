use super::fs_safety::reject_link_or_reparse;
use std::fs;
use std::path::Path;

const MAX_CACHE_ENTRIES: usize = 500_000;
const MAX_CACHE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

pub(super) fn transfer_cache(source: &Path, destination: &Path) -> Result<(), String> {
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
    validate_cache_tree(&source)?;
    fs::rename(&source, destination).map_err(|error| {
        format!(
            "failed to promote the validated Kotlin dependency cache from {} to {}: {error}",
            source.display(),
            destination.display()
        )
    })
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

fn validate_cache_tree(cache: &Path) -> Result<(), String> {
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
            } else if !metadata.is_file() {
                return Err(format!(
                    "prepared Kotlin dependency cache contains a non-file entry: {}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}
