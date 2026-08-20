use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

pub(super) fn review_temporary_root(output_root: &Path) -> Result<PathBuf, String> {
    let parent = output_root
        .parent()
        .ok_or_else(|| "historical-v2 review output has no parent".to_string())?;
    let metadata = fs::symlink_metadata(parent).map_err(|error| {
        format!("failed to inspect historical-v2 review output parent: {error}")
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("historical-v2 review output parent is not a plain directory".into());
    }
    let name = output_root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "historical-v2 review output name is not UTF-8".to_string())?;
    Ok(parent.join(format!(".{name}.tmp-{}", std::process::id())))
}

pub(super) fn review_safe_path(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let relative = Path::new(relative);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("historical-v2 review artifact path is unsafe".into());
    }
    Ok(root.join(relative))
}

pub(super) fn write_review_file_new(path: &Path, bytes: &[u8], label: &str) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("failed to create {label}: {error}"))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("failed to persist {label}: {error}"))
}

pub(super) fn read_plain_review_file(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect historical-v2 {label}: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("historical-v2 {label} is not a plain file"));
    }
    fs::read(path).map_err(|error| format!("failed to read historical-v2 {label}: {error}"))
}

pub(super) fn collect_review_files(root: &Path) -> Result<BTreeSet<String>, String> {
    fn visit(root: &Path, current: &Path, files: &mut BTreeSet<String>) -> Result<(), String> {
        for entry in fs::read_dir(current)
            .map_err(|error| format!("failed to inspect historical-v2 review bundle: {error}"))?
        {
            let entry =
                entry.map_err(|error| format!("failed to inspect review entry: {error}"))?;
            let kind = entry
                .file_type()
                .map_err(|error| format!("failed to inspect review entry: {error}"))?;
            if kind.is_symlink() || (!kind.is_dir() && !kind.is_file()) {
                return Err("historical-v2 review bundle contains an unsafe entry".into());
            }
            if kind.is_dir() {
                visit(root, &entry.path(), files)?;
            } else {
                let path = entry.path();
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| "historical-v2 review artifact escaped its root".to_string())?
                    .components()
                    .map(|component| component.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/");
                if !files.insert(relative) {
                    return Err("historical-v2 review bundle repeats a file".into());
                }
            }
        }
        Ok(())
    }
    let mut files = BTreeSet::new();
    visit(root, root, &mut files)?;
    Ok(files)
}

pub(super) fn review_hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| review_sha256(&bytes))
        .map_err(|error| format!("failed to commit historical-v2 review bundle: {error}"))
}

pub(super) fn review_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(super) fn is_review_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(super) fn is_review_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
