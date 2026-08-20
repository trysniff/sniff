use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

pub(super) fn canonical_plain_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {label}: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!("{label} is not a plain directory"));
    }
    fs::canonicalize(path).map_err(|error| format!("failed to resolve {label}: {error}"))
}

pub(super) fn relative_plain_directory(root: &Path, child: &Path) -> Result<String, String> {
    let root = canonical_plain_directory(root, "historical-v2 corpus root")?;
    let child = canonical_plain_directory(child, "historical-v2 source bundle root")?;
    let relative = child
        .strip_prefix(&root)
        .map_err(|_| "historical-v2 source bundle is outside the corpus root".to_string())?;
    path_string(relative)
}

pub(super) fn relative_plain_file(
    root: &Path,
    child: &Path,
    label: &str,
) -> Result<String, String> {
    let metadata = fs::symlink_metadata(child)
        .map_err(|error| format!("failed to inspect {label}: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{label} is not a plain file"));
    }
    let root = canonical_plain_directory(root, "historical-v2 corpus root")?;
    let child =
        fs::canonicalize(child).map_err(|error| format!("failed to resolve {label}: {error}"))?;
    let relative = child
        .strip_prefix(&root)
        .map_err(|_| format!("{label} is outside the corpus root"))?;
    path_string(relative)
}

pub(super) fn require_new_file_under_root(root: &Path, path: &Path) -> Result<(), String> {
    if path.exists() {
        return Err("historical-v2 corpus bundle already exists".into());
    }
    let root = canonical_plain_directory(root, "historical-v2 corpus root")?;
    let parent = path
        .parent()
        .ok_or_else(|| "historical-v2 corpus bundle has no parent".to_string())?;
    let parent = canonical_plain_directory(parent, "historical-v2 corpus bundle parent")?;
    if parent.strip_prefix(root).is_err()
        || path.file_name().is_none()
        || path
            .components()
            .next_back()
            .is_none_or(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("historical-v2 corpus bundle path is outside its corpus root".into());
    }
    Ok(())
}

pub(super) fn safe_join(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let relative = Path::new(relative);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("historical-v2 corpus artifact path is unsafe".into());
    }
    Ok(root.join(relative))
}

pub(super) fn load_plain_file(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {label}: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > max_bytes {
        return Err(format!("{label} is unsafe or exceeds its size limit"));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    File::open(path)
        .and_then(|file| {
            file.take(max_bytes.saturating_add(1))
                .read_to_end(&mut bytes)
        })
        .map_err(|error| format!("failed to read {label}: {error}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(format!("{label} exceeds its size limit"));
    }
    Ok(bytes)
}

pub(super) fn file_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn path_string(path: &Path) -> Result<String, String> {
    if path.as_os_str().is_empty() {
        return Err("historical-v2 corpus artifact path is empty".into());
    }
    path.components()
        .map(|component| {
            let Component::Normal(value) = component else {
                return Err("historical-v2 corpus artifact path is unsafe".to_string());
            };
            value
                .to_str()
                .map(str::to_string)
                .ok_or_else(|| "historical-v2 corpus artifact path is not UTF-8".to_string())
        })
        .collect::<Result<Vec<_>, String>>()
        .map(|parts| parts.join("/"))
}
