use super::super::benchmark_run::write_new_file;
use crate::benchmark::IntentionalBoundarySourceBundle;
use serde::de::DeserializeOwned;
use std::error::Error;
use std::fs;
use std::io::{Error as IoError, ErrorKind};
use std::path::{Path, PathBuf};

const SOURCE_BUNDLE_MANIFEST: &str = "manifest.json";

pub(super) fn read_source_bundle(
    directory: &str,
) -> Result<(PathBuf, IntentionalBoundarySourceBundle), Box<dyn Error>> {
    let root = existing_plain_directory(directory, "source bundle")?;
    let bundle = read_json::<IntentionalBoundarySourceBundle>(&root.join(SOURCE_BUNDLE_MANIFEST))?;
    Ok((root, bundle))
}

pub(super) fn new_directory_path(path: &str, label: &str) -> Result<PathBuf, IoError> {
    let path = absolute_path(Path::new(path))?;
    if path.exists() {
        return Err(IoError::new(
            ErrorKind::AlreadyExists,
            format!(
                "intentional-boundary {label} already exists: {}",
                path.display()
            ),
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        invalid_data(
            &format!("intentional-boundary {label} is invalid"),
            "path has no parent",
        )
    })?;
    require_plain_directory(parent, &format!("intentional-boundary {label} parent"))?;
    Ok(path)
}

pub(super) fn existing_plain_directory(path: &str, label: &str) -> Result<PathBuf, IoError> {
    let path = canonical_path(Path::new(path)).map_err(|error| {
        IoError::new(
            error.kind(),
            format!("failed to resolve intentional-boundary {label} {path}: {error}"),
        )
    })?;
    require_plain_directory(&path, &format!("intentional-boundary {label}"))?;
    Ok(path)
}

pub(super) fn require_plain_directory(path: &Path, label: &str) -> Result<(), IoError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        IoError::new(
            error.kind(),
            format!("failed to inspect {label} {}: {error}", path.display()),
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid_data(
            &format!("{label} is invalid"),
            "expected a plain directory",
        ));
    }
    Ok(())
}

pub(super) fn absolute_path(path: &Path) -> Result<PathBuf, IoError> {
    let path = std::path::absolute(path).map_err(|error| {
        IoError::new(
            error.kind(),
            format!("failed to resolve path {}: {error}", path.display()),
        )
    })?;
    normalize_platform_path(path)
}

pub(super) fn canonical_path(path: &Path) -> Result<PathBuf, IoError> {
    let path = fs::canonicalize(path)?;
    normalize_platform_path(path)
}

#[cfg(windows)]
fn normalize_platform_path(path: PathBuf) -> Result<PathBuf, IoError> {
    let value = path.to_str().ok_or_else(|| {
        invalid_data(
            "Windows path is invalid",
            "canonical path is not representable as UTF-8",
        )
    })?;
    if let Some(unc) = value.strip_prefix(r"\\?\UNC\") {
        return Ok(PathBuf::from(format!(r"\\{unc}")));
    }
    if let Some(local) = value.strip_prefix(r"\\?\") {
        return Ok(PathBuf::from(local));
    }
    Ok(path)
}

#[cfg(not(windows))]
fn normalize_platform_path(path: PathBuf) -> Result<PathBuf, IoError> {
    Ok(path)
}

pub(super) fn write_json_new(
    path: &str,
    value: &impl serde::Serialize,
) -> Result<(), Box<dyn Error>> {
    write_new_file(Path::new(path), &serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

pub(super) fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, Box<dyn Error>> {
    let text = fs::read_to_string(path).map_err(|error| {
        IoError::new(
            error.kind(),
            format!("failed to read benchmark file {}: {error}", path.display()),
        )
    })?;
    serde_json::from_str(&text).map_err(|error| {
        invalid_data(
            "failed to parse benchmark JSON",
            format!("{}: {error}", path.display()),
        )
        .into()
    })
}

pub(super) fn invalid_data(context: &str, detail: impl std::fmt::Display) -> IoError {
    IoError::new(ErrorKind::InvalidData, format!("{context}: {detail}"))
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn removes_windows_verbatim_prefixes_before_external_process_use() {
        assert_eq!(
            normalize_platform_path(PathBuf::from(r"\\?\D:\source\rank-0001")).unwrap(),
            PathBuf::from(r"D:\source\rank-0001")
        );
        assert_eq!(
            normalize_platform_path(PathBuf::from(r"\\?\UNC\server\share\source")).unwrap(),
            PathBuf::from(r"\\server\share\source")
        );
    }
}
