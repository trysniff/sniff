use super::safe_relative_path;
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use same_file::Handle;
use std::fs::File;
use std::io::Read;
use std::path::Path;

// A resource bound for serialized evidence, not a method-eligibility filter.
pub(super) const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;

pub(crate) fn read_plain_file(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>, String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| format!("{label} has no file name"))?;
    let directory = Dir::open_ambient_dir(parent, ambient_authority())
        .map_err(|error| format!("failed to open {label} directory: {error}"))?;
    read_bounded(
        open_plain_file(&directory, Path::new(name), limit, label)?,
        limit,
        label,
    )
}

pub(super) fn read_artifact(root: &Path, relative: &str) -> Result<Vec<u8>, String> {
    let relative = safe_relative_path(relative)?;
    // Descendants stay beneath this handle; absolute aliases fail closed even inside the root.
    let directory = Dir::open_ambient_dir(root, ambient_authority())
        .map_err(|error| format!("failed to open source-seal root: {error}"))?;
    let file = open_plain_file(
        &directory,
        &relative,
        MAX_ARTIFACT_BYTES,
        "source-seal artifact",
    )?;
    let identity = Handle::from_file(
        file.try_clone()
            .map_err(|error| format!("failed to clone source-seal artifact handle: {error}"))?,
    )
    .map_err(|error| format!("failed to identify source-seal artifact: {error}"))?;
    let bytes = read_bounded(file, MAX_ARTIFACT_BYTES, "source-seal artifact")?;
    verify_binding(&directory, &relative, &identity)?;
    Ok(bytes)
}

fn verify_binding(directory: &Dir, relative: &Path, identity: &Handle) -> Result<(), String> {
    let file = open_plain_file(
        directory,
        relative,
        MAX_ARTIFACT_BYTES,
        "source-seal artifact",
    )?;
    let current = Handle::from_file(file)
        .map_err(|error| format!("failed to reidentify source-seal artifact: {error}"))?;
    if &current != identity {
        return Err("source-seal artifact changed its file identity".to_string());
    }
    Ok(())
}

fn open_plain_file(directory: &Dir, path: &Path, limit: u64, label: &str) -> Result<File, String> {
    open_plain_file_after_inspection(directory, path, limit, label, || {})
}

fn open_plain_file_after_inspection(
    directory: &Dir,
    path: &Path,
    limit: u64,
    label: &str,
    before_open: impl FnOnce(),
) -> Result<File, String> {
    let metadata = directory
        .symlink_metadata(path)
        .map_err(|error| confined_error(label, error))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err(format!("{label} is not a plain bounded file"));
    }
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_fs_ext::OpenOptionsSyncExt;
        options.nonblock(true);
    }
    before_open();
    let file = directory
        .open_with(path, &options)
        .map_err(|error| confined_error(label, error))?
        .into_std();
    let opened = file
        .metadata()
        .map_err(|error| format!("failed to inspect opened {label}: {error}"))?;
    if !opened.is_file() || opened.file_type().is_symlink() || opened.len() > limit {
        return Err(format!("{label} is not a plain bounded file"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if opened.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!("{label} is not a plain bounded file"));
        }
    }
    Ok(file)
}

fn confined_error(label: &str, error: std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        format!("{label} is inaccessible or escapes the source-seal bundle: {error}")
    } else {
        format!("failed to access {label}: {error}")
    }
}

fn read_bounded(reader: impl Read, limit: u64, label: &str) -> Result<Vec<u8>, String> {
    let limit_with_sentinel = limit
        .checked_add(1)
        .ok_or_else(|| format!("{label} read limit is invalid"))?;
    let mut bytes = Vec::new();
    reader
        .take(limit_with_sentinel)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read {label}: {error}"))?;
    if bytes.len() as u64 > limit {
        return Err(format!("{label} exceeds its read limit"));
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "benchmark_source_seal_io_tests.rs"]
mod tests;
