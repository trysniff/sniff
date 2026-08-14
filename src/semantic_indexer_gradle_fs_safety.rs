use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn reject_linked_path(root: &Path, relative: &Path) -> Result<(), String> {
    let mut current = PathBuf::from(root);
    for component in relative.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            format!(
                "failed to inspect Gradle path {}: {error}",
                current.display()
            )
        })?;
        reject_link_or_reparse(&current, &metadata)?;
    }
    Ok(())
}

pub(super) fn reject_link_or_reparse(path: &Path, metadata: &fs::Metadata) -> Result<(), String> {
    if metadata.file_type().is_symlink() || is_reparse_point(metadata) {
        return Err(format!(
            "Gradle dependency preparation refuses linked or reparse-point entries: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}
