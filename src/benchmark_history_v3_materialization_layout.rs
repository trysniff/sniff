use super::{HistoricalV3MaterializationError, HistoricalV3MaterializedRoots, failed, invalid};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

pub(super) fn write_new(path: &Path, bytes: &[u8]) -> Result<(), HistoricalV3MaterializationError> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| failed(format!("failed to create historical-v3 patch: {error}")))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| failed(format!("failed to persist historical-v3 patch: {error}")))
}

pub(super) fn validate_root_layout(
    roots: &HistoricalV3MaterializedRoots,
) -> Result<(), HistoricalV3MaterializationError> {
    let repository = fs::canonicalize(&roots.repository_root)
        .map_err(|error| invalid(format!("failed to resolve repository root: {error}")))?;
    let parent = repository
        .parent()
        .ok_or_else(|| invalid("historical-v3 repository root has no parent"))?;
    if repository.file_name().and_then(|value| value.to_str()) != Some("repository") {
        return Err(invalid("historical-v3 repository root changed its name"));
    }
    for (path, name) in [
        (&roots.base_root, "base"),
        (&roots.head_root, "head"),
        (&roots.merge_root, "merge"),
        (&roots.reproduced_root, "reproduced"),
    ] {
        let resolved = fs::canonicalize(path)
            .map_err(|error| invalid(format!("failed to resolve {name} root: {error}")))?;
        if resolved.parent() != Some(parent)
            || resolved.file_name().and_then(|value| value.to_str()) != Some(name)
        {
            return Err(invalid(
                "historical-v3 materialized roots escaped their root",
            ));
        }
    }
    let patch = fs::canonicalize(&roots.patch_path)
        .map_err(|error| invalid(format!("failed to resolve patch path: {error}")))?;
    if patch.parent() != Some(parent)
        || patch.file_name().and_then(|value| value.to_str()) != Some("merge.patch")
    {
        return Err(invalid(
            "historical-v3 patch escaped its materialization root",
        ));
    }
    Ok(())
}
