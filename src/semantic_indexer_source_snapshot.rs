use super::repository_relative_path;
use crate::types::FileRecord;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub(super) fn source_integrity_digest_at(
    repository_root: &Path,
    content_root: &Path,
    files: &[FileRecord],
) -> Result<String, String> {
    let mut sources = BTreeMap::new();
    for file in files {
        let relative = repository_relative_path(repository_root, Path::new(&file.file_path))?;
        if sources
            .insert(relative.clone(), file.source.as_bytes())
            .is_some()
        {
            return Err(format!(
                "semantic source snapshot repeats document {}",
                relative.0
            ));
        }
    }
    let mut digest = Sha256::new();
    for (relative, expected) in sources {
        let path = content_root.join(Path::new(&relative.0));
        let bytes = fs::read(&path).map_err(|error| {
            format!(
                "failed to hash eligible source file {} from semantic content root {}: {error}",
                relative.0,
                content_root.display()
            )
        })?;
        // A disk-only baseline could accept edits made after AST parsing.
        if bytes != expected {
            return Err(format!(
                "semantic compiler input differs from parsed source snapshot: {}",
                relative.0
            ));
        }
        digest.update((relative.0.len() as u64).to_le_bytes());
        digest.update(relative.0.as_bytes());
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(test)]
#[path = "tests/semantic_indexer_source_snapshot.rs"]
mod tests;
