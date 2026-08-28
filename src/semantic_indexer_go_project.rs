use super::{
    SemanticIndexerRunFailure, SemanticIndexerRunFailureKind, SemanticIndexerRunPhase, failure,
};
use crate::semantic_indexer_manifest::SemanticIndexerKind;
use std::fs;
use std::path::Path;

pub(super) fn require_go_project_root(root: &Path) -> Result<(), SemanticIndexerRunFailure> {
    for manifest in ["go.mod", "go.work"] {
        let path = root.join(manifest);
        match fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() => return Ok(()),
            Ok(_) => {
                return Err(failure(
                    SemanticIndexerRunFailureKind::UnsupportedProjectShape,
                    SemanticIndexerRunPhase::RepositoryValidation,
                    Some(SemanticIndexerKind::Go),
                    format!(
                        "Go compiler project metadata must be a file: {}",
                        path.display()
                    ),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(failure(
                    SemanticIndexerRunFailureKind::InvalidInput,
                    SemanticIndexerRunPhase::RepositoryValidation,
                    Some(SemanticIndexerKind::Go),
                    format!(
                        "failed to inspect Go compiler project metadata {}: {error}",
                        path.display()
                    ),
                ));
            }
        }
    }
    Err(failure(
        SemanticIndexerRunFailureKind::UnsupportedProjectShape,
        SemanticIndexerRunPhase::RepositoryValidation,
        Some(SemanticIndexerKind::Go),
        format!(
            "Go compiler indexing requires go.mod or go.work at the repository root {}; Sniff will not invent module metadata or fall back to name matching",
            root.display()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_module_or_workspace_metadata() {
        for manifest in ["go.mod", "go.work"] {
            let root = tempfile::tempdir().unwrap();
            fs::write(root.path().join(manifest), "module example.com/project\n").unwrap();

            require_go_project_root(root.path()).unwrap();
        }
    }

    #[test]
    fn rejects_missing_metadata_without_a_fallback() {
        let root = tempfile::tempdir().unwrap();

        let failure = require_go_project_root(root.path()).unwrap_err();

        assert_eq!(
            failure.kind,
            SemanticIndexerRunFailureKind::UnsupportedProjectShape
        );
        assert_eq!(failure.phase, SemanticIndexerRunPhase::RepositoryValidation);
        assert_eq!(failure.indexer, Some(SemanticIndexerKind::Go));
        assert!(failure.detail.contains("requires go.mod or go.work"));
        assert!(failure.detail.contains("will not invent module metadata"));
        assert!(failure.detail.contains("fall back to name matching"));
    }

    #[test]
    fn rejects_non_file_metadata() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("go.mod")).unwrap();

        let failure = require_go_project_root(root.path()).unwrap_err();

        assert_eq!(
            failure.kind,
            SemanticIndexerRunFailureKind::UnsupportedProjectShape
        );
        assert_eq!(failure.phase, SemanticIndexerRunPhase::RepositoryValidation);
        assert!(failure.detail.contains("metadata must be a file"));
    }
}
