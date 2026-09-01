use super::{
    SemanticIndexerRunFailure, SemanticIndexerRunFailureKind, SemanticIndexerRunPhase, failure,
};
use crate::semantic_indexer_manifest::SemanticIndexerKind;
use std::fs;
use std::path::Path;

pub(super) fn require_go_project_root(root: &Path) -> Result<(), SemanticIndexerRunFailure> {
    let module = root.join("go.mod");
    match fs::metadata(&module) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return Err(non_file_metadata(&module)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let workspace = root.join("go.work");
            return match fs::metadata(&workspace) {
                Ok(metadata) if metadata.is_file() => Err(failure(
                    SemanticIndexerRunFailureKind::UnsupportedProjectShape,
                    SemanticIndexerRunPhase::RepositoryValidation,
                    Some(SemanticIndexerKind::Go),
                    format!(
                        "Go workspace {} has no root go.mod; pinned scip-go is a single-module indexer, so Sniff will not index a partial workspace or fall back to name matching",
                        workspace.display()
                    ),
                )),
                Ok(_) => Err(non_file_metadata(&workspace)),
                Err(work_error) if work_error.kind() == std::io::ErrorKind::NotFound => {
                    Err(missing_project_metadata(root))
                }
                Err(work_error) => Err(metadata_inspection_failure(&workspace, work_error)),
            };
        }
        Err(error) => return Err(metadata_inspection_failure(&module, error)),
    }
    let workspace = root.join("go.work");
    match fs::metadata(&workspace) {
        Ok(metadata) if metadata.is_file() => Err(failure(
            SemanticIndexerRunFailureKind::UnsupportedProjectShape,
            SemanticIndexerRunPhase::RepositoryValidation,
            Some(SemanticIndexerKind::Go),
            format!(
                "Go workspace {} may contain multiple modules; Sniff refuses partial single-module indexing until every workspace module and cross-module relationship can be proven",
                workspace.display()
            ),
        )),
        Ok(_) => Err(non_file_metadata(&workspace)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(metadata_inspection_failure(&workspace, error)),
    }
}

fn non_file_metadata(path: &Path) -> SemanticIndexerRunFailure {
    failure(
        SemanticIndexerRunFailureKind::UnsupportedProjectShape,
        SemanticIndexerRunPhase::RepositoryValidation,
        Some(SemanticIndexerKind::Go),
        format!(
            "Go compiler project metadata must be a file: {}",
            path.display()
        ),
    )
}

fn metadata_inspection_failure(path: &Path, error: std::io::Error) -> SemanticIndexerRunFailure {
    failure(
        SemanticIndexerRunFailureKind::InvalidInput,
        SemanticIndexerRunPhase::RepositoryValidation,
        Some(SemanticIndexerKind::Go),
        format!(
            "failed to inspect Go compiler project metadata {}: {error}",
            path.display()
        ),
    )
}

fn missing_project_metadata(root: &Path) -> SemanticIndexerRunFailure {
    failure(
        SemanticIndexerRunFailureKind::UnsupportedProjectShape,
        SemanticIndexerRunPhase::RepositoryValidation,
        Some(SemanticIndexerKind::Go),
        format!(
            "Go compiler indexing requires go.mod at the repository root {}; Sniff will not invent module metadata or fall back to name matching",
            root.display()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_root_module_metadata() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("go.mod"), "module example.com/project\n").unwrap();

        require_go_project_root(root.path()).unwrap();
    }

    #[test]
    fn rejects_workspace_without_claiming_partial_support() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("go.work"), "go 1.23\nuse ./module\n").unwrap();

        let failure = require_go_project_root(root.path()).unwrap_err();

        assert_eq!(
            failure.kind,
            SemanticIndexerRunFailureKind::UnsupportedProjectShape
        );
        assert!(failure.detail.contains("single-module indexer"));
        assert!(
            failure
                .detail
                .contains("will not index a partial workspace")
        );
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
        assert!(failure.detail.contains("requires go.mod"));
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
