use crate::semantic_index::RepositoryPath;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};

pub(super) fn require_normal_source_scope(
    root: &Path,
    files: &[crate::types::FileRecord],
) -> Result<GoRepositoryScope, super::SemanticIndexerRunFailure> {
    super::go_project::require_go_project_root(root)?;
    let result: Result<GoRepositoryScope, String> = (|| {
        let scope = discover(root)?;
        let required = super::files_for_indexer(
            files,
            crate::semantic_indexer_manifest::SemanticIndexerKind::Go,
        )
        .iter()
        .map(|file| require_plain_source_path(root, Path::new(&file.file_path)))
        .collect::<Result<BTreeSet<_>, _>>()?;
        scope.require_source_owners(&required)?;
        Ok(scope)
    })();
    result.map_err(|detail| {
        super::failure(
            super::SemanticIndexerRunFailureKind::UnsupportedProjectShape,
            super::SemanticIndexerRunPhase::RepositoryValidation,
            Some(crate::semantic_indexer_manifest::SemanticIndexerKind::Go),
            detail,
        )
    })
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct GoRepositoryScope {
    pub(super) modules: BTreeMap<RepositoryPath, BTreeSet<RepositoryPath>>,
}

impl GoRepositoryScope {
    pub(super) fn require_source_owners(
        &self,
        required: &BTreeSet<RepositoryPath>,
    ) -> Result<(), String> {
        let owned = self
            .modules
            .values()
            .flatten()
            .cloned()
            .collect::<BTreeSet<_>>();
        let missing = required.difference(&owned).take(8).collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(format!(
                "Go source scope has no plain module/package-pattern owner: {missing:?}"
            ));
        }
        Ok(())
    }
}

pub(super) fn discover(root: &Path) -> Result<GoRepositoryScope, String> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("failed to inspect Go source root: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("Go source root is not a plain directory".to_string());
    }
    let mut scope = GoRepositoryScope {
        modules: BTreeMap::new(),
    };
    visit(root, root, None, None, &mut scope)?;
    Ok(scope)
}

fn visit(
    root: &Path,
    directory: &Path,
    owner: Option<&RepositoryPath>,
    inherited_workspace: Option<&Path>,
    scope: &mut GoRepositoryScope,
) -> Result<(), String> {
    let workspace_path = directory.join("go.work");
    let local_workspace = inspect_optional(&workspace_path)?.map(|_| workspace_path);
    let workspace = local_workspace.as_deref().or(inherited_workspace);
    let manifest = directory.join("go.mod");
    let local_owner = if let Some(metadata) = inspect_optional(&manifest)? {
        if let Some(workspace) = workspace {
            return Err(format!(
                "Go workspace requires compiler-proven module closure before discovery: {}",
                workspace.display()
            ));
        }
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(format!(
                "Go module metadata is not a plain file: {}",
                manifest.display()
            ));
        }
        let project = repository_path(root, &manifest)?;
        scope.modules.insert(project.clone(), BTreeSet::new());
        Some(project)
    } else {
        None
    };
    let owner = local_owner.as_ref().or(owner);
    let mut entries = fs::read_dir(directory)
        .map_err(|error| format!("failed to enumerate Go source scope: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to enumerate Go source scope: {error}"))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name();
        let bytes = name.as_encoded_bytes();
        // Match Go's ./... traversal, not generic application-role exclusions.
        if bytes.starts_with(b".") || bytes.starts_with(b"_") {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("failed to inspect Go source scope: {error}"))?;
        if metadata.is_dir() && (name == "vendor" || name == "testdata") {
            continue;
        }
        if metadata.file_type().is_symlink() {
            if bytes.ends_with(b".go") {
                return Err(format!(
                    "Go source census cannot prove symlink ownership: {}",
                    path.display()
                ));
            }
            // Go package traversal does not follow symlink directories. A
            // requested document below one still fails the owner check.
            continue;
        }
        if metadata.is_dir() {
            visit(root, &path, owner, workspace, scope)?;
        } else if bytes.ends_with(b".go") {
            if !metadata.is_file() {
                return Err(format!(
                    "Go source census input is not a plain file: {}",
                    path.display()
                ));
            }
            let owner = owner
                .ok_or_else(|| format!("Go source has no module owner: {}", path.display()))?;
            scope
                .modules
                .get_mut(owner)
                .ok_or_else(|| "Go source census lost its module owner".to_string())?
                .insert(repository_path(root, &path)?);
        }
    }
    Ok(())
}

fn require_plain_source_path(root: &Path, file: &Path) -> Result<RepositoryPath, String> {
    let file = if file.is_absolute() {
        file.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| error.to_string())?
            .join(file)
    };
    let canonical_root = fs::canonicalize(root).map_err(|error| error.to_string())?;
    // Preserve the caller's spelling below the repository, including internal
    // aliases, while accommodating platform aliases above it (e.g. /var).
    let lexical_root = file
        .ancestors()
        .filter(|ancestor| fs::canonicalize(ancestor).is_ok_and(|path| path == canonical_root))
        .last()
        .ok_or_else(|| format!("Go source is outside its repository: {}", file.display()))?;
    if fs::symlink_metadata(lexical_root)
        .map_err(|error| error.to_string())?
        .file_type()
        .is_symlink()
    {
        return Err(format!(
            "Go selected source passes through a symlink: {}",
            lexical_root.display()
        ));
    }
    let mut path = lexical_root.to_path_buf();
    for component in file
        .strip_prefix(lexical_root)
        .map_err(|error| error.to_string())?
        .components()
    {
        if !matches!(component, Component::Normal(_)) {
            return Err("Go selected source contains a non-canonical path component".to_string());
        }
        path.push(component);
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "Go selected source passes through a symlink: {}",
                path.display()
            ));
        }
    }
    super::repository_relative_path(root, &file)
}

fn inspect_optional(path: &Path) -> Result<Option<fs::Metadata>, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "failed to inspect Go project metadata {}: {error}",
            path.display()
        )),
    }
}

fn repository_path(root: &Path, path: &Path) -> Result<RepositoryPath, String> {
    let relative = path.strip_prefix(root).map_err(|error| error.to_string())?;
    let relative = relative
        .to_str()
        .ok_or_else(|| "Go source census path is not UTF-8".to_string())?
        .replace('\\', "/");
    Ok(RepositoryPath(relative))
}

#[cfg(test)]
#[path = "tests/semantic_indexer_go_model_scope.rs"]
mod tests;
