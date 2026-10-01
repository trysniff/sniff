use super::*;

pub(super) fn prepare_root(execution_root: &Path) -> Result<(), String> {
    super::go_input_tree::require_plain(execution_root, true)?;
    for path in cache_ancestors(execution_root) {
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&path).map_err(|error| {
                    format!("failed to prepare Go module-cache input root: {error}")
                })?;
            }
            Err(error) => {
                return Err(format!(
                    "failed to inspect Go module-cache input root: {error}"
                ));
            }
        }
        super::go_input_tree::require_plain(&path, true)?;
    }
    Ok(())
}

pub(super) fn identity_sha256(execution_root: &Path) -> Result<String, String> {
    for path in cache_ancestors(execution_root) {
        super::go_input_tree::require_plain(&path, true)?;
    }
    super::go_input_tree::sha256(
        &go_module_cache_root(execution_root),
        b"sniff-go-module-cache-input-tree-v1",
    )
    .map_err(|detail| format!("Go module-cache input binding: {detail}"))
}

fn cache_ancestors(execution_root: &Path) -> Vec<PathBuf> {
    let cache = go_module_cache_root(execution_root);
    let mut paths = cache
        .ancestors()
        .take_while(|path| *path != execution_root)
        .map(Path::to_path_buf)
        .collect::<Vec<_>>();
    paths.push(execution_root.to_path_buf());
    paths.reverse();
    paths
}

#[cfg(test)]
#[path = "tests/semantic_indexer_go_dependencies.rs"]
mod tests;
