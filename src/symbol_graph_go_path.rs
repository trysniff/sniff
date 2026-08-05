use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub(super) fn resolve_go_module_path(
    source_module: &str,
    project_root: &str,
    all_files: &HashMap<String, String>,
) -> Option<String> {
    let module_name = fs::read_to_string(Path::new(project_root).join("go.mod"))
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                line.trim()
                    .strip_prefix("module ")
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .map(str::to_string)
            })
        });
    let source_path = Path::new(source_module);
    let target_dir = if source_path.is_absolute() {
        source_path.to_path_buf()
    } else if let Some(module_name) = module_name {
        let relative = source_module
            .strip_prefix(&module_name)
            .and_then(|suffix| suffix.strip_prefix('/'))
            .or_else(|| (source_module == module_name).then_some(""))?;
        Path::new(project_root).join(relative)
    } else {
        Path::new(project_root).join(source_module)
    };
    let normalized_target = super::super::core::normalize_path(&target_dir.to_string_lossy());

    all_files.values().find_map(|file| {
        let parent = Path::new(file).parent()?;
        (super::super::core::normalize_path(&parent.to_string_lossy()) == normalized_target)
            .then(|| file.clone())
    })
}
