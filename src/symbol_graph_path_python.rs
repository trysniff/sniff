use super::lookup_file;
use std::collections::HashMap;
use std::path::Path;

pub(super) fn resolve_python_relative_module_path(
    parent_dir: &Path,
    source_module: &str,
    all_files: &HashMap<String, String>,
) -> Option<String> {
    let mut dot_count = 0;
    for c in source_module.chars() {
        if c == '.' {
            dot_count += 1;
        } else {
            break;
        }
    }
    let module_sub = &source_module[dot_count..];

    let mut target_dir = parent_dir.to_path_buf();
    for _ in 1..dot_count {
        if !target_dir.pop() {
            break;
        }
    }

    let mod_path = module_sub.replace('.', "/");
    let candidate_file = target_dir.join(format!("{}.py", mod_path));
    if let Some(orig) = lookup_file(&candidate_file.to_string_lossy(), all_files) {
        return Some(orig);
    }

    let candidate_init = target_dir.join(mod_path).join("__init__.py");
    if let Some(orig) = lookup_file(&candidate_init.to_string_lossy(), all_files) {
        return Some(orig);
    }

    None
}

pub(super) fn resolve_python_absolute_module_path(
    project_root: &str,
    source_module: &str,
    all_files: &HashMap<String, String>,
) -> Option<String> {
    let mod_path = source_module.replace('.', "/");
    for ancestor in Path::new(project_root).ancestors() {
        for root in [ancestor.to_path_buf(), ancestor.join("src")] {
            let candidate_file = root.join(format!("{}.py", mod_path));
            if let Some(orig) = lookup_file(&candidate_file.to_string_lossy(), all_files) {
                return Some(orig);
            }

            let candidate_init = root.join(&mod_path).join("__init__.py");
            if let Some(orig) = lookup_file(&candidate_init.to_string_lossy(), all_files) {
                return Some(orig);
            }
        }
    }

    None
}

pub(super) fn resolve_python_module_path(
    parent_dir: &Path,
    source_module: &str,
    project_root: &str,
    all_files: &HashMap<String, String>,
) -> Option<String> {
    if source_module.starts_with('.') {
        return resolve_python_relative_module_path(parent_dir, source_module, all_files);
    }
    resolve_python_absolute_module_path(project_root, source_module, all_files)
}
