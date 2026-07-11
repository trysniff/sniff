use std::collections::HashMap;
use std::path::Path;

pub(super) fn resolve_go_module_path(
    source_module: &str,
    all_files: &HashMap<String, String>,
) -> Option<String> {
    let suffix = source_module.replace('\\', "/");
    for f in all_files.values() {
        let f_path = Path::new(f);
        if let Some(p_dir) = f_path.parent() {
            let p_dir_str = p_dir.to_string_lossy().replace('\\', "/");
            if p_dir_str.ends_with(&suffix) {
                return Some(f.clone());
            }
        }
    }
    None
}
