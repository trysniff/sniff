use super::lookup_file;
use std::collections::HashMap;
use std::path::Path;

pub(super) fn resolve_js_ts_module_path(
    parent_dir: &Path,
    source_module: &str,
    all_files: &HashMap<String, String>,
) -> Option<String> {
    if !source_module.starts_with('.') {
        return None;
    }

    let relative_path = parent_dir.join(source_module);
    for ext in &["ts", "js", "tsx", "jsx", "mjs", "cjs"] {
        let candidate = relative_path.with_extension(ext);
        if let Some(orig) = lookup_file(&candidate.to_string_lossy(), all_files) {
            return Some(orig);
        }
    }

    for ext in &["ts", "js", "tsx", "jsx"] {
        let candidate = relative_path.join(format!("index.{}", ext));
        if let Some(orig) = lookup_file(&candidate.to_string_lossy(), all_files) {
            return Some(orig);
        }
    }

    None
}
