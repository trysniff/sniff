use std::collections::HashMap;
use std::path::Path;

use super::super::core;

pub(crate) fn lookup_file(
    candidate_str: &str,
    all_files: &HashMap<String, String>,
) -> Option<String> {
    let norm = core::normalize_path(candidate_str);
    all_files.get(&norm).cloned().or_else(|| {
        let cwd = std::env::current_dir().ok()?;
        let cwd_norm = core::normalize_path(&cwd.to_string_lossy());

        if let Some(stripped) = norm.strip_prefix(&(cwd_norm.clone() + "/"))
            && let Some(orig) = all_files.get(stripped)
        {
            return Some(orig.clone());
        }

        let candidate_path = Path::new(candidate_str);
        if candidate_path.is_relative() {
            let abs_candidate = cwd.join(candidate_path);
            let abs_norm = core::normalize_path(&abs_candidate.to_string_lossy());
            if let Some(orig) = all_files.get(&abs_norm) {
                return Some(orig.clone());
            }
        }

        None
    })
}
