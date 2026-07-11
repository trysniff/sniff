use super::lookup_file;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

fn rust_module_root(project_root: &str) -> PathBuf {
    let src_root = Path::new(project_root).join("src");
    if src_root.is_dir() {
        src_root
    } else {
        Path::new(project_root).to_path_buf()
    }
}

fn resolve_rust_module_roots(
    importing_file: &str,
    project_root: &str,
    parts: &[&str],
) -> Option<Vec<PathBuf>> {
    let mut roots = vec![rust_module_root(project_root)];
    if parts[0] == "self" {
        roots[0] = Path::new(importing_file).parent()?.to_path_buf();
    } else if parts[0] == "super" {
        let mut base = Path::new(importing_file).parent()?.to_path_buf();
        let super_count = parts.iter().take_while(|p| **p == "super").count();
        for _ in 1..super_count {
            if !base.pop() {
                break;
            }
        }
        roots[0] = base;
    }
    Some(roots)
}

fn resolve_rust_module_root_files(
    roots: &[PathBuf],
    all_files: &HashMap<String, String>,
) -> Option<String> {
    for root in roots {
        for candidate_name in ["mod.rs", "lib.rs", "main.rs"] {
            let candidate = root.join(candidate_name);
            if let Some(orig) = lookup_file(&candidate.to_string_lossy(), all_files) {
                return Some(orig);
            }
        }
    }
    None
}

fn resolve_rust_module_candidates(
    roots: &[PathBuf],
    module_parts: &[&str],
    all_files: &HashMap<String, String>,
) -> Option<String> {
    let module_path = module_parts.join("/");
    for root in roots {
        let candidate_file = root.join(format!("{}.rs", module_path));
        if let Some(orig) = lookup_file(&candidate_file.to_string_lossy(), all_files) {
            return Some(orig);
        }

        let candidate_mod = root.join(&module_path).join("mod.rs");
        if let Some(orig) = lookup_file(&candidate_mod.to_string_lossy(), all_files) {
            return Some(orig);
        }
    }
    None
}

pub(super) fn resolve_rust_module_path(
    importing_file: &str,
    source_module: &str,
    project_root: &str,
    all_files: &HashMap<String, String>,
) -> Option<String> {
    let parts: Vec<&str> = source_module
        .split("::")
        .filter(|p| !p.is_empty())
        .collect();
    if parts.is_empty() {
        return None;
    }

    let roots = resolve_rust_module_roots(importing_file, project_root, &parts)?;

    let start_idx = match parts[0] {
        "crate" | "self" => 1,
        "super" => parts.iter().take_while(|p| **p == "super").count(),
        _ => 0,
    };
    let module_parts = &parts[start_idx..];
    if module_parts.is_empty() {
        return resolve_rust_module_root_files(&roots, all_files);
    }

    resolve_rust_module_candidates(&roots, module_parts, all_files)
}
