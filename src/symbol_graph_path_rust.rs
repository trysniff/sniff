use super::lookup_file;
use crate::symbol_graph::ResolveContext;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

fn crate_root_file(ctx: &ResolveContext<'_>) -> Option<String> {
    let root = rust_module_root(ctx.project_root);
    ["lib.rs", "main.rs", "mod.rs"]
        .iter()
        .find_map(|name| lookup_file(&root.join(name).to_string_lossy(), ctx.all_files))
}

fn resolve_linked_rust_module(ctx: &ResolveContext<'_>, parts: &[&str]) -> Option<String> {
    let mut index = 0usize;
    let mut current = match parts.first().copied()? {
        "crate" => {
            index = 1;
            crate_root_file(ctx)?
        }
        "self" => {
            index = 1;
            ctx.importing_file.to_string()
        }
        "super" => {
            let mut current = ctx.importing_file.to_string();
            while parts.get(index) == Some(&"super") {
                current = ctx
                    .rust_parents
                    .get(&super::super::normalize_path(&current))?
                    .clone();
                index += 1;
            }
            current
        }
        crate_name if ctx.rust_crate_names.contains(crate_name) => {
            index = 1;
            crate_root_file(ctx)?
        }
        _ => ctx.importing_file.to_string(),
    };

    while let Some(segment) = parts.get(index) {
        current = ctx
            .rust_modules
            .get(&(
                super::super::normalize_path(&current),
                (*segment).to_string(),
            ))?
            .clone();
        index += 1;
    }
    Some(current)
}

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
    ctx: &ResolveContext<'_>,
    source_module: &str,
) -> Option<String> {
    let parts: Vec<&str> = source_module
        .split("::")
        .filter(|p| !p.is_empty())
        .collect();
    if parts.is_empty() {
        return None;
    }

    if let Some(linked) = resolve_linked_rust_module(ctx, &parts) {
        return Some(linked);
    }

    let roots = resolve_rust_module_roots(ctx.importing_file, ctx.project_root, &parts)?;

    let start_idx = match parts[0] {
        "crate" | "self" => 1,
        "super" => parts.iter().take_while(|p| **p == "super").count(),
        crate_name if ctx.rust_crate_names.contains(crate_name) => 1,
        _ => 0,
    };
    let module_parts = &parts[start_idx..];
    if module_parts.is_empty() {
        return resolve_rust_module_root_files(&roots, ctx.all_files);
    }

    resolve_rust_module_candidates(&roots, module_parts, ctx.all_files)
}
