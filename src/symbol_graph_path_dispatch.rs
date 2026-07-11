use super::ResolveContext;
use std::path::Path;

#[path = "symbol_graph_go_path.rs"]
mod go_path;
#[path = "symbol_graph_path_js_ts.rs"]
mod js_ts;
#[path = "symbol_graph_path_lookup.rs"]
mod lookup;
#[path = "symbol_graph_path_python.rs"]
mod python;
#[path = "symbol_graph_path_rust.rs"]
mod rust_path;

pub(super) use lookup::lookup_file;

pub(super) fn resolve_module_path(ctx: &ResolveContext<'_>, source_module: &str) -> Option<String> {
    let importing_path = Path::new(ctx.importing_file);
    let parent_dir = importing_path.parent()?;

    match ctx.language {
        "javascript" | "typescript" => {
            js_ts::resolve_js_ts_module_path(parent_dir, source_module, ctx.all_files)
        }
        "python" => python::resolve_python_module_path(
            parent_dir,
            source_module,
            ctx.project_root,
            ctx.all_files,
        ),
        "rust" => rust_path::resolve_rust_module_path(
            ctx.importing_file,
            source_module,
            ctx.project_root,
            ctx.all_files,
        ),
        "go" => go_path::resolve_go_module_path(source_module, ctx.all_files),
        _ => None,
    }
}
