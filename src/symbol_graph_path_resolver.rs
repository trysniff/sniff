#[path = "symbol_graph_path_core.rs"]
mod core;
#[path = "symbol_graph_path_direct.rs"]
mod direct;
#[path = "symbol_graph_path_dispatch.rs"]
mod dispatch;
#[path = "symbol_graph_path_exports.rs"]
mod exports;
#[path = "symbol_graph_path_reference.rs"]
mod reference;

use super::ResolveContext;

pub use core::normalize_path;
pub(crate) use direct::resolve_direct_symbol;
pub(crate) use exports::{resolve_default_export, resolve_symbol_key, same_path};
pub(crate) use reference::resolve_qualified_reference;

pub(super) fn resolve_module_path(ctx: &ResolveContext<'_>, source_module: &str) -> Option<String> {
    dispatch::resolve_module_path(ctx, source_module)
}
