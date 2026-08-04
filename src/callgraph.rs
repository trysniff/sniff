#[path = "ref_count_flags.rs"]
mod flags;
#[path = "callgraph_refs.rs"]
mod refs;

pub fn build_references(
    file_records: &mut [crate::types::FileRecord],
    graph: &crate::symbol_graph::SymbolGraph,
) {
    refs::build_references(file_records, graph);
}

pub fn build_references_with_context(
    file_records: &mut [crate::types::FileRecord],
    context_records: &[crate::types::FileRecord],
    graph: &crate::symbol_graph::SymbolGraph,
) {
    refs::build_references_with_context(file_records, context_records, graph);
}

pub fn build_callee_context(
    file_records: &[crate::types::FileRecord],
    graph: &crate::symbol_graph::SymbolGraph,
) -> std::collections::HashMap<(String, String, usize), Vec<crate::types::Reference>> {
    refs::build_callee_context(file_records, graph)
}

pub use flags::build_ref_count_flags;
