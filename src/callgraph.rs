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

pub use flags::build_ref_count_flags;
