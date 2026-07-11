use crate::config::ResolvedConfig;
use crate::report_types::StaticFlag;
use crate::scorer;
use crate::signal_layers;
use crate::types::FileRecord;
pub(super) fn build_graph(
    file_records: &[crate::types::FileRecord],
    root: &str,
) -> Result<crate::symbol_graph::SymbolGraph, String> {
    let mut graph = crate::symbol_graph::SymbolGraph::new(root);
    for f in file_records {
        let syms = crate::parser::parse_file_symbols_checked(&f.file_path)
            .map_err(|err| format!("symbol parse failed for {}: {err}", f.file_path))?;
        graph.add_file(syms);
    }
    graph.resolve_all();
    Ok(graph)
}

pub(super) fn build_static_flags(
    file_records: &mut [FileRecord],
    path: &str,
    config: &ResolvedConfig,
) -> Result<(Vec<StaticFlag>, crate::symbol_graph::SymbolGraph), String> {
    let graph = build_graph(file_records, path)?;
    crate::callgraph::build_references(file_records, &graph);
    let ref_flags = crate::callgraph::build_ref_count_flags(file_records);
    let scorer_flags = scorer::score(file_records, config);
    let mut supporting_flags =
        signal_layers::collect_supporting_flags(file_records, config, std::path::Path::new(path));
    let mut static_flags = [ref_flags, scorer_flags].concat();
    static_flags.append(&mut supporting_flags);

    Ok((static_flags, graph))
}
