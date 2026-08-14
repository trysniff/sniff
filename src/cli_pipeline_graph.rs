use crate::config::ResolvedConfig;
use crate::report_types::StaticFlag;
use crate::scorer;
use crate::signal_layers;
use crate::types::FileRecord;
pub(super) fn build_graph(
    file_records: &[crate::types::FileRecord],
    root: &str,
    semantic_cache: Option<&crate::semantic_cache::SemanticIndexCache>,
) -> Result<crate::symbol_graph::SymbolGraph, String> {
    let mut graph = crate::symbol_graph::SymbolGraph::new(root);
    for f in file_records {
        let syms = if let Some(cache) = semantic_cache {
            cache.load_or_build(f)?.0
        } else {
            crate::parser::parse_file_symbols_checked(&f.file_path)
                .map_err(|err| format!("symbol parse failed for {}: {err}", f.file_path))?
        };
        graph.add_file(syms);
    }
    graph.resolve_all();
    Ok(graph)
}

pub(super) fn build_static_flags(
    file_records: &mut [FileRecord],
    evidence_records: &[FileRecord],
    path: &str,
    config: &ResolvedConfig,
    semantic_cache: Option<&crate::semantic_cache::SemanticIndexCache>,
) -> Result<(Vec<StaticFlag>, crate::symbol_graph::SymbolGraph), String> {
    let mut context_records = file_records.to_vec();
    context_records.extend_from_slice(evidence_records);
    let graph = build_graph(&context_records, path, semantic_cache)?;
    crate::callgraph::build_references_with_context(file_records, &context_records, &graph);
    let ref_flags = crate::callgraph::build_ref_count_flags(file_records);
    let scorer_flags = scorer::score(file_records, config);
    let mut supporting_flags =
        signal_layers::collect_supporting_flags(file_records, config, std::path::Path::new(path));
    let mut static_flags = [ref_flags, scorer_flags].concat();
    static_flags.append(&mut supporting_flags);

    Ok((static_flags, graph))
}

#[cfg(test)]
mod tests {
    use super::build_graph;
    use crate::semantic_cache::SemanticIndexCache;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn json_artifacts(root: &Path) -> Vec<PathBuf> {
        let mut artifacts = Vec::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(path) = pending.pop() {
            let Ok(entries) = std::fs::read_dir(path) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
                    artifacts.push(path);
                }
            }
        }
        artifacts
    }

    #[test]
    fn graph_pipeline_persists_and_reuses_semantic_artifacts() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("sniff-graph-cache-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(root.join("src")).unwrap();
        let source_path = root.join("src/main.rs");
        std::fs::write(&source_path, "pub fn cached_graph_method() {}\n").unwrap();
        let record = crate::parser::parse_file_checked(source_path.to_str().unwrap()).unwrap();
        let cache_root = root.join("cache");
        let cache = SemanticIndexCache::at(cache_root.clone());

        let first = build_graph(
            std::slice::from_ref(&record),
            root.to_str().unwrap(),
            Some(&cache),
        )
        .unwrap();
        let second = build_graph(&[record], root.to_str().unwrap(), Some(&cache)).unwrap();

        assert_eq!(first.files.len(), 1);
        assert_eq!(second.files.len(), 1);
        assert_eq!(json_artifacts(&cache_root).len(), 1);
        std::fs::remove_dir_all(root).ok();
    }
}
