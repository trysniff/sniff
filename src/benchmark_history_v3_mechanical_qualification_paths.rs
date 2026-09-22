use super::super::{
    HistoricalV3MechanicalPolicy, HistoricalV3PathChangeKind, HistoricalV3QualifiedPath,
    HistoricalV3SemanticSnapshot, HistoricalV3SourceFileFacts, HistoricalV3SourceSnapshot,
};
use super::roles::file_role_evidence;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn changed_paths(
    policy: &HistoricalV3MechanicalPolicy,
    base: &HistoricalV3SourceSnapshot,
    merge: &HistoricalV3SourceSnapshot,
    base_semantic: &HistoricalV3SemanticSnapshot,
    merge_semantic: &HistoricalV3SemanticSnapshot,
) -> Result<Vec<HistoricalV3QualifiedPath>, String> {
    let base_inventory = base
        .inventory
        .tracked_entries
        .iter()
        .map(|entry| (entry.repository_path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let merge_inventory = merge
        .inventory
        .tracked_entries
        .iter()
        .map(|entry| (entry.repository_path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let paths = base_inventory
        .keys()
        .chain(merge_inventory.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    let base_sources = source_maps(base)?;
    let merge_sources = source_maps(merge)?;
    let mut changed = Vec::new();
    for path in paths {
        let base_entry = base_inventory.get(path).copied();
        let merge_entry = merge_inventory.get(path).copied();
        if base_entry == merge_entry {
            continue;
        }
        let change = match (base_entry, merge_entry) {
            (None, Some(_)) => HistoricalV3PathChangeKind::Added,
            (Some(_), None) => HistoricalV3PathChangeKind::Deleted,
            (Some(_), Some(_)) => HistoricalV3PathChangeKind::Modified,
            (None, None) => unreachable!(),
        };
        let base_source = base_sources.get(path).copied();
        let merge_source = merge_sources.get(path).copied();
        changed.push(HistoricalV3QualifiedPath {
            path: path.to_string(),
            change,
            base_object_id: base_entry.map(|entry| entry.object_id.clone()),
            merge_object_id: merge_entry.map(|entry| entry.object_id.clone()),
            base_source_sha256: base_source.map(|source| source.source_sha256.clone()),
            merge_source_sha256: merge_source.map(|source| source.source_sha256.clone()),
            base_syntax_sha256: base_source.map(|source| source.syntax_sha256.clone()),
            merge_syntax_sha256: merge_source.map(|source| source.syntax_sha256.clone()),
            base_non_whitespace_lines: base_source
                .map_or(0, |source| source.non_whitespace_line_count),
            merge_non_whitespace_lines: merge_source
                .map_or(0, |source| source.non_whitespace_line_count),
            base_roles: base_entry
                .map(|_| file_role_evidence(path, policy, Some(base_semantic)))
                .unwrap_or_default(),
            merge_roles: merge_entry
                .map(|_| file_role_evidence(path, policy, Some(merge_semantic)))
                .unwrap_or_default(),
        });
    }
    Ok(changed)
}

fn source_maps(
    snapshot: &HistoricalV3SourceSnapshot,
) -> Result<BTreeMap<&str, &HistoricalV3SourceFileFacts>, String> {
    let map = snapshot
        .source_file_facts
        .iter()
        .map(|facts| (facts.repository_path.as_str(), facts))
        .collect::<BTreeMap<_, _>>();
    if map.len() != snapshot.source_file_facts.len() {
        return Err("historical-v3 source facts repeat a path".to_string());
    }
    Ok(map)
}
