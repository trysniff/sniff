use super::super::{
    HistoricalV3SemanticSnapshot, HistoricalV3SurfaceChange, HistoricalV3SurfaceDelta,
    HistoricalV3SurfaceEntry, IntentionalBoundarySemanticSymbolFacts,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(super) fn surface_delta(
    base: &HistoricalV3SemanticSnapshot,
    merge: &HistoricalV3SemanticSnapshot,
) -> Result<HistoricalV3SurfaceDelta, String> {
    let base_entries = surface_entries(base)?;
    let merge_entries = surface_entries(merge)?;
    let base_map = entry_map(&base_entries);
    let merge_map = entry_map(&merge_entries);
    let removed = base_map
        .iter()
        .filter(|(key, _)| !merge_map.contains_key(key))
        .map(|(_, entry)| (*entry).clone())
        .collect::<Vec<_>>();
    let added = merge_map
        .iter()
        .filter(|(key, _)| !base_map.contains_key(key))
        .map(|(_, entry)| (*entry).clone())
        .collect::<Vec<_>>();
    let changed = base_map
        .iter()
        .filter_map(|(key, base)| {
            let merge = merge_map.get(key)?;
            (base.api_fingerprint_sha256 != merge.api_fingerprint_sha256).then(|| {
                HistoricalV3SurfaceChange {
                    indexer: base.indexer,
                    symbol_id: base.symbol_id.clone(),
                    base_api_fingerprint_sha256: base.api_fingerprint_sha256.clone(),
                    merge_api_fingerprint_sha256: merge.api_fingerprint_sha256.clone(),
                }
            })
        })
        .collect::<Vec<_>>();
    let preserved = removed.is_empty() && added.is_empty() && changed.is_empty();
    let mut delta = HistoricalV3SurfaceDelta {
        base: base_entries,
        merge: merge_entries,
        removed,
        added,
        changed,
        preserved,
        delta_sha256: String::new(),
    };
    delta.delta_sha256 = delta_sha256(&delta)?;
    Ok(delta)
}

fn entry_map(
    entries: &[HistoricalV3SurfaceEntry],
) -> BTreeMap<(super::super::IntentionalBoundaryIndexerKind, &str), &HistoricalV3SurfaceEntry> {
    entries
        .iter()
        .map(|entry| ((entry.indexer, entry.symbol_id.as_str()), entry))
        .collect()
}

fn surface_entries(
    snapshot: &HistoricalV3SemanticSnapshot,
) -> Result<Vec<HistoricalV3SurfaceEntry>, String> {
    snapshot
        .surface_symbols
        .iter()
        .map(|surface| {
            Ok(HistoricalV3SurfaceEntry {
                indexer: surface.indexer,
                symbol_id: surface.symbol.symbol_id.clone(),
                api_fingerprint_sha256: api_fingerprint(&surface.symbol)?,
            })
        })
        .collect()
}

fn api_fingerprint(symbol: &IntentionalBoundarySemanticSymbolFacts) -> Result<String, String> {
    json_sha256(&(
        symbol.display_name.as_deref(),
        symbol.category,
        symbol.provider_kind.as_str(),
        &symbol.signatures,
        &symbol.owner,
        symbol.visibility,
        &symbol.surfaces,
        symbol.origin,
    ))
}

fn delta_sha256(delta: &HistoricalV3SurfaceDelta) -> Result<String, String> {
    let mut committed = delta.clone();
    committed.delta_sha256.clear();
    json_sha256(&committed)
}

fn json_sha256(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v3 surface evidence: {error}"))
}
