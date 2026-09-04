use super::{
    HistoricalV2PublicSurfaceChange, HistoricalV2PublicSurfaceDelta,
    HistoricalV2PublicSurfaceEntry, HistoricalV2SemanticSnapshotCensus,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(super) fn public_surface_delta(
    base: &HistoricalV2SemanticSnapshotCensus,
    patched: &HistoricalV2SemanticSnapshotCensus,
) -> Result<HistoricalV2PublicSurfaceDelta, String> {
    let base_entries = surface_entries(base)?;
    let patched_entries = surface_entries(patched)?;
    diff_entries(base_entries, patched_entries)
}

fn surface_entries(
    semantic: &HistoricalV2SemanticSnapshotCensus,
) -> Result<Vec<HistoricalV2PublicSurfaceEntry>, String> {
    let symbols = semantic
        .symbols
        .iter()
        .map(|entry| ((entry.indexer, entry.symbol.symbol_id.as_str()), entry))
        .collect::<BTreeMap<_, _>>();
    let mut entries = semantic
        .public_bindings
        .iter()
        .map(|binding| {
            let entry = symbols
                .get(&(binding.indexer, binding.symbol_id.as_str()))
                .ok_or_else(|| {
                    "historical-v2 public binding references a missing surface symbol".to_string()
                })?;
            let symbol = &entry.symbol;
            let semantic_fingerprint_sha256 = hash_json(&(
                &symbol.provider_identity,
                &symbol.display_name,
                symbol.category,
                &symbol.provider_kind,
                &symbol.signature,
                &symbol.signature_referenced_symbols,
                &symbol.owner,
                symbol.visibility,
                &symbol.surfaces,
                symbol.origin,
            ))?;
            Ok(HistoricalV2PublicSurfaceEntry {
                indexer: binding.indexer,
                surface_unit_id: binding.surface_unit_id.clone(),
                declaration_unit_id: binding.declaration_unit_id.clone(),
                symbol_id: symbol.symbol_id.clone(),
                semantic_fingerprint_sha256,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    entries.sort();
    if entries.windows(2).any(|pair| {
        pair[0].indexer == pair[1].indexer && pair[0].surface_unit_id == pair[1].surface_unit_id
    }) {
        return Err("historical-v2 public surface repeats a symbol".to_string());
    }
    Ok(entries)
}

fn diff_entries(
    base_entries: Vec<HistoricalV2PublicSurfaceEntry>,
    patched_entries: Vec<HistoricalV2PublicSurfaceEntry>,
) -> Result<HistoricalV2PublicSurfaceDelta, String> {
    let base = entry_map(&base_entries)?;
    let patched = entry_map(&patched_entries)?;
    let removed = base
        .iter()
        .filter(|(key, _)| !patched.contains_key(key))
        .map(|(_, entry)| (*entry).clone())
        .collect::<Vec<_>>();
    let added = patched
        .iter()
        .filter(|(key, _)| !base.contains_key(key))
        .map(|(_, entry)| (*entry).clone())
        .collect::<Vec<_>>();
    let changed = base
        .iter()
        .filter_map(|(key, base)| {
            let patched = patched.get(key)?;
            (base.semantic_fingerprint_sha256 != patched.semantic_fingerprint_sha256).then(|| {
                HistoricalV2PublicSurfaceChange {
                    indexer: base.indexer,
                    surface_unit_id: base.surface_unit_id.clone(),
                    base_symbol_id: base.symbol_id.clone(),
                    patched_symbol_id: patched.symbol_id.clone(),
                    base_fingerprint_sha256: base.semantic_fingerprint_sha256.clone(),
                    patched_fingerprint_sha256: patched.semantic_fingerprint_sha256.clone(),
                }
            })
        })
        .collect::<Vec<_>>();
    let preserved = removed.is_empty() && added.is_empty() && changed.is_empty();
    let mut delta = HistoricalV2PublicSurfaceDelta {
        base_entries,
        patched_entries,
        removed,
        added,
        changed,
        preserved,
        delta_sha256: String::new(),
    };
    delta.delta_sha256 = delta_sha256(&delta)?;
    Ok(delta)
}

type SurfaceKey<'a> = (super::IntentionalBoundaryIndexerKind, &'a str);

fn entry_map(
    entries: &[HistoricalV2PublicSurfaceEntry],
) -> Result<BTreeMap<SurfaceKey<'_>, &HistoricalV2PublicSurfaceEntry>, String> {
    let mut map = BTreeMap::new();
    for entry in entries {
        if map
            .insert((entry.indexer, entry.surface_unit_id.as_str()), entry)
            .is_some()
        {
            return Err("historical-v2 public surface repeats a symbol".to_string());
        }
    }
    Ok(map)
}

fn delta_sha256(delta: &HistoricalV2PublicSurfaceDelta) -> Result<String, String> {
    let mut committed = delta.clone();
    committed.delta_sha256.clear();
    hash_json(&committed)
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v2 public surface: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::benchmark::IntentionalBoundaryIndexerKind;

    #[test]
    fn moved_definitions_do_not_change_the_stable_surface_entry() {
        let base = surface_entry("symbol", '1');
        let mut patched = base.clone();
        patched.declaration_unit_id = "moved-declaration".to_string();
        let delta = diff_entries(vec![base], vec![patched]).expect("surface delta");
        assert!(delta.preserved);
        assert!(delta.changed.is_empty());
    }

    #[test]
    fn changed_signature_fingerprint_breaks_preservation() {
        let delta = diff_entries(
            vec![surface_entry("symbol", '1')],
            vec![surface_entry("symbol", '2')],
        )
        .expect("surface delta");
        assert!(!delta.preserved);
        assert_eq!(delta.changed.len(), 1);
    }

    fn surface_entry(symbol: &str, fingerprint: char) -> HistoricalV2PublicSurfaceEntry {
        HistoricalV2PublicSurfaceEntry {
            indexer: IntentionalBoundaryIndexerKind::Rust,
            surface_unit_id: "surface".to_string(),
            declaration_unit_id: "declaration".to_string(),
            symbol_id: symbol.to_string(),
            semantic_fingerprint_sha256: std::iter::repeat_n(fingerprint, 64).collect(),
        }
    }
}
