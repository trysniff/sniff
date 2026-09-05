use super::{
    HistoricalV2PublicSurfaceChange, HistoricalV2PublicSurfaceDelta,
    HistoricalV2PublicSurfaceEntry, HistoricalV2SemanticSnapshotCensus,
    IntentionalBoundarySemanticSymbolFacts,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default)]
struct SurfaceAggregate {
    declaration_unit_ids: BTreeSet<String>,
    symbol_ids: BTreeSet<String>,
    compiler_fingerprint_sha256s: BTreeSet<String>,
}

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
    let mut aggregates = BTreeMap::new();
    for binding in semantic
        .public_bindings
        .iter()
        .filter(|binding| binding.externally_reachable)
    {
        let entry = symbols
            .get(&(binding.indexer, binding.symbol_id.as_str()))
            .ok_or_else(|| {
                "historical-v2 public binding references a missing surface symbol".to_string()
            })?;
        record_surface_binding(
            &mut aggregates,
            binding.indexer,
            &binding.surface_unit_id,
            &binding.declaration_unit_id,
            &entry.symbol.symbol_id,
            semantic_fingerprint(&entry.symbol)?,
        );
    }
    Ok(finish_surface_entries(aggregates))
}

fn semantic_fingerprint(symbol: &IntentionalBoundarySemanticSymbolFacts) -> Result<String, String> {
    if symbol.signatures.is_empty() {
        return Err(format!(
            "historical-v2 public compiler symbol {} has no compiler API signature",
            symbol.symbol_id
        ));
    }
    let signatures = symbol
        .signatures
        .iter()
        .map(|signature| (&signature.language, &signature.text))
        .collect::<Vec<_>>();
    hash_json(&(
        symbol.category,
        &symbol.provider_kind,
        signatures,
        symbol.visibility,
        &symbol.surfaces,
        symbol.origin,
    ))
}

fn record_surface_binding(
    aggregates: &mut BTreeMap<SurfaceKey, SurfaceAggregate>,
    indexer: super::IntentionalBoundaryIndexerKind,
    surface_unit_id: &str,
    declaration_unit_id: &str,
    symbol_id: &str,
    compiler_fingerprint_sha256: String,
) {
    let aggregate = aggregates
        .entry((indexer, surface_unit_id.to_string()))
        .or_default();
    aggregate
        .declaration_unit_ids
        .insert(declaration_unit_id.to_string());
    aggregate.symbol_ids.insert(symbol_id.to_string());
    aggregate
        .compiler_fingerprint_sha256s
        .insert(compiler_fingerprint_sha256);
}

fn finish_surface_entries(
    aggregates: BTreeMap<SurfaceKey, SurfaceAggregate>,
) -> Vec<HistoricalV2PublicSurfaceEntry> {
    aggregates
        .into_iter()
        .map(
            |((indexer, surface_unit_id), aggregate)| HistoricalV2PublicSurfaceEntry {
                indexer,
                surface_unit_id,
                declaration_unit_ids: aggregate.declaration_unit_ids.into_iter().collect(),
                symbol_ids: aggregate.symbol_ids.into_iter().collect(),
                compiler_fingerprint_sha256s: aggregate
                    .compiler_fingerprint_sha256s
                    .into_iter()
                    .collect(),
            },
        )
        .collect()
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
            (base.compiler_fingerprint_sha256s != patched.compiler_fingerprint_sha256s).then(|| {
                HistoricalV2PublicSurfaceChange {
                    indexer: base.indexer,
                    surface_unit_id: base.surface_unit_id.clone(),
                    base_symbol_ids: base.symbol_ids.clone(),
                    patched_symbol_ids: patched.symbol_ids.clone(),
                    base_compiler_fingerprint_sha256s: base.compiler_fingerprint_sha256s.clone(),
                    patched_compiler_fingerprint_sha256s: patched
                        .compiler_fingerprint_sha256s
                        .clone(),
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

type SurfaceKey = (super::IntentionalBoundaryIndexerKind, String);

fn entry_map(
    entries: &[HistoricalV2PublicSurfaceEntry],
) -> Result<
    BTreeMap<(super::IntentionalBoundaryIndexerKind, &str), &HistoricalV2PublicSurfaceEntry>,
    String,
> {
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
    use crate::benchmark::{
        IntentionalBoundaryIndexerKind, IntentionalBoundarySemanticOrigin,
        IntentionalBoundarySemanticSignatureFacts, IntentionalBoundarySemanticSurface,
        IntentionalBoundarySemanticSymbolCategory, IntentionalBoundarySemanticVisibility,
    };

    #[test]
    fn moved_definitions_do_not_change_the_stable_surface_entry() {
        let base = surface_entry("symbol", '1');
        let mut patched = base.clone();
        patched.declaration_unit_ids = vec!["moved-declaration".to_string()];
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

    #[test]
    fn changing_one_overload_changes_the_compiler_surface_fingerprint() {
        let base = symbol_with_signatures(&["(value: number): number", "(value: string): string"]);
        let patched =
            symbol_with_signatures(&["(value: boolean): boolean", "(value: string): string"]);

        assert_ne!(
            semantic_fingerprint(&base).expect("base fingerprint"),
            semantic_fingerprint(&patched).expect("patched fingerprint")
        );
    }

    #[test]
    fn public_surface_without_a_compiler_signature_fails_closed() {
        let mut symbol = symbol_with_signatures(&[]);
        symbol.symbol_id = "unsigned".to_string();

        let error = semantic_fingerprint(&symbol).unwrap_err();

        assert_eq!(
            error,
            "historical-v2 public compiler symbol unsigned has no compiler API signature"
        );
    }

    #[test]
    fn repeated_exposure_occurrences_form_one_public_surface() {
        let mut aggregates = BTreeMap::new();
        for declaration in ["declaration-a", "declaration-b"] {
            record_surface_binding(
                &mut aggregates,
                IntentionalBoundaryIndexerKind::TypeScriptJavaScript,
                "surface",
                declaration,
                "compiler-symbol",
                "1".repeat(64),
            );
        }

        let entries = finish_surface_entries(aggregates);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].declaration_unit_ids,
            ["declaration-a", "declaration-b"]
        );
        assert_eq!(entries[0].symbol_ids, ["compiler-symbol"]);
        assert_eq!(entries[0].compiler_fingerprint_sha256s, ["1".repeat(64)]);
    }

    fn surface_entry(symbol: &str, fingerprint: char) -> HistoricalV2PublicSurfaceEntry {
        HistoricalV2PublicSurfaceEntry {
            indexer: IntentionalBoundaryIndexerKind::Rust,
            surface_unit_id: "surface".to_string(),
            declaration_unit_ids: vec!["declaration".to_string()],
            symbol_ids: vec![symbol.to_string()],
            compiler_fingerprint_sha256s: vec![std::iter::repeat_n(fingerprint, 64).collect()],
        }
    }

    fn symbol_with_signatures(signatures: &[&str]) -> IntentionalBoundarySemanticSymbolFacts {
        IntentionalBoundarySemanticSymbolFacts {
            symbol_id: "symbol".to_string(),
            provider_identity: "compiler identity".to_string(),
            display_name: Some("parse".to_string()),
            category: IntentionalBoundarySemanticSymbolCategory::Callable,
            provider_kind: "Function".to_string(),
            documentation: Vec::new(),
            signatures: signatures
                .iter()
                .map(|text| IntentionalBoundarySemanticSignatureFacts {
                    language: "typescript".to_string(),
                    text: (*text).to_string(),
                    referenced_symbols: Vec::new(),
                })
                .collect(),
            owner: None,
            definitions: Vec::new(),
            visibility: IntentionalBoundarySemanticVisibility::Public,
            surfaces: vec![IntentionalBoundarySemanticSurface::PublicApi],
            origin: IntentionalBoundarySemanticOrigin::Repository,
            ambiguity_notes: Vec::new(),
        }
    }
}
