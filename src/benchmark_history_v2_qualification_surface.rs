use super::{
    HistoricalV2PublicSurfaceChange, HistoricalV2PublicSurfaceDelta,
    HistoricalV2PublicSurfaceEntry, HistoricalV2SemanticPublicRootOrigin,
    HistoricalV2SemanticSnapshotCensus, IntentionalBoundarySemanticSymbolFacts,
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
    for root in &semantic.public_roots {
        let (exposure_id, surface_slot_id, root_kind) = match &root.origin {
            HistoricalV2SemanticPublicRootOrigin::RustCargoLibrary => continue,
            HistoricalV2SemanticPublicRootOrigin::NodePackageExposure {
                exposure_id,
                surface_slot_id,
            } => (exposure_id, surface_slot_id, "node"),
            HistoricalV2SemanticPublicRootOrigin::PythonDistributionModule {
                module_exposure_id,
                surface_slot_id,
            } => (module_exposure_id, surface_slot_id, "python"),
        };
        let entry = symbols
            .get(&(root.indexer, root.module_symbol_id.as_str()))
            .ok_or_else(|| {
                "historical-v2 package public root references a missing surface symbol".to_string()
            })?;
        record_surface_binding(
            &mut aggregates,
            root.indexer,
            surface_slot_id,
            exposure_id,
            &entry.symbol.symbol_id,
            package_root_fingerprint(root_kind, surface_slot_id)?,
        );
    }
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

fn package_root_fingerprint(root_kind: &str, surface_slot_id: &str) -> Result<String, String> {
    hash_json(&(
        "sniffbench-historical-v2-package-root-surface-v1",
        root_kind,
        surface_slot_id,
    ))
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
    use crate::benchmark::release::HistoricalV2SemanticPublicRoot;
    use crate::benchmark::{
        HistoricalV2SemanticSymbol, IntentionalBoundaryIndexerKind,
        IntentionalBoundarySemanticOrigin, IntentionalBoundarySemanticRange,
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

    #[test]
    fn side_effect_only_node_package_root_is_a_public_surface() {
        let entries = surface_entries(&snapshot_with_node_root(
            "src/index.ts",
            "package-root",
            "exposure-a",
            "module-a",
        ))
        .expect("root surface");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].surface_unit_id, "package-root");
        assert_eq!(entries[0].declaration_unit_ids, ["exposure-a"]);
        assert_eq!(entries[0].symbol_ids, ["module-a"]);
        assert_eq!(entries[0].compiler_fingerprint_sha256s.len(), 1);
    }

    #[test]
    fn moving_a_node_package_root_preserves_its_public_slot() {
        let base = surface_entries(&snapshot_with_node_root(
            "src/index.ts",
            "package-root",
            "exposure-a",
            "module-a",
        ))
        .unwrap();
        let patched = surface_entries(&snapshot_with_node_root(
            "src/moved.ts",
            "package-root",
            "exposure-b",
            "module-b",
        ))
        .unwrap();

        let delta = diff_entries(base, patched).unwrap();
        assert!(delta.preserved);
        assert!(delta.changed.is_empty());
    }

    #[test]
    fn removing_a_side_effect_only_node_package_root_changes_the_surface() {
        let base = surface_entries(&snapshot_with_node_root(
            "src/index.ts",
            "package-root",
            "exposure-a",
            "module-a",
        ))
        .unwrap();

        let delta = diff_entries(base, Vec::new()).unwrap();
        assert!(!delta.preserved);
        assert_eq!(delta.removed.len(), 1);

        let added = diff_entries(
            Vec::new(),
            surface_entries(&snapshot_with_node_root(
                "src/index.ts",
                "package-root",
                "exposure-a",
                "module-a",
            ))
            .unwrap(),
        )
        .unwrap();
        assert!(!added.preserved);
        assert_eq!(added.added.len(), 1);
    }

    #[test]
    fn empty_python_package_root_is_a_stable_public_surface() {
        let base = surface_entries(&snapshot_with_python_root(
            "pkg/__init__.py",
            "python-package-root",
            "module-exposure-a",
            "python-module-a",
        ))
        .unwrap();
        let patched = surface_entries(&snapshot_with_python_root(
            "src/pkg/__init__.py",
            "python-package-root",
            "module-exposure-b",
            "python-module-b",
        ))
        .unwrap();

        assert_eq!(base.len(), 1);
        assert_eq!(base[0].surface_unit_id, "python-package-root");
        let delta = diff_entries(base, patched).unwrap();
        assert!(delta.preserved);
        assert!(delta.changed.is_empty());
    }

    #[test]
    fn adding_or_removing_a_python_package_root_changes_the_surface() {
        let root = surface_entries(&snapshot_with_python_root(
            "pkg/__init__.py",
            "python-package-root",
            "module-exposure-a",
            "python-module-a",
        ))
        .unwrap();

        assert!(!diff_entries(root.clone(), Vec::new()).unwrap().preserved);
        assert!(!diff_entries(Vec::new(), root).unwrap().preserved);
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

    fn snapshot_with_node_root(
        repository_path: &str,
        surface_slot_id: &str,
        exposure_id: &str,
        symbol_id: &str,
    ) -> HistoricalV2SemanticSnapshotCensus {
        snapshot_with_package_root(
            repository_path,
            symbol_id,
            IntentionalBoundaryIndexerKind::TypeScriptJavaScript,
            HistoricalV2SemanticPublicRootOrigin::NodePackageExposure {
                exposure_id: exposure_id.to_string(),
                surface_slot_id: surface_slot_id.to_string(),
            },
        )
    }

    fn snapshot_with_python_root(
        repository_path: &str,
        surface_slot_id: &str,
        module_exposure_id: &str,
        symbol_id: &str,
    ) -> HistoricalV2SemanticSnapshotCensus {
        snapshot_with_package_root(
            repository_path,
            symbol_id,
            IntentionalBoundaryIndexerKind::Python,
            HistoricalV2SemanticPublicRootOrigin::PythonDistributionModule {
                module_exposure_id: module_exposure_id.to_string(),
                surface_slot_id: surface_slot_id.to_string(),
            },
        )
    }

    fn snapshot_with_package_root(
        repository_path: &str,
        symbol_id: &str,
        indexer: IntentionalBoundaryIndexerKind,
        origin: HistoricalV2SemanticPublicRootOrigin,
    ) -> HistoricalV2SemanticSnapshotCensus {
        let compiler_definition = IntentionalBoundarySemanticRange {
            repository_path: repository_path.to_string(),
            start_line_zero_based: 0,
            start_character_zero_based: 0,
            end_line_zero_based: 0,
            end_character_zero_based: 0,
        };
        let mut symbol = symbol_with_signatures(&[]);
        symbol.symbol_id = symbol_id.to_string();
        symbol.category = IntentionalBoundarySemanticSymbolCategory::Module;
        symbol.definitions = vec![compiler_definition.clone()];
        HistoricalV2SemanticSnapshotCensus {
            revision: "1".repeat(40),
            source_snapshot_census_sha256: "2".repeat(64),
            required_document_paths: vec![repository_path.to_string()],
            public_surface_document_paths: vec![repository_path.to_string()],
            indexers: Vec::new(),
            methods: Vec::new(),
            public_bindings: Vec::new(),
            public_roots: vec![HistoricalV2SemanticPublicRoot {
                indexer,
                repository_path: repository_path.to_string(),
                module_symbol_id: symbol_id.to_string(),
                compiler_definition,
                origin,
            }],
            public_reexport_hops: Vec::new(),
            symbols: vec![HistoricalV2SemanticSymbol {
                indexer,
                is_public_surface: false,
                is_public_root_evidence: true,
                is_reexport_evidence: false,
                symbol,
            }],
            symbol_count: 1,
            public_binding_count: 0,
            public_root_count: 1,
            public_reexport_hop_count: 0,
            public_symbol_count: 0,
            resolved_method_count: 0,
            compiler_excluded_method_count: 0,
            unresolved_method_count: 0,
            semantic_snapshot_sha256: "3".repeat(64),
        }
    }
}
