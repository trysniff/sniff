use super::super::IntentionalBoundarySemanticSurface;
use super::super::intentional_boundary_semantic::{flatten_symbol, indexer_kind};
use super::{HistoricalV3CompilerIndexEvidence, HistoricalV3SemanticSurfaceSymbol};
use crate::semantic_index::{SemanticIndex, SemanticSymbolOrigin, SemanticVisibility};
use crate::semantic_indexer_manifest::SemanticIndexerKind;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub(super) fn canonicalize_indexes(
    root: &Path,
    indexes: &BTreeMap<SemanticIndexerKind, SemanticIndex>,
) -> BTreeMap<SemanticIndexerKind, SemanticIndex> {
    let native_root = root.to_string_lossy();
    let slash_root = native_root.replace('\\', "/");
    indexes
        .iter()
        .map(|(kind, index)| {
            let mut index = index.clone();
            index.repository_root = ".".to_string();
            index.provenance.arguments.clear();
            for invocation in &mut index.provenance.invocations {
                invocation.arguments.clear();
                invocation.context.clear();
            }
            for diagnostic in &mut index.provenance.diagnostics {
                *diagnostic = diagnostic
                    .replace(native_root.as_ref(), "<repository-root>")
                    .replace(&slash_root, "<repository-root>");
            }
            (*kind, index)
        })
        .collect()
}

pub(super) fn index_evidence(
    indexes: &BTreeMap<SemanticIndexerKind, SemanticIndex>,
) -> Vec<HistoricalV3CompilerIndexEvidence> {
    indexes
        .iter()
        .map(|(kind, index)| HistoricalV3CompilerIndexEvidence {
            indexer: indexer_kind(*kind),
            index: index.clone(),
        })
        .collect()
}

pub(super) fn evidence_indexes(
    evidence: &[HistoricalV3CompilerIndexEvidence],
) -> Result<BTreeMap<SemanticIndexerKind, SemanticIndex>, String> {
    Ok(evidence
        .iter()
        .map(|evidence| {
            (
                semantic_indexer_kind(evidence.indexer),
                evidence.index.clone(),
            )
        })
        .collect())
}

pub(super) fn semantic_indexer_kind(
    kind: super::super::IntentionalBoundaryIndexerKind,
) -> SemanticIndexerKind {
    match kind {
        super::super::IntentionalBoundaryIndexerKind::TypeScriptJavaScript => {
            SemanticIndexerKind::TypeScriptJavaScript
        }
        super::super::IntentionalBoundaryIndexerKind::Python => SemanticIndexerKind::Python,
        super::super::IntentionalBoundaryIndexerKind::Go => SemanticIndexerKind::Go,
        super::super::IntentionalBoundaryIndexerKind::Kotlin => SemanticIndexerKind::Kotlin,
        super::super::IntentionalBoundaryIndexerKind::Rust => SemanticIndexerKind::Rust,
    }
}

pub(super) fn collect_surface_symbols(
    indexes: &BTreeMap<SemanticIndexerKind, SemanticIndex>,
) -> Result<Vec<HistoricalV3SemanticSurfaceSymbol>, String> {
    let mut symbols = Vec::new();
    let mut identities = BTreeSet::new();
    for (kind, index) in indexes {
        for (identity, symbol) in &index.symbols {
            if &symbol.id != identity {
                return Err("historical-v3 compiler symbol map identity changed".to_string());
            }
            if symbol.origin != SemanticSymbolOrigin::Repository
                || (symbol.visibility != SemanticVisibility::Public && symbol.surfaces.is_empty())
            {
                continue;
            }
            let symbol = flatten_symbol(symbol);
            let key = (indexer_kind(*kind), symbol.symbol_id.clone());
            if !identities.insert(key) {
                return Err("historical-v3 compiler surface repeats a symbol".to_string());
            }
            symbols.push(HistoricalV3SemanticSurfaceSymbol {
                indexer: indexer_kind(*kind),
                symbol,
            });
        }
    }
    symbols.sort_by(|left, right| {
        (left.indexer, left.symbol.symbol_id.as_str())
            .cmp(&(right.indexer, right.symbol.symbol_id.as_str()))
    });
    Ok(symbols)
}

pub(super) fn is_surface_symbol(symbol: &HistoricalV3SemanticSurfaceSymbol) -> bool {
    symbol.symbol.origin == super::super::IntentionalBoundarySemanticOrigin::Repository
        && (symbol.symbol.visibility == super::super::IntentionalBoundarySemanticVisibility::Public
            || !symbol.symbol.surfaces.is_empty())
        && symbol.symbol.surfaces.iter().all(|surface| {
            matches!(
                surface,
                IntentionalBoundarySemanticSurface::PublicApi
                    | IntentionalBoundarySemanticSurface::Entrypoint
                    | IntentionalBoundarySemanticSurface::Route
                    | IntentionalBoundarySemanticSurface::Command
                    | IntentionalBoundarySemanticSurface::Job
                    | IntentionalBoundarySemanticSurface::Callback
                    | IntentionalBoundarySemanticSurface::Plugin
                    | IntentionalBoundarySemanticSurface::FrameworkRegistration
                    | IntentionalBoundarySemanticSurface::Configuration
                    | IntentionalBoundarySemanticSurface::Schema
            )
        })
}
