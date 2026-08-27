use super::{
    IntentionalBoundaryIndexerKind, IntentionalBoundarySemanticIndexerCensus,
    IntentionalBoundarySemanticMethod, IntentionalBoundarySemanticSymbolFacts,
};
use serde::{Deserialize, Serialize};

pub const HISTORICAL_V2_SEMANTIC_CENSUS_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2PublicSymbol {
    pub indexer: IntentionalBoundaryIndexerKind,
    pub symbol: IntentionalBoundarySemanticSymbolFacts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SemanticSnapshotCensus {
    pub revision: String,
    pub source_snapshot_census_sha256: String,
    pub required_document_paths: Vec<String>,
    pub indexers: Vec<IntentionalBoundarySemanticIndexerCensus>,
    pub methods: Vec<IntentionalBoundarySemanticMethod>,
    pub public_symbols: Vec<HistoricalV2PublicSymbol>,
    pub public_symbol_count: usize,
    pub resolved_method_count: usize,
    pub compiler_excluded_method_count: usize,
    pub unresolved_method_count: usize,
    pub semantic_snapshot_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SemanticCensus {
    pub schema_version: u32,
    pub semantic_census_contract: String,
    pub canonical_repository: String,
    pub materialization_sha256: String,
    pub source_census_sha256: String,
    pub changed_indexers: Vec<IntentionalBoundaryIndexerKind>,
    pub base: HistoricalV2SemanticSnapshotCensus,
    pub patched: HistoricalV2SemanticSnapshotCensus,
    pub semantic_census_sha256: String,
}
