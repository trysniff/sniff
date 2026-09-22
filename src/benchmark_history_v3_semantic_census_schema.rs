use super::super::{
    HistoricalV3RankIdentity, HistoricalV3SourceSide, IntentionalBoundaryIndexerKind,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticCensusFailureEvidence,
    IntentionalBoundarySemanticSymbolFacts,
};
use crate::semantic_index::SemanticIndex;
use serde::{Deserialize, Serialize};

pub const HISTORICAL_V3_SEMANTIC_CENSUS_SCHEMA_VERSION: u32 = 1;
pub const HISTORICAL_V3_SEMANTIC_CENSUS_EXCLUSION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3SemanticSurfaceSymbol {
    pub indexer: IntentionalBoundaryIndexerKind,
    pub symbol: IntentionalBoundarySemanticSymbolFacts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3CompilerIndexEvidence {
    pub indexer: IntentionalBoundaryIndexerKind,
    pub index: SemanticIndex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3SemanticSnapshot {
    pub side: HistoricalV3SourceSide,
    pub revision: String,
    pub source_snapshot_sha256: String,
    pub compiler_indexes: Vec<HistoricalV3CompilerIndexEvidence>,
    pub semantic_census: IntentionalBoundarySemanticCensus,
    pub surface_symbols: Vec<HistoricalV3SemanticSurfaceSymbol>,
    pub surface_symbol_count: usize,
    pub snapshot_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV3SemanticSnapshotEvidence {
    Completed {
        snapshot: Box<HistoricalV3SemanticSnapshot>,
    },
    Excluded {
        side: HistoricalV3SourceSide,
        revision: String,
        source_snapshot_sha256: String,
        failures: Vec<IntentionalBoundarySemanticCensusFailureEvidence>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3SemanticCensus {
    pub schema_version: u32,
    pub semantic_census_contract: String,
    pub indexer_install_contract: String,
    pub rank: HistoricalV3RankIdentity,
    pub materialization_sha256: String,
    pub source_census_sha256: String,
    pub base: HistoricalV3SemanticSnapshot,
    pub merge: HistoricalV3SemanticSnapshot,
    pub semantic_census_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3SemanticCensusExclusion {
    pub schema_version: u32,
    pub exclusion_contract: String,
    pub indexer_install_contract: String,
    pub rank: HistoricalV3RankIdentity,
    pub materialization_sha256: String,
    pub source_census_sha256: String,
    pub sides: Vec<HistoricalV3SemanticSnapshotEvidence>,
    pub exclusion_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoricalV3SemanticCensusStageRun {
    Completed {
        artifact: Box<HistoricalV3SemanticCensus>,
        resumed: bool,
    },
    Excluded {
        artifact: Box<HistoricalV3SemanticCensusExclusion>,
        resumed: bool,
    },
}
