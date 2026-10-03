use super::{
    BlindPriorRepositoryWitness, HistoricalV3PriorV2PrWitness, SmallPriorRepositoryWitness,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "evidence",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum HistoricalV3PriorTemporalWitness {
    SelectedPr(HistoricalV3PriorV2PrWitness),
    BlindRepository(BlindPriorRepositoryWitness),
    ResearchOrSyntheticRepository(SmallPriorRepositoryWitness),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV3PriorTemporalObligationStatus {
    SourceReplayed {
        source_proof_sha256: String,
        witness: HistoricalV3PriorTemporalWitness,
    },
    UnresolvedOriginalEntity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3PriorTemporalObligation {
    pub partition: String,
    pub source_artifact_sha256: String,
    /// Position in the canonical sealed partition, not a source slot or dataset row.
    /// Original source coordinates remain in the structured witness.
    pub seal_entry_index: usize,
    pub prior_name: String,
    pub evidence: HistoricalV3PriorTemporalObligationStatus,
}

/// Source-replayed coverage only; it is never an aggregate admission credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3PriorTemporalCoverage {
    pub schema_version: u32,
    pub contract: String,
    pub prior_seal_sha256: String,
    pub cutoff_utc: String,
    pub obligations: Vec<HistoricalV3PriorTemporalObligation>,
    pub source_replayed_obligation_count: usize,
    pub unresolved_obligation_count: usize,
    pub fully_witnessed_repository_count: usize,
    pub unresolved_repository_count: usize,
    pub publication_qualified: bool,
    pub coverage_sha256: String,
}
