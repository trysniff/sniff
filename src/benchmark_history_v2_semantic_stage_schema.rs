use super::IntentionalBoundaryIndexerKind;
use serde::{Deserialize, Serialize};

pub const HISTORICAL_V2_SEMANTIC_CENSUS_EXCLUSION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2SemanticCensusExclusionReason {
    UnsupportedProjectShape,
    CompilerIndexerRejectedRepository,
    CompilerCensusIncomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2SemanticSnapshotSide {
    Base,
    Patched,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2SemanticCensusFailurePhase {
    RepositoryValidation,
    InstallationVerification,
    Preparation,
    Execution,
    OutputValidation,
    Cleanup,
    IntegrityVerification,
    SnapshotAssembly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SemanticProcessEvidence {
    pub status_code: Option<i32>,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub retained_stdout: String,
    pub retained_stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SemanticCensusFailureEvidence {
    pub side: HistoricalV2SemanticSnapshotSide,
    pub revision: String,
    pub reason: HistoricalV2SemanticCensusExclusionReason,
    pub indexer: Option<IntentionalBoundaryIndexerKind>,
    pub phase: HistoricalV2SemanticCensusFailurePhase,
    pub detail_sha256: String,
    pub retained_detail: String,
    pub detail_truncated: bool,
    pub process: Option<HistoricalV2SemanticProcessEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SemanticCensusExclusion {
    pub schema_version: u32,
    pub exclusion_contract: String,
    pub materialization_sha256: String,
    pub source_census_sha256: String,
    pub reasons: Vec<HistoricalV2SemanticCensusExclusionReason>,
    pub failures: Vec<HistoricalV2SemanticCensusFailureEvidence>,
    pub exclusion_sha256: String,
}
