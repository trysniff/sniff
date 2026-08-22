use super::{IntentionalBoundaryIndexerKind, IntentionalBoundarySemanticCensus};
use serde::{Deserialize, Serialize};

pub const INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_STAGE_SCHEMA_VERSION: u32 = 1;
pub const INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_EXCLUSION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundarySemanticCensusExclusionReason {
    UnsupportedProjectShape,
    CompilerIndexerRejectedRepository,
    CompilerCensusIncomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundarySemanticCensusFailurePhase {
    RepositoryValidation,
    InstallationVerification,
    Preparation,
    Execution,
    OutputValidation,
    Cleanup,
    IntegrityVerification,
    CensusAssembly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySemanticProcessEvidence {
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
pub struct IntentionalBoundarySemanticCensusFailureEvidence {
    pub reason: IntentionalBoundarySemanticCensusExclusionReason,
    pub indexer: Option<IntentionalBoundaryIndexerKind>,
    pub phase: IntentionalBoundarySemanticCensusFailurePhase,
    pub detail_sha256: String,
    pub retained_detail: String,
    pub detail_truncated: bool,
    pub process: Option<IntentionalBoundarySemanticProcessEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySemanticCensusStage {
    pub schema_version: u32,
    pub stage_contract: String,
    pub frame_task_sha256: String,
    pub population_rank: usize,
    pub materialization_sha256: String,
    pub inventory_sha256: String,
    pub source_census_stage_sha256: String,
    pub license_census_stage_sha256: String,
    pub semantic_census: IntentionalBoundarySemanticCensus,
    pub stage_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySemanticCensusExclusion {
    pub schema_version: u32,
    pub exclusion_contract: String,
    pub frame_task_sha256: String,
    pub population_rank: usize,
    pub repository: String,
    pub revision: String,
    pub materialization_sha256: String,
    pub inventory_sha256: String,
    pub source_census_stage_sha256: String,
    pub license_census_stage_sha256: String,
    pub reasons: Vec<IntentionalBoundarySemanticCensusExclusionReason>,
    pub failures: Vec<IntentionalBoundarySemanticCensusFailureEvidence>,
    pub exclusion_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentionalBoundarySemanticCensusStageOutcome {
    Completed(IntentionalBoundarySemanticCensusStage),
    Excluded(IntentionalBoundarySemanticCensusExclusion),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentionalBoundarySemanticCensusStageErrorKind {
    InvalidInput,
    InfrastructureUnavailable,
    InfrastructureFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentionalBoundarySemanticCensusStageError {
    pub kind: IntentionalBoundarySemanticCensusStageErrorKind,
    pub detail: String,
}
