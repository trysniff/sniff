use super::IntentionalBoundaryAstCensus;
use serde::{Deserialize, Serialize};

pub const INTENTIONAL_BOUNDARY_AST_CENSUS_STAGE_SCHEMA_VERSION: u32 = 1;
pub const INTENTIONAL_BOUNDARY_AST_CENSUS_EXCLUSION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryAstCensusExclusionReason {
    SourceParserRejected,
    CensusIncomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryAstCensusFailureEvidence {
    pub reason: IntentionalBoundaryAstCensusExclusionReason,
    pub language: String,
    pub repository_path: Option<String>,
    pub detail_sha256: String,
    pub retained_detail: String,
    pub detail_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryAstCensusStage {
    pub schema_version: u32,
    pub stage_contract: String,
    pub frame_task_sha256: String,
    pub population_rank: usize,
    pub materialization_sha256: String,
    pub inventory_sha256: String,
    pub source_census_stage_sha256: String,
    pub license_census_stage_sha256: String,
    pub semantic_census_stage_sha256: String,
    pub languages: Vec<String>,
    pub ast_censuses: Vec<IntentionalBoundaryAstCensus>,
    pub stage_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryAstCensusExclusion {
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
    pub semantic_census_stage_sha256: String,
    pub reasons: Vec<IntentionalBoundaryAstCensusExclusionReason>,
    pub failures: Vec<IntentionalBoundaryAstCensusFailureEvidence>,
    pub exclusion_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentionalBoundaryAstCensusStageOutcome {
    Completed(IntentionalBoundaryAstCensusStage),
    Excluded(IntentionalBoundaryAstCensusExclusion),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentionalBoundaryAstCensusStageErrorKind {
    InvalidInput,
    InfrastructureUnavailable,
    InfrastructureFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentionalBoundaryAstCensusStageError {
    pub kind: IntentionalBoundaryAstCensusStageErrorKind,
    pub detail: String,
}
