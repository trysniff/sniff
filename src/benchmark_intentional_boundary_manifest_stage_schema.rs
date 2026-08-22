use super::{
    IntentionalBoundaryManifestBindingCensus, IntentionalBoundaryManifestCensus,
    IntentionalBoundaryManifestProvider,
};
use serde::{Deserialize, Serialize};

pub const INTENTIONAL_BOUNDARY_MANIFEST_STAGE_SCHEMA_VERSION: u32 = 1;
pub const INTENTIONAL_BOUNDARY_MANIFEST_EXCLUSION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryManifestExclusionReason {
    ManifestShapeRejected,
    ManifestEncodingRejected,
    ManifestParserRejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryManifestFailureEvidence {
    pub reason: IntentionalBoundaryManifestExclusionReason,
    pub provider: IntentionalBoundaryManifestProvider,
    pub repository_path: String,
    pub detail_sha256: String,
    pub retained_detail: String,
    pub detail_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryManifestStage {
    pub schema_version: u32,
    pub stage_contract: String,
    pub frame_task_sha256: String,
    pub population_rank: usize,
    pub materialization_sha256: String,
    pub inventory_sha256: String,
    pub source_census_stage_sha256: String,
    pub license_census_stage_sha256: String,
    pub semantic_census_stage_sha256: String,
    pub ast_census_stage_sha256: String,
    pub manifest_census: IntentionalBoundaryManifestCensus,
    pub binding_census: IntentionalBoundaryManifestBindingCensus,
    pub stage_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryManifestExclusion {
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
    pub ast_census_stage_sha256: String,
    pub reasons: Vec<IntentionalBoundaryManifestExclusionReason>,
    pub failures: Vec<IntentionalBoundaryManifestFailureEvidence>,
    pub exclusion_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentionalBoundaryManifestStageOutcome {
    Completed(Box<IntentionalBoundaryManifestStage>),
    Excluded(Box<IntentionalBoundaryManifestExclusion>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentionalBoundaryManifestStageErrorKind {
    InvalidInput,
    InfrastructureUnavailable,
    InfrastructureFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentionalBoundaryManifestStageError {
    pub kind: IntentionalBoundaryManifestStageErrorKind,
    pub detail: String,
}
