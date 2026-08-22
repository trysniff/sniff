use super::{BoundaryGitEntryKind, IntentionalBoundarySourceCensus};
use serde::{Deserialize, Serialize};

pub const INTENTIONAL_BOUNDARY_SOURCE_CENSUS_STAGE_SCHEMA_VERSION: u32 = 1;
pub const INTENTIONAL_BOUNDARY_SOURCE_CENSUS_EXCLUSION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundarySourceCensusExclusionReason {
    NoSupportedSources,
    UnsupportedProjectShape,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IntentionalBoundarySourceCensusFailureEvidence {
    RepositoryContainsGitlink {
        repository_path: String,
        object_id: String,
    },
    SupportedSourceIsNotRegularBlob {
        repository_path: String,
        object_id: String,
        entry_kind: BoundaryGitEntryKind,
    },
    SupportedSourceIsNotUtf8 {
        repository_path: String,
        object_id: String,
        byte_length: u64,
        source_sha256: String,
        language: String,
        valid_up_to: usize,
        error_length: Option<usize>,
    },
    SupportedSourceCannotBeParsed {
        repository_path: String,
        object_id: String,
        byte_length: u64,
        source_sha256: String,
        language: String,
        parser_error_sha256: String,
        retained_parser_error: String,
        parser_error_truncated: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySourceCensusStage {
    pub schema_version: u32,
    pub stage_contract: String,
    pub frame_task_sha256: String,
    pub population_rank: usize,
    pub materialization_sha256: String,
    pub inventory_sha256: String,
    pub source_extension_contract: String,
    pub source_census: IntentionalBoundarySourceCensus,
    pub stage_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySourceCensusExclusion {
    pub schema_version: u32,
    pub exclusion_contract: String,
    pub frame_task_sha256: String,
    pub population_rank: usize,
    pub repository: String,
    pub revision: String,
    pub materialization_sha256: String,
    pub inventory_sha256: String,
    pub source_extension_contract: String,
    pub reason: IntentionalBoundarySourceCensusExclusionReason,
    pub tracked_entry_count: usize,
    pub failures: Vec<IntentionalBoundarySourceCensusFailureEvidence>,
    pub exclusion_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentionalBoundarySourceCensusStageOutcome {
    Completed(IntentionalBoundarySourceCensusStage),
    Excluded(IntentionalBoundarySourceCensusExclusion),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentionalBoundarySourceCensusStageErrorKind {
    InvalidInput,
    InfrastructureUnavailable,
    InfrastructureFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentionalBoundarySourceCensusStageError {
    pub kind: IntentionalBoundarySourceCensusStageErrorKind,
    pub detail: String,
}
