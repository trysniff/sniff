use super::BoundaryGitEntryKind;
use serde::{Deserialize, Serialize};

pub const HISTORICAL_V2_SOURCE_CENSUS_EXCLUSION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2SourceSnapshotSide {
    Base,
    Patched,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2SourceCensusExclusionReason {
    RepositoryContainsGitlink,
    SupportedSourceIsNotRegularBlob,
    SupportedSourceIsNotUtf8,
    SupportedSourceCannotBeParsed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV2SourceCensusFailureEvidence {
    RepositoryContainsGitlink {
        side: HistoricalV2SourceSnapshotSide,
        revision: String,
        repository_path: String,
        object_id: String,
    },
    SupportedSourceIsNotRegularBlob {
        side: HistoricalV2SourceSnapshotSide,
        revision: String,
        repository_path: String,
        object_id: String,
        entry_kind: BoundaryGitEntryKind,
    },
    SupportedSourceIsNotUtf8 {
        side: HistoricalV2SourceSnapshotSide,
        revision: String,
        repository_path: String,
        object_id: String,
        byte_length: u64,
        source_sha256: String,
        language: String,
        valid_up_to: usize,
        error_length: Option<usize>,
    },
    SupportedSourceCannotBeParsed {
        side: HistoricalV2SourceSnapshotSide,
        revision: String,
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
pub struct HistoricalV2SourceCensusExclusion {
    pub schema_version: u32,
    pub exclusion_contract: String,
    pub materialization_sha256: String,
    pub reasons: Vec<HistoricalV2SourceCensusExclusionReason>,
    pub failures: Vec<HistoricalV2SourceCensusFailureEvidence>,
    pub exclusion_sha256: String,
}
