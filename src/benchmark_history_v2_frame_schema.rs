use serde::{Deserialize, Serialize};

pub const HISTORICAL_V2_FRAME_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2ProjectedRow {
    pub source_shard_index: usize,
    pub source_row_index: usize,
    pub global_row_index: usize,
    pub base_commit: String,
    pub created_at: String,
    pub instance_id: String,
    pub license: String,
    pub patch: String,
    pub pull_number: i64,
    pub repo: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2PatchFacts {
    pub language: String,
    pub changed_paths: Vec<String>,
    pub added_non_whitespace_lines: usize,
    pub deleted_non_whitespace_lines: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2FrameExclusionReason {
    EmptyInstanceId,
    InvalidRepository,
    InvalidBaseRevision,
    InvalidPullNumber,
    EmptyCreatedAt,
    EmptyLicense,
    MalformedPatch,
    NoSupportedLanguage,
    MultipleSupportedLanguages,
    NoSupportedLanguageHunks,
    NoNetSupportedLanguageReduction,
    DuplicatePullRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV2FrameDisposition {
    Eligible {
        facts: HistoricalV2PatchFacts,
        rank_sha256: String,
    },
    Excluded {
        reason: HistoricalV2FrameExclusionReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2FrameRecord {
    pub source_shard_index: usize,
    pub source_row_index: usize,
    pub global_row_index: usize,
    pub instance_id: String,
    pub canonical_repository: Option<String>,
    pub pull_number: Option<u64>,
    pub base_revision: Option<String>,
    pub created_at: String,
    pub license: String,
    pub patch_sha256: String,
    pub patch_size_bytes: usize,
    pub projected_row_sha256: String,
    pub disposition: HistoricalV2FrameDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2FrameShard {
    pub source_shard_index: usize,
    pub artifact_path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub row_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2Frame {
    pub schema_version: u32,
    pub protocol_sha256: String,
    pub dataset_revision: String,
    pub ranking_seed: String,
    pub shards: Vec<HistoricalV2FrameShard>,
    pub row_count: usize,
    pub eligible_count: usize,
    pub excluded_count: usize,
    pub records: Vec<HistoricalV2FrameRecord>,
    pub frame_sha256: String,
}
