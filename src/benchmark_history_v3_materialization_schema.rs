use super::HistoricalV3CandidateIdentity;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const HISTORICAL_V3_MATERIALIZATION_SCHEMA_VERSION: u32 = 1;
pub const HISTORICAL_V3_MATERIALIZATION_EXCLUSION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV3RevisionKind {
    Base,
    Head,
    Merge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV3MaterializationExclusionReason {
    RevisionUnavailable,
    UnsupportedGitObjectFormat,
    PullRequestHeadChanged,
    BaseNotAncestorOfMerge,
    PatchDoesNotReproduceMerge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3GitCommandEvidence {
    pub command_label: String,
    pub exit_code: Option<i32>,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub retained_stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3UnavailableRevision {
    pub kind: HistoricalV3RevisionKind,
    pub revision: String,
    pub fetch: HistoricalV3GitCommandEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV3MaterializationExclusionEvidence {
    RevisionUnavailable {
        missing: Vec<HistoricalV3UnavailableRevision>,
    },
    UnsupportedGitObjectFormat {
        object_format: String,
    },
    PullRequestHeadChanged {
        expected_head_commit: String,
        fetched_head_commit: String,
    },
    BaseNotAncestorOfMerge {
        base_commit: String,
        merge_commit: String,
    },
    PatchDoesNotReproduceMerge {
        patch_sha256: String,
        expected_merge_tree: String,
        reproduced_tree: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3MaterializationExclusion {
    pub schema_version: u32,
    pub exclusion_contract: String,
    pub protocol_sha256: String,
    pub candidate_manifest_sha256: String,
    pub stream_task_sha256: String,
    pub stream_rank: usize,
    pub rank_sha256: String,
    pub identity: HistoricalV3CandidateIdentity,
    pub name_with_owner: String,
    pub reason: HistoricalV3MaterializationExclusionReason,
    pub evidence: HistoricalV3MaterializationExclusionEvidence,
    pub exclusion_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3Materialization {
    pub schema_version: u32,
    pub materialization_contract: String,
    pub protocol_sha256: String,
    pub candidate_manifest_sha256: String,
    pub stream_task_sha256: String,
    pub stream_rank: usize,
    pub rank_sha256: String,
    pub identity: HistoricalV3CandidateIdentity,
    pub name_with_owner: String,
    pub clone_url: String,
    pub git_object_format: String,
    pub base_tree_oid: String,
    pub head_tree_oid: String,
    pub merge_tree_oid: String,
    pub merge_parent_commits: Vec<String>,
    pub patch_sha256: String,
    pub patch_byte_count: u64,
    pub materialization_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalV3MaterializedRoots {
    pub repository_root: PathBuf,
    pub base_root: PathBuf,
    pub head_root: PathBuf,
    pub merge_root: PathBuf,
    pub reproduced_root: PathBuf,
    pub patch_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoricalV3MaterializationOutcome {
    Completed {
        artifact: Box<HistoricalV3Materialization>,
        roots: HistoricalV3MaterializedRoots,
    },
    Excluded(Box<HistoricalV3MaterializationExclusion>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoricalV3MaterializationErrorKind {
    InvalidInput,
    InfrastructureUnavailable,
    InfrastructureFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalV3MaterializationError {
    pub kind: HistoricalV3MaterializationErrorKind,
    pub detail: String,
}

impl std::fmt::Display for HistoricalV3MaterializationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.detail)
    }
}

impl std::error::Error for HistoricalV3MaterializationError {}
