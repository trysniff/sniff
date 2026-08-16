use serde::{Deserialize, Serialize};

pub const HISTORICAL_V2_MATERIALIZATION_EXCLUSION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2MaterializationExclusionReason {
    RepositoryUnavailable,
    RepositoryEmpty,
    BaseRevisionUnavailable,
    UnsupportedGitObjectFormat,
    HistoricalPatchDoesNotApply,
    HistoricalPatchProducesNoTreeChange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2GitCommandRejectionEvidence {
    pub command_label: String,
    pub exit_code: Option<i32>,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub retained_stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV2MaterializationExclusionEvidence {
    RepositoryProbe {
        url: String,
        status: u16,
    },
    RepositoryEmpty {
        clone_url: String,
    },
    BaseRevisionUnavailable {
        revision: String,
        command: HistoricalV2GitCommandRejectionEvidence,
    },
    UnsupportedGitObjectFormat {
        object_format: String,
    },
    HistoricalPatchRejected {
        patch_sha256: String,
        command: HistoricalV2GitCommandRejectionEvidence,
    },
    HistoricalPatchProducesNoTreeChange {
        base_tree_oid: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2MaterializationExclusion {
    pub schema_version: u32,
    pub exclusion_contract: String,
    pub canonical_repository: String,
    pub base_revision: String,
    pub historical_patch_sha256: String,
    pub reason: HistoricalV2MaterializationExclusionReason,
    pub evidence: HistoricalV2MaterializationExclusionEvidence,
    pub exclusion_sha256: String,
}
