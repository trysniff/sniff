use serde::{Deserialize, Serialize};

pub const HISTORICAL_V3_PROTOCOL_SCHEMA_VERSION: u32 = 2;
pub const HISTORICAL_V3_STREAM_TASK_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV3Language {
    Go,
    JavaScript,
    Kotlin,
    Python,
    Rust,
    TypeScript,
}

impl HistoricalV3Language {
    pub(super) const ALL: [Self; 6] = [
        Self::Go,
        Self::JavaScript,
        Self::Kotlin,
        Self::Python,
        Self::Rust,
        Self::TypeScript,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV3AllowedMetadataField {
    RepositoryId,
    PullRequestNumber,
    CreatedAt,
    UpdatedAt,
    ClosedAt,
    MergedAt,
    BaseCommit,
    HeadCommit,
    MergeCommit,
    ParentCommits,
    ArtifactIdentity,
}

impl HistoricalV3AllowedMetadataField {
    pub(super) const ALL: [Self; 11] = [
        Self::RepositoryId,
        Self::PullRequestNumber,
        Self::CreatedAt,
        Self::UpdatedAt,
        Self::ClosedAt,
        Self::MergedAt,
        Self::BaseCommit,
        Self::HeadCommit,
        Self::MergeCommit,
        Self::ParentCommits,
        Self::ArtifactIdentity,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV3ForbiddenMetadataField {
    Title,
    Body,
    IssueText,
    Comments,
    Reviews,
    Reactions,
    Labels,
    Assignees,
    Popularity,
    AuthorIdentity,
    GeneratedSummary,
}

impl HistoricalV3ForbiddenMetadataField {
    pub(super) const ALL: [Self; 11] = [
        Self::Title,
        Self::Body,
        Self::IssueText,
        Self::Comments,
        Self::Reviews,
        Self::Reactions,
        Self::Labels,
        Self::Assignees,
        Self::Popularity,
        Self::AuthorIdentity,
        Self::GeneratedSummary,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV3MechanicalRequirement {
    ImmutableRevisionsMaterialize,
    PatchReproducesMerge,
    ChangedProductionMethodResolves,
    CompilerSourceAndSemanticCensus,
    RepositoryMethodBounds,
    NetProductionReductionOrConsolidation,
    PublicSurfacePreserved,
    IdenticalTestsPass,
    NonProductionOnlyChangesExcluded,
}

impl HistoricalV3MechanicalRequirement {
    pub(super) const ALL: [Self; 9] = [
        Self::ImmutableRevisionsMaterialize,
        Self::PatchReproducesMerge,
        Self::ChangedProductionMethodResolves,
        Self::CompilerSourceAndSemanticCensus,
        Self::RepositoryMethodBounds,
        Self::NetProductionReductionOrConsolidation,
        Self::PublicSurfacePreserved,
        Self::IdenticalTestsPass,
        Self::NonProductionOnlyChangesExcluded,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3SourceFrameBinding {
    pub language: HistoricalV3Language,
    pub frame_id: String,
    pub policy_sha256: String,
    pub manifest_sha256: String,
    pub frame_sha256: String,
    pub repository_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3CandidateWindow {
    pub merged_at_or_after_utc: String,
    pub merged_before_utc: String,
    pub github_api_version: String,
    pub partition: String,
    pub pagination: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3StopRule {
    pub accepted_target_per_language: usize,
    pub distinct_repository_floor_per_language: usize,
    pub accepted_case_cap_per_repository: usize,
    pub reviewable_candidate_cap_per_repository: usize,
    pub adjudication_cap_per_language: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3MechanicalPolicy {
    pub production_method_minimum: usize,
    pub production_method_maximum: usize,
    pub generated_path_segments: Vec<String>,
    pub vendored_path_segments: Vec<String>,
    pub documentation_path_segments: Vec<String>,
    pub fixture_path_segments: Vec<String>,
    pub test_path_segments: Vec<String>,
    pub test_file_suffixes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3Protocol {
    pub schema_version: u32,
    pub protocol_id: String,
    pub protocol_contract: String,
    pub ranking_domain: String,
    pub ranking_seed: String,
    pub prior_benchmark_identity_seal_sha256: String,
    pub languages: Vec<HistoricalV3Language>,
    pub source_frames: Vec<HistoricalV3SourceFrameBinding>,
    pub candidate_window: HistoricalV3CandidateWindow,
    pub allowed_metadata_fields: Vec<HistoricalV3AllowedMetadataField>,
    pub forbidden_metadata_fields: Vec<HistoricalV3ForbiddenMetadataField>,
    pub mechanical_requirements: Vec<HistoricalV3MechanicalRequirement>,
    pub mechanical_policy: HistoricalV3MechanicalPolicy,
    pub stop_rule: HistoricalV3StopRule,
    pub no_fallbacks: bool,
    pub model_access_forbidden: bool,
    pub sniff_output_access_forbidden: bool,
    pub protocol_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3CandidateIdentity {
    pub language: HistoricalV3Language,
    pub repository_id: u64,
    pub pull_request_number: u64,
    pub base_commit: String,
    pub head_commit: String,
    pub merge_commit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3CandidateTask {
    pub stream_rank: usize,
    pub identity: HistoricalV3CandidateIdentity,
    pub rank_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3StreamTask {
    pub schema_version: u32,
    pub stream_contract: String,
    pub protocol_sha256: String,
    pub candidates: Vec<HistoricalV3CandidateTask>,
    pub task_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV3ReviewDisposition {
    Accepted,
    Rejected,
    Disputed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3ReviewRecord {
    pub stream_rank: usize,
    pub rank_sha256: String,
    pub language: HistoricalV3Language,
    pub repository_id: u64,
    pub disposition: HistoricalV3ReviewDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HistoricalV3StopStatus {
    Continue {
        reviewed: usize,
        accepted: usize,
        distinct_accepted_repositories: usize,
    },
    TargetReached {
        reviewed_prefix: usize,
        accepted: usize,
        distinct_accepted_repositories: usize,
    },
    FailedAdjudicationCap {
        reviewed: usize,
        accepted: usize,
        distinct_accepted_repositories: usize,
    },
    FailedSourceExhausted {
        reviewed: usize,
        accepted: usize,
        distinct_accepted_repositories: usize,
    },
}
