use super::{HistoricalRepositoryCandidate, ProvenanceArtifact, SourceSnapshot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const NON_BLIND_HISTORY_ASSESSMENT_SCHEMA_VERSION: u32 = 1;
pub const NON_BLIND_HISTORY_ASSESSMENT_PROTOCOL_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalCommitMetadata {
    pub commit_sha: String,
    pub parent_shas: Vec<String>,
    pub subject: String,
    pub changed_paths: Vec<HistoricalChangedPath>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalChangedPath {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_path: Option<String>,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RankedHistoricalCommit {
    pub rank: usize,
    pub commit_sha: String,
    pub parent_sha: String,
    pub subject: String,
    pub changed_paths: Vec<HistoricalChangedPath>,
    pub metadata_sha256: String,
    pub rank_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalGitDiscovery {
    pub repository: String,
    pub default_branch: String,
    pub default_branch_head: String,
    pub reachable_commit_count: usize,
    pub matching_commit_count: usize,
    pub matching_commits_sha256: String,
    pub selected_commit: Option<RankedHistoricalCommit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalRevisionSide {
    Parent,
    Commit,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AffectedHistoricalMethod {
    pub side: HistoricalRevisionSide,
    pub language: String,
    pub repository_path: String,
    pub symbol: String,
    pub start_line: usize,
    pub end_line: usize,
    pub source_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalTestResult {
    pub revision: String,
    pub command: Vec<String>,
    pub runtime_identity: String,
    pub status_code: Option<i32>,
    pub timed_out: bool,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub raw_result_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalRepositoryFacts {
    pub repository: String,
    pub accessible: bool,
    pub repository_empty: bool,
    pub default_branch: Option<String>,
    pub default_branch_head: Option<String>,
    pub complete_history: bool,
    pub matching_commit_count: Option<usize>,
    pub selected_commit: Option<RankedHistoricalCommit>,
    pub supported_project_shape: Option<bool>,
    pub qualifying_production_change: Option<bool>,
    pub parent_method_counts: BTreeMap<String, usize>,
    pub parent_method_count: Option<usize>,
    pub affected_methods: Vec<AffectedHistoricalMethod>,
    pub quota_language: Option<String>,
    pub source_non_whitespace_lines_before: Option<usize>,
    pub source_non_whitespace_lines_after: Option<usize>,
    pub license_path: Option<String>,
    pub test_recipe: Option<Vec<String>>,
    pub parent_test: Option<HistoricalTestResult>,
    pub commit_test: Option<HistoricalTestResult>,
    pub test_outcome: Option<HistoricalTestOutcome>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalTestOutcome {
    Passed,
    RecipeUnavailable,
    RecipeAmbiguous,
    RecipeChanged,
    RuntimeUnavailable,
    SandboxUnavailable,
    ParentFailed,
    CommitFailed,
    TimedOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalAssessmentDisposition {
    Selected,
    Excluded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalExclusionReason {
    Inaccessible,
    EmptyRepository,
    IncompleteHistory,
    NoMatchingCommit,
    UnsupportedProjectShape,
    NoQualifyingProductionChange,
    NoAffectedMethods,
    BelowMethodFloor,
    AboveMethodCeiling,
    NoSourceReduction,
    MissingLicense,
    TestRecipeUnavailable,
    TestRecipeAmbiguous,
    TestRecipeChanged,
    RuntimeUnavailable,
    SandboxUnavailable,
    ParentTestsFailed,
    CommitTestsFailed,
    TestTimedOut,
    QuotaFilled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalEvidenceKind {
    RepositoryRefs,
    CommitMetadata,
    SourceCensus,
    SourceDelta,
    License,
    TestRecipe,
    ParentTest,
    CommitTest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalAssessmentEvidence {
    pub kind: HistoricalEvidenceKind,
    pub source: String,
    pub observed_at: String,
    pub artifact_path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalSelectedProvenance {
    pub provenance_id: String,
    pub upstream_url: String,
    pub upstream_revision: String,
    pub upstream_record_id: String,
    pub before: Vec<SourceSnapshot>,
    pub after: Vec<SourceSnapshot>,
    pub license: ProvenanceArtifact,
    pub behavioral_evidence: Vec<ProvenanceArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalRepositoryAssessment {
    #[serde(flatten)]
    pub candidate: HistoricalRepositoryCandidate,
    pub facts: Option<HistoricalRepositoryFacts>,
    pub evidence: Vec<HistoricalAssessmentEvidence>,
    pub disposition: Option<HistoricalAssessmentDisposition>,
    pub exclusion_reason: Option<HistoricalExclusionReason>,
    pub selected_provenance: Option<HistoricalSelectedProvenance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonBlindHistoryAssessment {
    pub schema_version: u32,
    pub protocol_sha256: String,
    pub policy_sha256: String,
    pub history_worksheet_sha256: String,
    pub history_task_sha256: String,
    pub task_sha256: String,
    pub quota_target: BTreeMap<String, usize>,
    pub assessments: Vec<HistoricalRepositoryAssessment>,
}
