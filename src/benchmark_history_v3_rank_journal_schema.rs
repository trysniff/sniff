use super::super::{
    HistoricalV3CandidateIdentity, HistoricalV3Language, HistoricalV3Materialization,
    HistoricalV3MaterializationExclusion, HistoricalV3MaterializedRoots,
};
use serde::{Deserialize, Serialize};

pub const HISTORICAL_V3_RANK_CHECKPOINT_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV3RankStage {
    Materialization,
    SourceCensus,
    SemanticCensus,
    MechanicalQualification,
    TestRecipe,
    IdenticalTests,
    ReadyForSourceReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV3RankArtifactKind {
    Materialization,
    MaterializationExclusion,
    SourceCensus,
    SourceCensusExclusion,
    SemanticCensus,
    SemanticCensusExclusion,
    MechanicalQualification,
    MechanicalQualificationExclusion,
    TestRecipe,
    TestRecipeExclusion,
    IdenticalTests,
    IdenticalTestsExclusion,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3RankIdentity {
    pub protocol_sha256: String,
    pub candidate_manifest_sha256: String,
    pub stream_task_sha256: String,
    pub stream_rank: usize,
    pub rank_sha256: String,
    pub candidate: HistoricalV3CandidateIdentity,
    pub name_with_owner: String,
}

impl HistoricalV3RankIdentity {
    pub fn language(&self) -> HistoricalV3Language {
        self.candidate.language
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV3RankStageOutcome {
    Completed {
        artifact_kind: HistoricalV3RankArtifactKind,
        artifact_sha256: String,
    },
    Excluded {
        artifact_kind: HistoricalV3RankArtifactKind,
        artifact_sha256: String,
    },
    ReadyForSourceReview {
        bundle_sha256: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3RankCheckpoint {
    pub schema_version: u32,
    pub checkpoint_contract: String,
    pub identity: HistoricalV3RankIdentity,
    pub sequence: usize,
    pub previous_checkpoint_sha256: Option<String>,
    pub stage: HistoricalV3RankStage,
    pub outcome: HistoricalV3RankStageOutcome,
    pub checkpoint_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoricalV3RankJournalErrorKind {
    InvalidInput,
    InfrastructureUnavailable,
    InfrastructureFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalV3RankJournalError {
    pub stage: HistoricalV3RankStage,
    pub kind: HistoricalV3RankJournalErrorKind,
    pub detail: String,
}

impl std::fmt::Display for HistoricalV3RankJournalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.detail)
    }
}

impl std::error::Error for HistoricalV3RankJournalError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoricalV3MaterializationStageRun {
    Completed {
        artifact: Box<HistoricalV3Materialization>,
        roots: HistoricalV3MaterializedRoots,
        resumed: bool,
    },
    Excluded {
        artifact: Box<HistoricalV3MaterializationExclusion>,
        resumed: bool,
    },
}
