use super::{
    HistoricalV2IdenticalTestExclusionReason, HistoricalV2MaterializationExclusionReason,
    HistoricalV2QualificationExclusionReason, HistoricalV2SemanticCensusExclusionReason,
    HistoricalV2SourceCensusExclusionReason, HistoricalV2TestMaterializationExclusionReason,
    HistoricalV2TestRecipeExclusionReason,
};
use serde::{Deserialize, Serialize};

pub const HISTORICAL_V2_SLOT_STAGE_CHECKPOINT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2SlotStage {
    Payload,
    Materialization,
    TestMaterialization,
    SourceCensus,
    SemanticCensus,
    AssessmentIdentity,
    Qualification,
    TestRecipe,
    IdenticalTests,
    ReadyForReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2StageArtifactKind {
    SelectedPayload,
    Materialization,
    TestMaterialization,
    NoTestPatch,
    SourceCensus,
    SemanticCensus,
    AssessmentIdentity,
    Qualification,
    TestRecipe,
    IdenticalTestExecution,
    MaterializationExclusion,
    TestMaterializationExclusion,
    SourceCensusExclusion,
    SemanticCensusExclusion,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "stage",
    content = "reason",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum HistoricalV2TerminalExclusionReason {
    Materialization(HistoricalV2MaterializationExclusionReason),
    TestMaterialization(HistoricalV2TestMaterializationExclusionReason),
    SourceCensus(Vec<HistoricalV2SourceCensusExclusionReason>),
    SemanticCensus(Vec<HistoricalV2SemanticCensusExclusionReason>),
    Qualification(Vec<HistoricalV2QualificationExclusionReason>),
    TestRecipe(HistoricalV2TestRecipeExclusionReason),
    IdenticalTests(HistoricalV2IdenticalTestExclusionReason),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV2SlotStageOutcome {
    Completed {
        artifact_kind: HistoricalV2StageArtifactKind,
        artifact_sha256: String,
    },
    Excluded {
        reason: HistoricalV2TerminalExclusionReason,
        artifact_kind: HistoricalV2StageArtifactKind,
        artifact_sha256: String,
    },
    ReadyForReview,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SlotStageCheckpoint {
    pub schema_version: u32,
    pub checkpoint_contract: String,
    pub selection_sha256: String,
    pub language: String,
    pub slot_number: usize,
    pub canonical_repository: String,
    pub sequence: usize,
    pub previous_checkpoint_sha256: Option<String>,
    pub stage: HistoricalV2SlotStage,
    pub outcome: HistoricalV2SlotStageOutcome,
    pub checkpoint_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoricalV2StageResult<T, E = HistoricalV2TerminalExclusionReason> {
    Completed(T),
    Excluded(E),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoricalV2SlotStageErrorKind {
    InvalidInput,
    InfrastructureUnavailable,
    InfrastructureFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalV2SlotStageError {
    pub stage: HistoricalV2SlotStage,
    pub kind: HistoricalV2SlotStageErrorKind,
    pub detail: String,
}
