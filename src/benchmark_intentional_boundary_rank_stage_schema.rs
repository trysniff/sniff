use super::{
    IntentionalBoundaryAstCensusExclusion, IntentionalBoundaryAstCensusStage,
    IntentionalBoundaryBehaviorStage, IntentionalBoundaryCandidateStage,
    IntentionalBoundaryEvidenceStage, IntentionalBoundaryGeneratorStage,
    IntentionalBoundaryLicenseCensusExclusion, IntentionalBoundaryLicenseCensusStage,
    IntentionalBoundaryManifestExclusion, IntentionalBoundaryManifestStage,
    IntentionalBoundaryMaterialization, IntentionalBoundaryMaterializationExclusion,
    IntentionalBoundaryProjectModelExclusion, IntentionalBoundaryProjectModelStage,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundarySemanticCensusExclusion,
    IntentionalBoundarySemanticCensusStage, IntentionalBoundarySourceCensusExclusion,
    IntentionalBoundarySourceCensusStage,
};
use serde::{Deserialize, Serialize};

pub const INTENTIONAL_BOUNDARY_RANK_STAGE_CHECKPOINT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryRankStage {
    Materialization,
    Inventory,
    SourceCensus,
    LicenseCensus,
    SemanticCensus,
    AstCensus,
    Manifest,
    BaseEvidence,
    ProjectModel,
    Generator,
    Behavior,
    Candidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryRankStageArtifactKind {
    Materialization,
    MaterializationExclusion,
    Inventory,
    SourceCensus,
    SourceCensusExclusion,
    LicenseCensus,
    LicenseCensusExclusion,
    SemanticCensus,
    SemanticCensusExclusion,
    AstCensus,
    AstCensusExclusion,
    Manifest,
    ManifestExclusion,
    BaseEvidence,
    ProjectModel,
    ProjectModelExclusion,
    Generator,
    Behavior,
    Candidate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "artifact_kind",
    content = "artifact",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum IntentionalBoundaryRankStageArtifact {
    Materialization(IntentionalBoundaryMaterialization),
    MaterializationExclusion(IntentionalBoundaryMaterializationExclusion),
    Inventory(IntentionalBoundaryRepositoryInventory),
    SourceCensus(IntentionalBoundarySourceCensusStage),
    SourceCensusExclusion(IntentionalBoundarySourceCensusExclusion),
    LicenseCensus(IntentionalBoundaryLicenseCensusStage),
    LicenseCensusExclusion(IntentionalBoundaryLicenseCensusExclusion),
    SemanticCensus(IntentionalBoundarySemanticCensusStage),
    SemanticCensusExclusion(IntentionalBoundarySemanticCensusExclusion),
    AstCensus(IntentionalBoundaryAstCensusStage),
    AstCensusExclusion(IntentionalBoundaryAstCensusExclusion),
    Manifest(Box<IntentionalBoundaryManifestStage>),
    ManifestExclusion(Box<IntentionalBoundaryManifestExclusion>),
    BaseEvidence(Box<IntentionalBoundaryEvidenceStage>),
    ProjectModel(Box<IntentionalBoundaryProjectModelStage>),
    ProjectModelExclusion(Box<IntentionalBoundaryProjectModelExclusion>),
    Generator(Box<IntentionalBoundaryGeneratorStage>),
    Behavior(Box<IntentionalBoundaryBehaviorStage>),
    Candidate(Box<IntentionalBoundaryCandidateStage>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum IntentionalBoundaryRankStageOutcome {
    Completed {
        artifact_kind: IntentionalBoundaryRankStageArtifactKind,
        artifact_sha256: String,
    },
    Excluded {
        artifact_kind: IntentionalBoundaryRankStageArtifactKind,
        artifact_sha256: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryRankStageCheckpoint {
    pub schema_version: u32,
    pub checkpoint_contract: String,
    pub frame_task_sha256: String,
    pub population_rank: usize,
    pub population_rank_sha256: String,
    pub repository: String,
    pub sequence: usize,
    pub previous_checkpoint_sha256: Option<String>,
    pub stage: IntentionalBoundaryRankStage,
    pub outcome: IntentionalBoundaryRankStageOutcome,
    pub checkpoint_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentionalBoundaryRankStageErrorKind {
    InvalidInput,
    InfrastructureUnavailable,
    InfrastructureFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentionalBoundaryRankStageError {
    pub stage: IntentionalBoundaryRankStage,
    pub kind: IntentionalBoundaryRankStageErrorKind,
    pub detail: String,
}
