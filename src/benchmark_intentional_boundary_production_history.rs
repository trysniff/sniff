use super::super::{
    IntentionalBoundaryAstCensusStage, IntentionalBoundaryBehaviorStage,
    IntentionalBoundaryCandidateStage, IntentionalBoundaryEvidenceStage,
    IntentionalBoundaryGeneratorStage, IntentionalBoundaryLicenseCensusStage,
    IntentionalBoundaryManifestStage, IntentionalBoundaryMaterialization,
    IntentionalBoundaryProjectModelStage, IntentionalBoundaryRankStage,
    IntentionalBoundaryRankStageArtifact, IntentionalBoundaryRankStageError,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundarySemanticCensusStage,
    IntentionalBoundarySourceCensusStage, IntentionalBoundaryStoredRankStage,
};

pub(super) fn materialization(
    history: &[IntentionalBoundaryStoredRankStage],
    stage: IntentionalBoundaryRankStage,
) -> Result<&IntentionalBoundaryMaterialization, IntentionalBoundaryRankStageError> {
    match artifact(history, 0, stage)? {
        IntentionalBoundaryRankStageArtifact::Materialization(value) => Ok(value),
        _ => Err(wrong_artifact(stage, "materialization")),
    }
}

pub(super) fn inventory(
    history: &[IntentionalBoundaryStoredRankStage],
    stage: IntentionalBoundaryRankStage,
) -> Result<&IntentionalBoundaryRepositoryInventory, IntentionalBoundaryRankStageError> {
    match artifact(history, 1, stage)? {
        IntentionalBoundaryRankStageArtifact::Inventory(value) => Ok(value),
        _ => Err(wrong_artifact(stage, "inventory")),
    }
}

pub(super) fn source_census(
    history: &[IntentionalBoundaryStoredRankStage],
    stage: IntentionalBoundaryRankStage,
) -> Result<&IntentionalBoundarySourceCensusStage, IntentionalBoundaryRankStageError> {
    match artifact(history, 2, stage)? {
        IntentionalBoundaryRankStageArtifact::SourceCensus(value) => Ok(value),
        _ => Err(wrong_artifact(stage, "source census")),
    }
}

pub(super) fn license_census(
    history: &[IntentionalBoundaryStoredRankStage],
    stage: IntentionalBoundaryRankStage,
) -> Result<&IntentionalBoundaryLicenseCensusStage, IntentionalBoundaryRankStageError> {
    match artifact(history, 3, stage)? {
        IntentionalBoundaryRankStageArtifact::LicenseCensus(value) => Ok(value),
        _ => Err(wrong_artifact(stage, "license census")),
    }
}

pub(super) fn semantic_census(
    history: &[IntentionalBoundaryStoredRankStage],
    stage: IntentionalBoundaryRankStage,
) -> Result<&IntentionalBoundarySemanticCensusStage, IntentionalBoundaryRankStageError> {
    match artifact(history, 4, stage)? {
        IntentionalBoundaryRankStageArtifact::SemanticCensus(value) => Ok(value),
        _ => Err(wrong_artifact(stage, "semantic census")),
    }
}

pub(super) fn ast_census(
    history: &[IntentionalBoundaryStoredRankStage],
    stage: IntentionalBoundaryRankStage,
) -> Result<&IntentionalBoundaryAstCensusStage, IntentionalBoundaryRankStageError> {
    match artifact(history, 5, stage)? {
        IntentionalBoundaryRankStageArtifact::AstCensus(value) => Ok(value),
        _ => Err(wrong_artifact(stage, "AST census")),
    }
}

pub(super) fn manifest(
    history: &[IntentionalBoundaryStoredRankStage],
    stage: IntentionalBoundaryRankStage,
) -> Result<&IntentionalBoundaryManifestStage, IntentionalBoundaryRankStageError> {
    match artifact(history, 6, stage)? {
        IntentionalBoundaryRankStageArtifact::Manifest(value) => Ok(value),
        _ => Err(wrong_artifact(stage, "manifest")),
    }
}

pub(super) fn base_evidence(
    history: &[IntentionalBoundaryStoredRankStage],
    stage: IntentionalBoundaryRankStage,
) -> Result<&IntentionalBoundaryEvidenceStage, IntentionalBoundaryRankStageError> {
    match artifact(history, 7, stage)? {
        IntentionalBoundaryRankStageArtifact::BaseEvidence(value) => Ok(value),
        _ => Err(wrong_artifact(stage, "base evidence")),
    }
}

pub(super) fn project_model(
    history: &[IntentionalBoundaryStoredRankStage],
    stage: IntentionalBoundaryRankStage,
) -> Result<&IntentionalBoundaryProjectModelStage, IntentionalBoundaryRankStageError> {
    match artifact(history, 8, stage)? {
        IntentionalBoundaryRankStageArtifact::ProjectModel(value) => Ok(value),
        _ => Err(wrong_artifact(stage, "project model")),
    }
}

pub(super) fn generator(
    history: &[IntentionalBoundaryStoredRankStage],
    stage: IntentionalBoundaryRankStage,
) -> Result<&IntentionalBoundaryGeneratorStage, IntentionalBoundaryRankStageError> {
    match artifact(history, 9, stage)? {
        IntentionalBoundaryRankStageArtifact::Generator(value) => Ok(value),
        _ => Err(wrong_artifact(stage, "generator")),
    }
}

pub(super) fn behavior(
    history: &[IntentionalBoundaryStoredRankStage],
    stage: IntentionalBoundaryRankStage,
) -> Result<&IntentionalBoundaryBehaviorStage, IntentionalBoundaryRankStageError> {
    match artifact(history, 10, stage)? {
        IntentionalBoundaryRankStageArtifact::Behavior(value) => Ok(value),
        _ => Err(wrong_artifact(stage, "behavior")),
    }
}

pub(super) fn candidate(
    history: &[IntentionalBoundaryStoredRankStage],
    stage: IntentionalBoundaryRankStage,
) -> Result<&IntentionalBoundaryCandidateStage, IntentionalBoundaryRankStageError> {
    match artifact(history, 11, stage)? {
        IntentionalBoundaryRankStageArtifact::Candidate(value) => Ok(value),
        _ => Err(wrong_artifact(stage, "candidate")),
    }
}

fn artifact(
    history: &[IntentionalBoundaryStoredRankStage],
    index: usize,
    stage: IntentionalBoundaryRankStage,
) -> Result<&IntentionalBoundaryRankStageArtifact, IntentionalBoundaryRankStageError> {
    history
        .get(index)
        .map(|stored| &stored.artifact)
        .ok_or_else(|| wrong_artifact(stage, "committed predecessor"))
}

fn wrong_artifact(
    stage: IntentionalBoundaryRankStage,
    expected: &str,
) -> IntentionalBoundaryRankStageError {
    IntentionalBoundaryRankStageError::invalid(
        stage,
        format!("intentional-boundary production stage requires committed {expected}"),
    )
}
