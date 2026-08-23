use super::super::{
    IntentionalBoundaryFrameError, IntentionalBoundaryFrameErrorKind,
    IntentionalBoundaryFrameExclusionReason, IntentionalBoundaryLicenseCensusExclusionReason,
    IntentionalBoundaryMaterializationExclusionReason, IntentionalBoundaryRankStage,
    IntentionalBoundaryRankStageArtifact, IntentionalBoundaryRankStageError,
    IntentionalBoundaryRankTerminalContext, IntentionalBoundarySourceCensusExclusionReason,
    prepare_intentional_boundary_analyzed_rank_typed,
    prepare_intentional_boundary_excluded_rank_typed,
    reconcile_intentional_boundary_frame_rank_typed,
};
use super::history::{candidate, inventory};
use super::roots::ProductionRoots;

pub(super) fn reconcile_terminal(
    roots: &ProductionRoots,
    context: IntentionalBoundaryRankTerminalContext<'_>,
) -> Result<(), IntentionalBoundaryRankStageError> {
    let last = context.history.last().ok_or_else(|| {
        IntentionalBoundaryRankStageError::invalid(
            IntentionalBoundaryRankStage::Materialization,
            "intentional-boundary production terminal history is empty",
        )
    })?;
    let stage = last.checkpoint.stage;
    let record = match &last.artifact {
        IntentionalBoundaryRankStageArtifact::Candidate(_) => {
            let inventory = inventory(context.history, stage)?;
            let candidate = candidate(context.history, stage)?;
            prepare_intentional_boundary_analyzed_rank_typed(
                context.task,
                context.repository_task.population_rank,
                &inventory.inventory_sha256,
                candidate.candidate_census.clone(),
            )
            .map_err(|error| map_frame_error(stage, error))?
        }
        artifact => {
            let (reason, evidence_sha256) = exclusion_record(artifact, stage)?;
            prepare_intentional_boundary_excluded_rank_typed(
                context.task,
                context.repository_task.population_rank,
                reason,
                evidence_sha256,
            )
            .map_err(|error| map_frame_error(stage, error))?
        }
    };
    reconcile_intentional_boundary_frame_rank_typed(&roots.frame, context.task, &record)
        .map_err(|error| map_frame_error(stage, error))?;
    roots.remove_checkout(context.repository_task.population_rank, stage)
}

fn map_frame_error(
    stage: IntentionalBoundaryRankStage,
    error: IntentionalBoundaryFrameError,
) -> IntentionalBoundaryRankStageError {
    match error.kind {
        IntentionalBoundaryFrameErrorKind::InvalidInput
        | IntentionalBoundaryFrameErrorKind::CorruptState => {
            IntentionalBoundaryRankStageError::invalid(stage, error.detail)
        }
        IntentionalBoundaryFrameErrorKind::InfrastructureFailed => {
            IntentionalBoundaryRankStageError::infrastructure(stage, error.detail)
        }
    }
}

fn exclusion_record(
    artifact: &IntentionalBoundaryRankStageArtifact,
    stage: IntentionalBoundaryRankStage,
) -> Result<(IntentionalBoundaryFrameExclusionReason, &str), IntentionalBoundaryRankStageError> {
    let value = match artifact {
        IntentionalBoundaryRankStageArtifact::MaterializationExclusion(value) => (
            match value.reason {
                IntentionalBoundaryMaterializationExclusionReason::RepositoryInaccessible => {
                    IntentionalBoundaryFrameExclusionReason::RepositoryInaccessible
                }
                IntentionalBoundaryMaterializationExclusionReason::EmptyRepository => {
                    IntentionalBoundaryFrameExclusionReason::EmptyRepository
                }
            },
            value.exclusion_sha256.as_str(),
        ),
        IntentionalBoundaryRankStageArtifact::SourceCensusExclusion(value) => (
            match value.reason {
                IntentionalBoundarySourceCensusExclusionReason::NoSupportedSources => {
                    IntentionalBoundaryFrameExclusionReason::NoSupportedSources
                }
                IntentionalBoundarySourceCensusExclusionReason::UnsupportedProjectShape => {
                    IntentionalBoundaryFrameExclusionReason::UnsupportedProjectShape
                }
            },
            value.exclusion_sha256.as_str(),
        ),
        IntentionalBoundaryRankStageArtifact::LicenseCensusExclusion(value) => (
            match value.reason {
                IntentionalBoundaryLicenseCensusExclusionReason::MissingLicense => {
                    IntentionalBoundaryFrameExclusionReason::MissingLicense
                }
                IntentionalBoundaryLicenseCensusExclusionReason::UnsupportedProjectShape => {
                    IntentionalBoundaryFrameExclusionReason::UnsupportedProjectShape
                }
            },
            value.exclusion_sha256.as_str(),
        ),
        IntentionalBoundaryRankStageArtifact::SemanticCensusExclusion(value) => (
            IntentionalBoundaryFrameExclusionReason::UnsupportedProjectShape,
            value.exclusion_sha256.as_str(),
        ),
        IntentionalBoundaryRankStageArtifact::AstCensusExclusion(value) => (
            IntentionalBoundaryFrameExclusionReason::UnsupportedProjectShape,
            value.exclusion_sha256.as_str(),
        ),
        IntentionalBoundaryRankStageArtifact::ManifestExclusion(value) => (
            IntentionalBoundaryFrameExclusionReason::UnsupportedProjectShape,
            value.exclusion_sha256.as_str(),
        ),
        IntentionalBoundaryRankStageArtifact::ProjectModelExclusion(value) => (
            IntentionalBoundaryFrameExclusionReason::UnsupportedProjectShape,
            value.exclusion_sha256.as_str(),
        ),
        _ => {
            return Err(IntentionalBoundaryRankStageError::invalid(
                stage,
                "intentional-boundary terminal history has no exclusion artifact",
            ));
        }
    };
    Ok(value)
}
