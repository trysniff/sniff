use super::super::{
    HistoricalV3CandidateCollection, HistoricalV3Materialization, HistoricalV3Protocol,
    HistoricalV3RankArtifactKind, HistoricalV3RankJournalError, HistoricalV3RankJournalErrorKind,
    HistoricalV3RankStage, HistoricalV3RankStageOutcome, HistoricalV3SemanticCensus,
    HistoricalV3SemanticCensusExclusion, HistoricalV3SemanticCensusStageRun,
    HistoricalV3SourceCensus, HistoricalV3StoredRankStage, IntentionalBoundaryInventoryError,
    IntentionalBoundaryInventoryErrorKind, IntentionalBoundarySemanticCensusStageError,
    IntentionalBoundarySemanticCensusStageErrorKind,
    validate_historical_v3_semantic_census_commitment,
    validate_historical_v3_semantic_census_exclusion,
};
use serde::de::DeserializeOwned;

pub(super) fn resume_semantic_census(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    materialization: &HistoricalV3Materialization,
    source_census: &HistoricalV3SourceCensus,
    stored: &HistoricalV3StoredRankStage,
) -> Result<HistoricalV3SemanticCensusStageRun, HistoricalV3RankJournalError> {
    match &stored.checkpoint.outcome {
        HistoricalV3RankStageOutcome::Completed {
            artifact_kind: HistoricalV3RankArtifactKind::SemanticCensus,
            artifact_sha256,
        } => {
            let artifact = read_required_artifact::<HistoricalV3SemanticCensus>(stored)?;
            if artifact.semantic_census_sha256 != *artifact_sha256 {
                return Err(invalid(
                    "historical-v3 semantic census does not match its checkpoint",
                ));
            }
            validate_historical_v3_semantic_census_commitment(
                protocol,
                collection,
                materialization,
                source_census,
                &artifact,
            )
            .map_err(invalid)?;
            Ok(HistoricalV3SemanticCensusStageRun::Completed {
                artifact: Box::new(artifact),
                resumed: true,
            })
        }
        HistoricalV3RankStageOutcome::Excluded {
            artifact_kind: HistoricalV3RankArtifactKind::SemanticCensusExclusion,
            artifact_sha256,
        } => {
            let artifact = read_required_artifact::<HistoricalV3SemanticCensusExclusion>(stored)?;
            if artifact.exclusion_sha256 != *artifact_sha256 {
                return Err(invalid(
                    "historical-v3 semantic exclusion does not match its checkpoint",
                ));
            }
            validate_historical_v3_semantic_census_exclusion(
                protocol,
                collection,
                materialization,
                source_census,
                &artifact,
            )
            .map_err(invalid)?;
            Ok(HistoricalV3SemanticCensusStageRun::Excluded {
                artifact: Box::new(artifact),
                resumed: true,
            })
        }
        _ => Err(invalid(
            "historical-v3 rank journal has an invalid semantic census outcome",
        )),
    }
}

pub(super) fn read_completed_materialization(
    stored: &HistoricalV3StoredRankStage,
) -> Result<HistoricalV3Materialization, HistoricalV3RankJournalError> {
    if !matches!(
        stored.checkpoint.outcome,
        HistoricalV3RankStageOutcome::Completed {
            artifact_kind: HistoricalV3RankArtifactKind::Materialization,
            ..
        }
    ) {
        return Err(invalid(
            "historical-v3 semantic census requires completed materialization",
        ));
    }
    read_required_artifact(stored)
}

pub(super) fn read_completed_source_census(
    stored: &HistoricalV3StoredRankStage,
) -> Result<HistoricalV3SourceCensus, HistoricalV3RankJournalError> {
    if !matches!(
        stored.checkpoint.outcome,
        HistoricalV3RankStageOutcome::Completed {
            artifact_kind: HistoricalV3RankArtifactKind::SourceCensus,
            ..
        }
    ) {
        return Err(invalid(
            "historical-v3 semantic census requires completed source census",
        ));
    }
    read_required_artifact(stored)
}

fn read_required_artifact<T: DeserializeOwned>(
    stored: &HistoricalV3StoredRankStage,
) -> Result<T, HistoricalV3RankJournalError> {
    stored
        .read_artifact()
        .map_err(invalid)?
        .ok_or_else(|| invalid("historical-v3 rank checkpoint has no artifact"))
}

pub(super) fn map_semantic_error(
    error: IntentionalBoundarySemanticCensusStageError,
) -> HistoricalV3RankJournalError {
    HistoricalV3RankJournalError {
        stage: HistoricalV3RankStage::SemanticCensus,
        kind: match error.kind {
            IntentionalBoundarySemanticCensusStageErrorKind::InvalidInput => {
                HistoricalV3RankJournalErrorKind::InvalidInput
            }
            IntentionalBoundarySemanticCensusStageErrorKind::InfrastructureUnavailable => {
                HistoricalV3RankJournalErrorKind::InfrastructureUnavailable
            }
            IntentionalBoundarySemanticCensusStageErrorKind::InfrastructureFailed => {
                HistoricalV3RankJournalErrorKind::InfrastructureFailed
            }
        },
        detail: error.detail,
    }
}

pub(super) fn map_inventory_error(
    error: IntentionalBoundaryInventoryError,
) -> HistoricalV3RankJournalError {
    HistoricalV3RankJournalError {
        stage: HistoricalV3RankStage::SemanticCensus,
        kind: match error.kind {
            IntentionalBoundaryInventoryErrorKind::InvalidInput => {
                HistoricalV3RankJournalErrorKind::InvalidInput
            }
            IntentionalBoundaryInventoryErrorKind::InfrastructureUnavailable => {
                HistoricalV3RankJournalErrorKind::InfrastructureUnavailable
            }
            IntentionalBoundaryInventoryErrorKind::InfrastructureFailed => {
                HistoricalV3RankJournalErrorKind::InfrastructureFailed
            }
        },
        detail: error.detail,
    }
}

pub(super) fn invalid(detail: impl Into<String>) -> HistoricalV3RankJournalError {
    HistoricalV3RankJournalError {
        stage: HistoricalV3RankStage::SemanticCensus,
        kind: HistoricalV3RankJournalErrorKind::InvalidInput,
        detail: detail.into(),
    }
}
