use super::super::{
    HistoricalV3CandidateCollection, HistoricalV3Materialization,
    HistoricalV3MechanicalQualification, HistoricalV3MechanicalQualificationExclusion,
    HistoricalV3MechanicalQualificationStageRun, HistoricalV3Protocol,
    HistoricalV3RankArtifactKind, HistoricalV3RankJournalError, HistoricalV3RankJournalErrorKind,
    HistoricalV3RankStage, HistoricalV3RankStageOutcome, HistoricalV3SemanticCensus,
    HistoricalV3SourceCensus, HistoricalV3StoredRankStage,
    validate_historical_v3_mechanical_qualification,
    validate_historical_v3_mechanical_qualification_exclusion,
};
use serde::de::DeserializeOwned;

pub(super) struct MechanicalInputs {
    pub materialization: HistoricalV3Materialization,
    pub source_census: HistoricalV3SourceCensus,
    pub semantic_census: HistoricalV3SemanticCensus,
}

pub(super) fn read_inputs(
    history: &[HistoricalV3StoredRankStage],
) -> Result<MechanicalInputs, HistoricalV3RankJournalError> {
    if history.len() < 3 {
        return Err(invalid(
            "historical-v3 mechanical qualification requires three completed prior stages",
        ));
    }
    Ok(MechanicalInputs {
        materialization: read_completed(
            &history[0],
            HistoricalV3RankArtifactKind::Materialization,
            "materialization",
        )?,
        source_census: read_completed(
            &history[1],
            HistoricalV3RankArtifactKind::SourceCensus,
            "source census",
        )?,
        semantic_census: read_completed(
            &history[2],
            HistoricalV3RankArtifactKind::SemanticCensus,
            "semantic census",
        )?,
    })
}

pub(super) fn resume(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    inputs: &MechanicalInputs,
    stored: &HistoricalV3StoredRankStage,
) -> Result<HistoricalV3MechanicalQualificationStageRun, HistoricalV3RankJournalError> {
    match &stored.checkpoint.outcome {
        HistoricalV3RankStageOutcome::Completed {
            artifact_kind: HistoricalV3RankArtifactKind::MechanicalQualification,
            artifact_sha256,
        } => {
            let artifact = read_required::<HistoricalV3MechanicalQualification>(stored)?;
            if artifact.qualification_sha256 != *artifact_sha256 {
                return Err(invalid(
                    "historical-v3 mechanical qualification does not match its checkpoint",
                ));
            }
            validate_historical_v3_mechanical_qualification(
                protocol,
                collection,
                &inputs.materialization,
                &inputs.source_census,
                &inputs.semantic_census,
                &artifact,
            )
            .map_err(invalid)?;
            Ok(HistoricalV3MechanicalQualificationStageRun::Qualified {
                artifact: Box::new(artifact),
                resumed: true,
            })
        }
        HistoricalV3RankStageOutcome::Excluded {
            artifact_kind: HistoricalV3RankArtifactKind::MechanicalQualificationExclusion,
            artifact_sha256,
        } => {
            let artifact = read_required::<HistoricalV3MechanicalQualificationExclusion>(stored)?;
            if artifact.exclusion_sha256 != *artifact_sha256 {
                return Err(invalid(
                    "historical-v3 mechanical exclusion does not match its checkpoint",
                ));
            }
            validate_historical_v3_mechanical_qualification_exclusion(
                protocol,
                collection,
                &inputs.materialization,
                &inputs.source_census,
                &inputs.semantic_census,
                &artifact,
            )
            .map_err(invalid)?;
            Ok(HistoricalV3MechanicalQualificationStageRun::Excluded {
                artifact: Box::new(artifact),
                resumed: true,
            })
        }
        _ => Err(invalid(
            "historical-v3 rank journal has an invalid mechanical qualification outcome",
        )),
    }
}

fn read_completed<T: DeserializeOwned>(
    stored: &HistoricalV3StoredRankStage,
    expected: HistoricalV3RankArtifactKind,
    label: &str,
) -> Result<T, HistoricalV3RankJournalError> {
    if !matches!(
        stored.checkpoint.outcome,
        HistoricalV3RankStageOutcome::Completed { artifact_kind, .. } if artifact_kind == expected
    ) {
        return Err(invalid(format!(
            "historical-v3 mechanical qualification requires completed {label}"
        )));
    }
    read_required(stored)
}

fn read_required<T: DeserializeOwned>(
    stored: &HistoricalV3StoredRankStage,
) -> Result<T, HistoricalV3RankJournalError> {
    stored
        .read_artifact()
        .map_err(invalid)?
        .ok_or_else(|| invalid("historical-v3 rank checkpoint has no artifact"))
}

pub(super) fn invalid(detail: impl Into<String>) -> HistoricalV3RankJournalError {
    HistoricalV3RankJournalError {
        stage: HistoricalV3RankStage::MechanicalQualification,
        kind: HistoricalV3RankJournalErrorKind::InvalidInput,
        detail: detail.into(),
    }
}
