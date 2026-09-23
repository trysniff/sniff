use super::super::{
    HistoricalV3IdenticalTests, HistoricalV3Materialization, HistoricalV3MechanicalQualification,
    HistoricalV3RankArtifactKind, HistoricalV3RankJournalError, HistoricalV3RankJournalErrorKind,
    HistoricalV3RankStage, HistoricalV3RankStageOutcome, HistoricalV3SemanticCensus,
    HistoricalV3SourceCensus, HistoricalV3StoredRankStage, HistoricalV3TestRecipe,
};
use serde::de::DeserializeOwned;

pub(super) struct SourceReviewInputs {
    pub materialization: HistoricalV3Materialization,
    pub source_census: HistoricalV3SourceCensus,
    pub semantic_census: HistoricalV3SemanticCensus,
    pub qualification: HistoricalV3MechanicalQualification,
    pub recipe: HistoricalV3TestRecipe,
    pub execution: HistoricalV3IdenticalTests,
}

pub(super) fn read_inputs(
    history: &[HistoricalV3StoredRankStage],
) -> Result<SourceReviewInputs, HistoricalV3RankJournalError> {
    if history.len() < 6 {
        return Err(invalid(
            "historical-v3 source review requires six completed prior stages",
        ));
    }
    Ok(SourceReviewInputs {
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
        qualification: read_completed(
            &history[3],
            HistoricalV3RankArtifactKind::MechanicalQualification,
            "mechanical qualification",
        )?,
        recipe: read_completed(
            &history[4],
            HistoricalV3RankArtifactKind::TestRecipe,
            "test recipe",
        )?,
        execution: read_completed(
            &history[5],
            HistoricalV3RankArtifactKind::IdenticalTests,
            "identical tests",
        )?,
    })
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
            "historical-v3 source review requires completed {label}"
        )));
    }
    stored
        .read_artifact()
        .map_err(invalid)?
        .ok_or_else(|| invalid("historical-v3 rank checkpoint has no artifact"))
}

pub(super) fn invalid(detail: impl Into<String>) -> HistoricalV3RankJournalError {
    HistoricalV3RankJournalError {
        stage: HistoricalV3RankStage::ReadyForSourceReview,
        kind: HistoricalV3RankJournalErrorKind::InvalidInput,
        detail: detail.into(),
    }
}
