use super::super::HistoricalV3CandidateCollection;
use super::super::{
    HistoricalV3Materialization, HistoricalV3MechanicalQualification, HistoricalV3Protocol,
    HistoricalV3RankArtifactKind, HistoricalV3RankJournalError, HistoricalV3RankJournalErrorKind,
    HistoricalV3RankStage, HistoricalV3RankStageOutcome, HistoricalV3SemanticCensus,
    HistoricalV3SourceCensus, HistoricalV3StoredRankStage, HistoricalV3TestRecipe,
    HistoricalV3TestRecipeExclusion, HistoricalV3TestRecipeStageRun,
    validate_historical_v3_test_recipe, validate_historical_v3_test_recipe_exclusion,
};
use serde::de::DeserializeOwned;

pub(super) struct TestRecipeInputs {
    pub materialization: HistoricalV3Materialization,
    pub source_census: HistoricalV3SourceCensus,
    pub semantic_census: HistoricalV3SemanticCensus,
    pub qualification: HistoricalV3MechanicalQualification,
}

pub(super) fn read_inputs(
    history: &[HistoricalV3StoredRankStage],
) -> Result<TestRecipeInputs, HistoricalV3RankJournalError> {
    if history.len() < 4 {
        return Err(invalid(
            "historical-v3 test recipe requires four completed prior stages",
        ));
    }
    Ok(TestRecipeInputs {
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
    })
}

pub(super) fn resume(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    inputs: &TestRecipeInputs,
    stored: &HistoricalV3StoredRankStage,
) -> Result<HistoricalV3TestRecipeStageRun, HistoricalV3RankJournalError> {
    match &stored.checkpoint.outcome {
        HistoricalV3RankStageOutcome::Completed {
            artifact_kind: HistoricalV3RankArtifactKind::TestRecipe,
            artifact_sha256,
        } => {
            let artifact = read_required::<HistoricalV3TestRecipe>(stored)?;
            if artifact.recipe_sha256 != *artifact_sha256 {
                return Err(invalid(
                    "historical-v3 test recipe does not match its checkpoint",
                ));
            }
            validate_historical_v3_test_recipe(
                protocol,
                collection,
                &inputs.materialization,
                &inputs.source_census,
                &inputs.semantic_census,
                &inputs.qualification,
                &artifact,
            )
            .map_err(invalid)?;
            Ok(HistoricalV3TestRecipeStageRun::Selected {
                artifact: Box::new(artifact),
                resumed: true,
            })
        }
        HistoricalV3RankStageOutcome::Excluded {
            artifact_kind: HistoricalV3RankArtifactKind::TestRecipeExclusion,
            artifact_sha256,
        } => {
            let artifact = read_required::<HistoricalV3TestRecipeExclusion>(stored)?;
            if artifact.exclusion_sha256 != *artifact_sha256 {
                return Err(invalid(
                    "historical-v3 test recipe exclusion does not match its checkpoint",
                ));
            }
            validate_historical_v3_test_recipe_exclusion(
                protocol,
                collection,
                &inputs.materialization,
                &inputs.source_census,
                &inputs.semantic_census,
                &inputs.qualification,
                &artifact,
            )
            .map_err(invalid)?;
            Ok(HistoricalV3TestRecipeStageRun::Excluded {
                artifact: Box::new(artifact),
                resumed: true,
            })
        }
        _ => Err(invalid(
            "historical-v3 rank journal has an invalid test recipe outcome",
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
            "historical-v3 test recipe requires completed {label}"
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
        stage: HistoricalV3RankStage::TestRecipe,
        kind: HistoricalV3RankJournalErrorKind::InvalidInput,
        detail: detail.into(),
    }
}
