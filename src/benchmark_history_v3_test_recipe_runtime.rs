use super::super::{
    HistoricalV3CandidateCollection, HistoricalV3Protocol, HistoricalV3RankArtifactKind,
    HistoricalV3RankJournal, HistoricalV3RankJournalError, HistoricalV3RankStage,
    HistoricalV3RankStageOutcome, HistoricalV3TestRecipeOutcome, HistoricalV3TestRecipeStageRun,
    derive_historical_v3_test_recipe, historical_v3_rank_identity,
};
use super::store::{TestRecipeInputs, invalid, read_inputs, resume};
use std::path::Path;

pub fn run_historical_v3_test_recipe_stage(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    stream_rank: usize,
    journal_root: &Path,
) -> Result<HistoricalV3TestRecipeStageRun, HistoricalV3RankJournalError> {
    run_historical_v3_test_recipe_stage_with(
        protocol,
        collection,
        stream_rank,
        journal_root,
        |inputs| {
            derive_historical_v3_test_recipe(
                protocol,
                collection,
                &inputs.materialization,
                &inputs.source_census,
                &inputs.semantic_census,
                &inputs.qualification,
            )
            .map_err(invalid)
        },
    )
}

pub(super) fn run_historical_v3_test_recipe_stage_with<F>(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    stream_rank: usize,
    journal_root: &Path,
    derive: F,
) -> Result<HistoricalV3TestRecipeStageRun, HistoricalV3RankJournalError>
where
    F: FnOnce(
        &TestRecipeInputs,
    ) -> Result<HistoricalV3TestRecipeOutcome, HistoricalV3RankJournalError>,
{
    let identity =
        historical_v3_rank_identity(protocol, collection, stream_rank).map_err(invalid)?;
    let mut journal = HistoricalV3RankJournal::open(journal_root, &identity)?;
    let inputs = read_inputs(journal.history())?;
    if let Some(stored) = journal.history().get(4) {
        return resume(protocol, collection, &inputs, stored);
    }
    if journal.next_stage() != Some(HistoricalV3RankStage::TestRecipe) {
        return Err(invalid("historical-v3 rank is not open for test recipe"));
    }
    match derive(&inputs)? {
        HistoricalV3TestRecipeOutcome::Selected(artifact) => {
            super::super::validate_historical_v3_test_recipe(
                protocol,
                collection,
                &inputs.materialization,
                &inputs.source_census,
                &inputs.semantic_census,
                &inputs.qualification,
                &artifact,
            )
            .map_err(invalid)?;
            journal.append(
                HistoricalV3RankStage::TestRecipe,
                HistoricalV3RankStageOutcome::Completed {
                    artifact_kind: HistoricalV3RankArtifactKind::TestRecipe,
                    artifact_sha256: artifact.recipe_sha256.clone(),
                },
                Some(artifact.as_ref()),
            )?;
            Ok(HistoricalV3TestRecipeStageRun::Selected {
                artifact,
                resumed: false,
            })
        }
        HistoricalV3TestRecipeOutcome::Excluded(artifact) => {
            super::super::validate_historical_v3_test_recipe_exclusion(
                protocol,
                collection,
                &inputs.materialization,
                &inputs.source_census,
                &inputs.semantic_census,
                &inputs.qualification,
                &artifact,
            )
            .map_err(invalid)?;
            journal.append(
                HistoricalV3RankStage::TestRecipe,
                HistoricalV3RankStageOutcome::Excluded {
                    artifact_kind: HistoricalV3RankArtifactKind::TestRecipeExclusion,
                    artifact_sha256: artifact.exclusion_sha256.clone(),
                },
                Some(artifact.as_ref()),
            )?;
            Ok(HistoricalV3TestRecipeStageRun::Excluded {
                artifact,
                resumed: false,
            })
        }
    }
}
