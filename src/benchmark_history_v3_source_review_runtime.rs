use super::super::history_v3_rank_journal::{materialized_roots, rank_workspace};
use super::super::{
    HistoricalV3CandidateCollection, HistoricalV3IdenticalTestOutcome, HistoricalV3Protocol,
    HistoricalV3RankJournal, HistoricalV3RankJournalError, HistoricalV3RankStage,
    HistoricalV3RankStageOutcome, HistoricalV3SourceReviewBundle, HistoricalV3SourceReviewInputs,
    HistoricalV3SourceReviewRoots, HistoricalV3SourceReviewStageRun, historical_v3_rank_identity,
    validate_historical_v3_identical_tests, validate_historical_v3_materialization,
    validate_historical_v3_mechanical_qualification, validate_historical_v3_test_recipe,
};
use super::commitment::{
    build_historical_v3_source_review_bundle, validate_historical_v3_source_review_bundle,
};
use super::store::{SourceReviewInputs, invalid, read_inputs};
use std::path::Path;

pub fn run_historical_v3_source_review_stage(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    stream_rank: usize,
    journal_root: &Path,
    workspace_root: &Path,
) -> Result<HistoricalV3SourceReviewStageRun, HistoricalV3RankJournalError> {
    let identity =
        historical_v3_rank_identity(protocol, collection, stream_rank).map_err(invalid)?;
    let mut journal = HistoricalV3RankJournal::open(journal_root, &identity)?;
    let inputs = read_inputs(journal.history())?;
    validate_inputs(protocol, collection, &inputs)?;
    let review_inputs = review_inputs(protocol, collection, &inputs);
    if let Some(stored) = journal.history().get(6) {
        let artifact = stored
            .read_artifact::<HistoricalV3SourceReviewBundle>()
            .map_err(invalid)?
            .ok_or_else(|| invalid("historical-v3 source-review checkpoint has no bundle"))?;
        validate_historical_v3_source_review_bundle(&review_inputs, &artifact).map_err(invalid)?;
        let HistoricalV3RankStageOutcome::ReadyForSourceReview { bundle_sha256 } =
            &stored.checkpoint.outcome
        else {
            return Err(invalid(
                "historical-v3 final checkpoint is not ready for source review",
            ));
        };
        if artifact.bundle_sha256 != *bundle_sha256 {
            return Err(invalid(
                "historical-v3 source-review bundle does not match its checkpoint",
            ));
        }
        return Ok(HistoricalV3SourceReviewStageRun {
            artifact: Box::new(artifact),
            resumed: true,
        });
    }
    if journal.next_stage() != Some(HistoricalV3RankStage::ReadyForSourceReview) {
        return Err(invalid(
            "historical-v3 rank is not open for source-review publication",
        ));
    }
    let destination = rank_workspace(workspace_root, &identity)?;
    let roots = materialized_roots(&destination);
    validate_historical_v3_materialization(protocol, collection, &inputs.materialization, &roots)
        .map_err(HistoricalV3RankJournalError::from)?;
    let review_roots = HistoricalV3SourceReviewRoots {
        base_root: &roots.base_root,
        merge_root: &roots.merge_root,
    };
    let artifact =
        build_historical_v3_source_review_bundle(&review_inputs, &review_roots).map_err(invalid)?;
    journal.append(
        HistoricalV3RankStage::ReadyForSourceReview,
        HistoricalV3RankStageOutcome::ReadyForSourceReview {
            bundle_sha256: artifact.bundle_sha256.clone(),
        },
        Some(&artifact),
    )?;
    Ok(HistoricalV3SourceReviewStageRun {
        artifact: Box::new(artifact),
        resumed: false,
    })
}

fn review_inputs<'a>(
    protocol: &'a HistoricalV3Protocol,
    collection: &'a HistoricalV3CandidateCollection,
    inputs: &'a SourceReviewInputs,
) -> HistoricalV3SourceReviewInputs<'a> {
    HistoricalV3SourceReviewInputs {
        protocol,
        collection,
        materialization: &inputs.materialization,
        source_census: &inputs.source_census,
        semantic_census: &inputs.semantic_census,
        qualification: &inputs.qualification,
        recipe: &inputs.recipe,
        execution: &inputs.execution,
    }
}

fn validate_inputs(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    inputs: &SourceReviewInputs,
) -> Result<(), HistoricalV3RankJournalError> {
    validate_historical_v3_mechanical_qualification(
        protocol,
        collection,
        &inputs.materialization,
        &inputs.source_census,
        &inputs.semantic_census,
        &inputs.qualification,
    )
    .map_err(invalid)?;
    validate_historical_v3_test_recipe(
        protocol,
        collection,
        &inputs.materialization,
        &inputs.source_census,
        &inputs.semantic_census,
        &inputs.qualification,
        &inputs.recipe,
    )
    .map_err(invalid)?;
    validate_historical_v3_identical_tests(protocol, &inputs.recipe, &inputs.execution)
        .map_err(invalid)?;
    if !matches!(
        inputs.execution.outcome,
        HistoricalV3IdenticalTestOutcome::Passed
    ) {
        return Err(invalid(
            "historical-v3 source review requires passing identical tests",
        ));
    }
    Ok(())
}
