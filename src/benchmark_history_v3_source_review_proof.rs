use super::super::{
    HistoricalV3CandidateCollection, HistoricalV3Protocol, HistoricalV3RankArtifactKind,
    HistoricalV3RankIdentity, HistoricalV3RankJournal, HistoricalV3RankJournalError,
    HistoricalV3RankStageOutcome, HistoricalV3StoredRankStage, historical_v3_rank_identity,
};
use super::store::{SourceReviewInputs, invalid, read_inputs};
use super::{HistoricalV3SourceReviewBundle, HistoricalV3SourceReviewInputs};
use std::path::Path;

pub struct HistoricalV3VerifiedSourceReview {
    rank: HistoricalV3RankIdentity,
    inputs: SourceReviewInputs,
    bundle: HistoricalV3SourceReviewBundle,
}

impl HistoricalV3VerifiedSourceReview {
    pub fn rank(&self) -> &HistoricalV3RankIdentity {
        &self.rank
    }

    pub fn bundle(&self) -> &HistoricalV3SourceReviewBundle {
        &self.bundle
    }

    pub fn inputs<'a>(
        &'a self,
        protocol: &'a HistoricalV3Protocol,
        collection: &'a HistoricalV3CandidateCollection,
    ) -> HistoricalV3SourceReviewInputs<'a> {
        HistoricalV3SourceReviewInputs {
            protocol,
            collection,
            materialization: &self.inputs.materialization,
            source_census: &self.inputs.source_census,
            semantic_census: &self.inputs.semantic_census,
            qualification: &self.inputs.qualification,
            recipe: &self.inputs.recipe,
            execution: &self.inputs.execution,
        }
    }
}

pub fn verify_historical_v3_source_review_rank(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    stream_rank: usize,
    journal_root: &Path,
) -> Result<HistoricalV3VerifiedSourceReview, HistoricalV3RankJournalError> {
    let rank = historical_v3_rank_identity(protocol, collection, stream_rank).map_err(invalid)?;
    let journal = HistoricalV3RankJournal::open(journal_root, &rank)?;
    let history = journal.history();
    if history.len() != 7 {
        return Err(invalid(
            "historical-v3 source-review rank requires exactly seven committed stages",
        ));
    }
    let inputs = read_inputs(history)?;
    for (stored, kind, logical_sha256) in [
        (
            &history[0],
            HistoricalV3RankArtifactKind::Materialization,
            inputs.materialization.materialization_sha256.as_str(),
        ),
        (
            &history[1],
            HistoricalV3RankArtifactKind::SourceCensus,
            inputs.source_census.source_census_sha256.as_str(),
        ),
        (
            &history[2],
            HistoricalV3RankArtifactKind::SemanticCensus,
            inputs.semantic_census.semantic_census_sha256.as_str(),
        ),
        (
            &history[3],
            HistoricalV3RankArtifactKind::MechanicalQualification,
            inputs.qualification.qualification_sha256.as_str(),
        ),
        (
            &history[4],
            HistoricalV3RankArtifactKind::TestRecipe,
            inputs.recipe.recipe_sha256.as_str(),
        ),
        (
            &history[5],
            HistoricalV3RankArtifactKind::IdenticalTests,
            inputs.execution.execution_sha256.as_str(),
        ),
    ] {
        require_completed_hash(stored, kind, logical_sha256)?;
    }
    let bundle = history[6]
        .read_artifact::<HistoricalV3SourceReviewBundle>()
        .map_err(invalid)?
        .ok_or_else(|| invalid("historical-v3 source-review bundle is missing"))?;
    let HistoricalV3RankStageOutcome::ReadyForSourceReview { bundle_sha256 } =
        &history[6].checkpoint.outcome
    else {
        return Err(invalid(
            "historical-v3 final rank stage is not source review",
        ));
    };
    if bundle_sha256 != &bundle.bundle_sha256 {
        return Err(invalid(
            "historical-v3 source-review checkpoint hash changed",
        ));
    }
    let proof = HistoricalV3VerifiedSourceReview {
        rank,
        inputs,
        bundle,
    };
    super::validate_historical_v3_source_review_bundle(
        &proof.inputs(protocol, collection),
        proof.bundle(),
    )
    .map_err(invalid)?;
    Ok(proof)
}

fn require_completed_hash(
    stored: &HistoricalV3StoredRankStage,
    kind: HistoricalV3RankArtifactKind,
    logical_sha256: &str,
) -> Result<(), HistoricalV3RankJournalError> {
    match &stored.checkpoint.outcome {
        HistoricalV3RankStageOutcome::Completed {
            artifact_kind,
            artifact_sha256,
        } if *artifact_kind == kind && artifact_sha256 == logical_sha256 => Ok(()),
        _ => Err(invalid(
            "historical-v3 source-review prior stage differs from its checkpoint",
        )),
    }
}
