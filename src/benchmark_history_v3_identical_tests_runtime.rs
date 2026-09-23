use super::super::history_v3_rank_journal::{materialized_roots, rank_workspace};
use super::super::{
    HistoricalV3CandidateCollection, HistoricalV3IdenticalTestExecutionError,
    HistoricalV3IdenticalTestExecutionErrorKind, HistoricalV3IdenticalTestExecutionRequest,
    HistoricalV3IdenticalTestExecutor, HistoricalV3IdenticalTestOutcome,
    HistoricalV3IdenticalTestsStageRun, HistoricalV3Protocol, HistoricalV3RankArtifactKind,
    HistoricalV3RankJournal, HistoricalV3RankJournalError, HistoricalV3RankJournalErrorKind,
    HistoricalV3RankStage, HistoricalV3RankStageOutcome, historical_v3_execution_identity_sha256,
    historical_v3_rank_identity, validate_historical_v3_identical_tests,
    validate_historical_v3_materialization, validate_historical_v3_test_recipe,
};
use super::commitment::seal_execution;
use super::store::{IdenticalTestInputs, invalid, read_inputs};
use std::path::Path;

pub fn run_historical_v3_identical_tests_stage<E: HistoricalV3IdenticalTestExecutor>(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    stream_rank: usize,
    journal_root: &Path,
    workspace_root: &Path,
    executor: &E,
) -> Result<HistoricalV3IdenticalTestsStageRun, HistoricalV3RankJournalError> {
    let identity =
        historical_v3_rank_identity(protocol, collection, stream_rank).map_err(invalid)?;
    let mut journal = HistoricalV3RankJournal::open(journal_root, &identity)?;
    let inputs = read_inputs(journal.history())?;
    validate_inputs(protocol, collection, &inputs)?;
    if let Some(stored) = journal.history().get(5) {
        let artifact = stored
            .read_artifact()
            .map_err(invalid)?
            .ok_or_else(|| invalid("historical-v3 identical-test checkpoint has no artifact"))?;
        validate_historical_v3_identical_tests(protocol, &inputs.recipe, &artifact)
            .map_err(invalid)?;
        return resumed(stored, artifact);
    }
    if journal.next_stage() != Some(HistoricalV3RankStage::IdenticalTests) {
        return Err(invalid(
            "historical-v3 rank is not open for identical tests",
        ));
    }
    let destination = rank_workspace(workspace_root, &identity)?;
    let roots = materialized_roots(&destination);
    validate_historical_v3_materialization(protocol, collection, &inputs.materialization, &roots)
        .map_err(HistoricalV3RankJournalError::from)?;
    let execution_identity_sha256 =
        historical_v3_execution_identity_sha256(protocol, &inputs.recipe).map_err(invalid)?;
    executor
        .recover(&execution_identity_sha256)
        .map_err(map_execution_error)?;
    let raw = executor
        .execute(&HistoricalV3IdenticalTestExecutionRequest {
            execution_identity_sha256: &execution_identity_sha256,
            recipe: &inputs.recipe,
            base_root: &roots.base_root,
            merge_root: &roots.merge_root,
            policy: &protocol.identical_test_policy,
        })
        .map_err(map_execution_error)?;
    let artifact = seal_execution(protocol, &inputs.recipe, raw).map_err(invalid)?;
    validate_historical_v3_identical_tests(protocol, &inputs.recipe, &artifact).map_err(invalid)?;
    let (outcome, passed) = match artifact.outcome {
        HistoricalV3IdenticalTestOutcome::Passed => (
            HistoricalV3RankStageOutcome::Completed {
                artifact_kind: HistoricalV3RankArtifactKind::IdenticalTests,
                artifact_sha256: artifact.execution_sha256.clone(),
            },
            true,
        ),
        HistoricalV3IdenticalTestOutcome::Excluded { .. } => (
            HistoricalV3RankStageOutcome::Excluded {
                artifact_kind: HistoricalV3RankArtifactKind::IdenticalTestsExclusion,
                artifact_sha256: artifact.execution_sha256.clone(),
            },
            false,
        ),
    };
    journal.append(
        HistoricalV3RankStage::IdenticalTests,
        outcome,
        Some(&artifact),
    )?;
    if passed {
        Ok(HistoricalV3IdenticalTestsStageRun::Passed {
            artifact: Box::new(artifact),
            resumed: false,
        })
    } else {
        Ok(HistoricalV3IdenticalTestsStageRun::Excluded {
            artifact: Box::new(artifact),
            resumed: false,
        })
    }
}

fn validate_inputs(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    inputs: &IdenticalTestInputs,
) -> Result<(), HistoricalV3RankJournalError> {
    validate_historical_v3_test_recipe(
        protocol,
        collection,
        &inputs.materialization,
        &inputs.source_census,
        &inputs.semantic_census,
        &inputs.qualification,
        &inputs.recipe,
    )
    .map_err(invalid)
}

fn resumed(
    stored: &super::super::HistoricalV3StoredRankStage,
    artifact: super::HistoricalV3IdenticalTests,
) -> Result<HistoricalV3IdenticalTestsStageRun, HistoricalV3RankJournalError> {
    let checkpoint_sha256 = match &stored.checkpoint.outcome {
        HistoricalV3RankStageOutcome::Completed {
            artifact_sha256, ..
        }
        | HistoricalV3RankStageOutcome::Excluded {
            artifact_sha256, ..
        } => artifact_sha256,
        HistoricalV3RankStageOutcome::ReadyForSourceReview { .. } => {
            return Err(invalid(
                "historical-v3 identical-test checkpoint has no artifact identity",
            ));
        }
    };
    if artifact.execution_sha256 != *checkpoint_sha256 {
        return Err(invalid(
            "historical-v3 identical tests do not match their checkpoint",
        ));
    }
    match (&stored.checkpoint.outcome, &artifact.outcome) {
        (
            HistoricalV3RankStageOutcome::Completed {
                artifact_kind: HistoricalV3RankArtifactKind::IdenticalTests,
                ..
            },
            HistoricalV3IdenticalTestOutcome::Passed,
        ) => Ok(HistoricalV3IdenticalTestsStageRun::Passed {
            artifact: Box::new(artifact),
            resumed: true,
        }),
        (
            HistoricalV3RankStageOutcome::Excluded {
                artifact_kind: HistoricalV3RankArtifactKind::IdenticalTestsExclusion,
                ..
            },
            HistoricalV3IdenticalTestOutcome::Excluded { .. },
        ) => Ok(HistoricalV3IdenticalTestsStageRun::Excluded {
            artifact: Box::new(artifact),
            resumed: true,
        }),
        _ => Err(invalid(
            "historical-v3 identical-test outcome changed its checkpoint kind",
        )),
    }
}

fn map_execution_error(
    error: HistoricalV3IdenticalTestExecutionError,
) -> HistoricalV3RankJournalError {
    HistoricalV3RankJournalError {
        stage: HistoricalV3RankStage::IdenticalTests,
        kind: match error.kind {
            HistoricalV3IdenticalTestExecutionErrorKind::InvalidInput => {
                HistoricalV3RankJournalErrorKind::InvalidInput
            }
            HistoricalV3IdenticalTestExecutionErrorKind::InfrastructureUnavailable => {
                HistoricalV3RankJournalErrorKind::InfrastructureUnavailable
            }
            HistoricalV3IdenticalTestExecutionErrorKind::InfrastructureFailed => {
                HistoricalV3RankJournalErrorKind::InfrastructureFailed
            }
        },
        detail: error.detail,
    }
}
