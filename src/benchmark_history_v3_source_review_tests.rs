use super::super::history_v3_identical_tests::tests::{passing_events, prepared_rank};
use super::super::history_v3_rank_journal::rank_workspace;
use super::super::{
    HistoricalV3ExecutionSide, HistoricalV3IdenticalTestExclusionReason,
    HistoricalV3IdenticalTestExecutionError, HistoricalV3IdenticalTestExecutionRequest,
    HistoricalV3IdenticalTestExecutor, HistoricalV3IdenticalTestOutcome, HistoricalV3RankJournal,
    HistoricalV3RawIdenticalTestExecution, HistoricalV3SourceReviewInputs,
    historical_v3_rank_identity, run_historical_v3_identical_tests_stage,
};
use super::{
    run_historical_v3_source_review_stage, validate_historical_v3_source_review_bundle,
    verify_historical_v3_source_review_rank,
};
use std::fs;

struct PassingExecutor;

impl HistoricalV3IdenticalTestExecutor for PassingExecutor {
    fn recover(&self, _identity: &str) -> Result<(), HistoricalV3IdenticalTestExecutionError> {
        Ok(())
    }

    fn execute(
        &self,
        request: &HistoricalV3IdenticalTestExecutionRequest<'_>,
    ) -> Result<HistoricalV3RawIdenticalTestExecution, HistoricalV3IdenticalTestExecutionError>
    {
        Ok(HistoricalV3RawIdenticalTestExecution {
            image_digest: request.recipe.image_digest.clone(),
            toolchain_manifest_sha256: request.recipe.toolchain_manifest_sha256.clone(),
            dependency_store_sha256: request.recipe.dependency_store_sha256.clone(),
            events: passing_events(request.recipe),
            outcome: HistoricalV3IdenticalTestOutcome::Passed,
        })
    }
}

struct ExcludingExecutor;

impl HistoricalV3IdenticalTestExecutor for ExcludingExecutor {
    fn recover(&self, _identity: &str) -> Result<(), HistoricalV3IdenticalTestExecutionError> {
        Ok(())
    }

    fn execute(
        &self,
        request: &HistoricalV3IdenticalTestExecutionRequest<'_>,
    ) -> Result<HistoricalV3RawIdenticalTestExecution, HistoricalV3IdenticalTestExecutionError>
    {
        let mut events = passing_events(request.recipe);
        let mut event = events.remove(0);
        event.exit_code = Some(1);
        Ok(HistoricalV3RawIdenticalTestExecution {
            image_digest: request.recipe.image_digest.clone(),
            toolchain_manifest_sha256: request.recipe.toolchain_manifest_sha256.clone(),
            dependency_store_sha256: request.recipe.dependency_store_sha256.clone(),
            events: vec![event],
            outcome: HistoricalV3IdenticalTestOutcome::Excluded {
                reason: HistoricalV3IdenticalTestExclusionReason::PreparationFailed {
                    side: HistoricalV3ExecutionSide::Base,
                    command_index: 0,
                },
            },
        })
    }
}

#[tokio::test]
async fn commits_blind_bundle_rejects_rehashed_semantic_tamper_and_resumes_without_git() {
    let (fixture, protocol, collection, journal, workspace, _) = prepared_rank().await;
    let execution = run_historical_v3_identical_tests_stage(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
        &PassingExecutor,
    )
    .unwrap();
    assert!(
        verify_historical_v3_source_review_rank(&protocol, &collection, 1, journal.path(),)
            .is_err()
    );
    let first = run_historical_v3_source_review_stage(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
    )
    .unwrap();
    let proof =
        verify_historical_v3_source_review_rank(&protocol, &collection, 1, journal.path()).unwrap();
    assert_eq!(proof.bundle(), first.artifact.as_ref());
    assert_eq!(
        proof.inputs(&protocol, &collection).qualification.rank,
        proof.rank().clone()
    );
    assert!(!first.resumed);
    assert!(first.artifact.source_only);
    assert!(!first.artifact.repository_identity_included);
    assert!(!first.artifact.change_metadata_included);
    assert!(!first.artifact.sniff_output_included);
    assert!(!first.artifact.prior_labels_included);
    assert!(!first.artifact.methods.is_empty());
    let encoded = serde_json::to_string(&first.artifact).unwrap();
    assert!(!encoded.contains("name_with_owner"));
    assert!(!encoded.contains("pull_request_number"));
    assert!(!encoded.contains("retained_stdout_base64"));
    assert!(!encoded.contains("retained_stderr_base64"));

    let mut tampered = (*first.artifact).clone();
    tampered.methods[0].semantic.symbol_name = "forged".to_string();
    tampered = super::commitment::seal_source_review_bundle(tampered).unwrap();
    let inputs = super::store::read_inputs(
        HistoricalV3RankJournal::open(
            journal.path(),
            &historical_v3_rank_identity(&protocol, &collection, 1).unwrap(),
        )
        .unwrap()
        .history(),
    )
    .unwrap();
    let review_inputs = HistoricalV3SourceReviewInputs {
        protocol: &protocol,
        collection: &collection,
        materialization: &inputs.materialization,
        source_census: &inputs.source_census,
        semantic_census: &inputs.semantic_census,
        qualification: &inputs.qualification,
        recipe: &inputs.recipe,
        execution: &inputs.execution,
    };
    assert!(
        validate_historical_v3_source_review_bundle(&review_inputs, &tampered)
            .unwrap_err()
            .contains("method changed")
    );

    let identity = historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let destination = rank_workspace(workspace.path(), &identity).unwrap();
    fs::rename(
        destination.join("repository/.git"),
        destination.join("repository/.git-disabled"),
    )
    .unwrap();
    let resumed = run_historical_v3_source_review_stage(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
    )
    .unwrap();
    assert!(resumed.resumed);
    assert_eq!(resumed.artifact, first.artifact);
    let persisted = HistoricalV3RankJournal::open(journal.path(), &identity).unwrap();
    assert_eq!(persisted.history().len(), 7);
    assert_eq!(persisted.next_stage(), None);
    assert!(matches!(
        execution,
        super::super::HistoricalV3IdenticalTestsStageRun::Passed { .. }
    ));
    drop(fixture);
}

#[tokio::test]
async fn excluded_identical_tests_cannot_publish_a_source_review_bundle() {
    let (_fixture, protocol, collection, journal, workspace, _) = prepared_rank().await;
    run_historical_v3_identical_tests_stage(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
        &ExcludingExecutor,
    )
    .unwrap();
    let error = run_historical_v3_source_review_stage(
        &protocol,
        &collection,
        1,
        journal.path(),
        workspace.path(),
    )
    .unwrap_err();
    assert!(error.detail.contains("requires completed identical tests"));
}
