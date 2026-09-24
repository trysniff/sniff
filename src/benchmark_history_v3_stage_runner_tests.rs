use super::super::history_v3_identical_tests::tests::passing_events;
use super::super::history_v3_label_review::tests::review_fixture;
use super::super::history_v3_semantic_census::tests as semantic_fixture;
use super::super::history_v3_test_recipe::tests::prepare_qualified_rank;
use super::super::{
    HistoricalV3IdenticalTestExecutionError, HistoricalV3IdenticalTestExecutionRequest,
    HistoricalV3IdenticalTestExecutor, HistoricalV3IdenticalTestOutcome, HistoricalV3NextStep,
    HistoricalV3RankStage, HistoricalV3RawIdenticalTestExecution, HistoricalV3ReplayProgress,
    HistoricalV3ReviewRecordPaths, HistoricalV3ReviewerVerdict, audit_historical_v3_label_reviews,
    prepare_historical_v3_label_resolution, replay_historical_v3_ordered_progress,
    resolve_historical_v3_label, write_historical_v3_final_label_new,
    write_historical_v3_label_audit_new, write_historical_v3_label_worksheet_new,
    write_historical_v3_resolution_worksheet_new,
};
use super::{HistoricalV3RunPaths, advance_historical_v3_ordered_step};
use std::cell::Cell;

struct UnexpectedExecutor;

impl HistoricalV3IdenticalTestExecutor for UnexpectedExecutor {
    fn recover(&self, _identity: &str) -> Result<(), HistoricalV3IdenticalTestExecutionError> {
        panic!("executor must not be called by this runner step")
    }

    fn execute(
        &self,
        _request: &HistoricalV3IdenticalTestExecutionRequest<'_>,
    ) -> Result<HistoricalV3RawIdenticalTestExecution, HistoricalV3IdenticalTestExecutionError>
    {
        panic!("executor must not be called by this runner step")
    }
}

struct OnceUnavailableExecutor {
    unavailable: Cell<bool>,
}

impl HistoricalV3IdenticalTestExecutor for OnceUnavailableExecutor {
    fn recover(&self, _identity: &str) -> Result<(), HistoricalV3IdenticalTestExecutionError> {
        Ok(())
    }

    fn execute(
        &self,
        request: &HistoricalV3IdenticalTestExecutionRequest<'_>,
    ) -> Result<HistoricalV3RawIdenticalTestExecution, HistoricalV3IdenticalTestExecutionError>
    {
        if self.unavailable.replace(false) {
            return Err(HistoricalV3IdenticalTestExecutionError::unavailable(
                "synthetic interrupted executor",
            ));
        }
        Ok(HistoricalV3RawIdenticalTestExecution {
            image_digest: request.recipe.image_digest.clone(),
            toolchain_manifest_sha256: request.recipe.toolchain_manifest_sha256.clone(),
            dependency_store_sha256: request.recipe.dependency_store_sha256.clone(),
            events: passing_events(request.recipe),
            outcome: HistoricalV3IdenticalTestOutcome::Passed,
        })
    }
}

#[tokio::test]
async fn resumes_local_census_and_retries_an_executor_outage() {
    let fixture = semantic_fixture::fixture();
    let protocol = semantic_fixture::protocol();
    let collection = semantic_fixture::collection(&protocol, &fixture);
    let language = collection.candidates[0].language;
    let journal = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let review = tempfile::tempdir().unwrap();
    let stop_path = review.path().join("stop.json");
    semantic_fixture::prepare_rank(
        &protocol,
        &collection,
        &fixture,
        journal.path(),
        workspace.path(),
    );
    let executor = OnceUnavailableExecutor {
        unavailable: Cell::new(true),
    };
    let replay = || {
        replay_historical_v3_ordered_progress(
            &protocol,
            &collection,
            language,
            journal.path(),
            review.path(),
            &stop_path,
        )
        .unwrap()
    };
    let advance = || {
        advance_historical_v3_ordered_step(
            &protocol,
            &collection,
            language,
            HistoricalV3RunPaths {
                journal_root: journal.path(),
                workspace_root: workspace.path(),
                review_root: review.path(),
                stop_path: &stop_path,
            },
            &executor,
        )
    };
    for expected in [
        HistoricalV3RankStage::MechanicalQualification,
        HistoricalV3RankStage::TestRecipe,
        HistoricalV3RankStage::IdenticalTests,
    ] {
        let progress = advance().await.unwrap();
        assert!(matches!(
            progress,
            HistoricalV3ReplayProgress::PendingRank {
                processed_ranks: 0,
                next: HistoricalV3NextStep::RankStage(stage),
                ..
            } if stage == expected
        ));
        assert_eq!(replay(), progress);
    }
    let before_outage = replay();
    assert!(
        advance()
            .await
            .unwrap_err()
            .contains("synthetic interrupted executor")
    );
    assert_eq!(replay(), before_outage);
    let after_retry = advance().await.unwrap();
    assert!(matches!(
        after_retry,
        HistoricalV3ReplayProgress::PendingRank {
            next: HistoricalV3NextStep::RankStage(HistoricalV3RankStage::ReadyForSourceReview),
            ..
        }
    ));
    assert_eq!(replay(), after_retry);
    let human = advance().await.unwrap();
    assert!(matches!(
        human,
        HistoricalV3ReplayProgress::PendingRank {
            next: HistoricalV3NextStep::HumanReview,
            ..
        }
    ));
    assert_eq!(replay(), human);
    assert!(
        advance()
            .await
            .unwrap_err()
            .contains("independent human review")
    );
}

#[tokio::test]
async fn advances_only_the_pending_test_recipe_stage() {
    let fixture = semantic_fixture::fixture();
    let protocol = semantic_fixture::protocol();
    let collection = semantic_fixture::collection(&protocol, &fixture);
    let journal = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let review = tempfile::tempdir().unwrap();
    prepare_qualified_rank(
        &protocol,
        &collection,
        &fixture,
        journal.path(),
        workspace.path(),
    )
    .await;
    let progress = advance_historical_v3_ordered_step(
        &protocol,
        &collection,
        collection.candidates[0].language,
        HistoricalV3RunPaths {
            journal_root: journal.path(),
            workspace_root: workspace.path(),
            review_root: review.path(),
            stop_path: &review.path().join("stop.json"),
        },
        &UnexpectedExecutor,
    )
    .await
    .unwrap();
    assert!(matches!(
        progress,
        HistoricalV3ReplayProgress::PendingRank {
            processed_ranks: 0,
            next: HistoricalV3NextStep::RankStage(HistoricalV3RankStage::IdenticalTests),
            ..
        }
    ));
}

#[tokio::test]
async fn human_review_requires_an_independent_decision() {
    let fixture = review_fixture().await;
    let inputs = fixture.inputs();
    let workspace = tempfile::tempdir().unwrap();
    let review = tempfile::tempdir().unwrap();
    let error = advance_historical_v3_ordered_step(
        inputs.protocol,
        inputs.collection,
        inputs.qualification.rank.language(),
        HistoricalV3RunPaths {
            journal_root: fixture.journal_path(),
            workspace_root: workspace.path(),
            review_root: review.path(),
            stop_path: &review.path().join("stop.json"),
        },
        &UnexpectedExecutor,
    )
    .await
    .unwrap_err();
    assert!(error.contains("independent human review"));
}

#[tokio::test]
async fn publishes_and_replays_the_verified_stop() {
    let fixture = review_fixture().await;
    let inputs = fixture.inputs();
    let workspace = tempfile::tempdir().unwrap();
    let review = tempfile::tempdir().unwrap();
    let paths = HistoricalV3ReviewRecordPaths::new(review.path(), &inputs.qualification.rank);
    let worksheets = [
        fixture.worksheet("reviewer-a", HistoricalV3ReviewerVerdict::Slop),
        fixture.worksheet("reviewer-b", HistoricalV3ReviewerVerdict::Slop),
    ];
    let audit = audit_historical_v3_label_reviews(&inputs, &fixture.bundle, &worksheets).unwrap();
    let resolution =
        prepare_historical_v3_label_resolution(&inputs, &fixture.bundle, &worksheets, &audit)
            .unwrap();
    let label =
        resolve_historical_v3_label(&inputs, &fixture.bundle, &worksheets, &audit, &resolution)
            .unwrap();
    std::fs::create_dir_all(paths.audit.parent().unwrap()).unwrap();
    write_historical_v3_label_worksheet_new(&paths.reviewer_one, &worksheets[0]).unwrap();
    write_historical_v3_label_worksheet_new(&paths.reviewer_two, &worksheets[1]).unwrap();
    write_historical_v3_label_audit_new(&paths.audit, &audit).unwrap();
    write_historical_v3_resolution_worksheet_new(&paths.resolution, &resolution).unwrap();
    write_historical_v3_final_label_new(&paths.final_label, &label).unwrap();
    let stop_path = review.path().join("stop.json");
    let advance = || {
        advance_historical_v3_ordered_step(
            inputs.protocol,
            inputs.collection,
            inputs.qualification.rank.language(),
            HistoricalV3RunPaths {
                journal_root: fixture.journal_path(),
                workspace_root: workspace.path(),
                review_root: review.path(),
                stop_path: &stop_path,
            },
            &UnexpectedExecutor,
        )
    };
    let first = advance().await.unwrap();
    assert!(matches!(first, HistoricalV3ReplayProgress::Terminal { .. }));
    assert!(stop_path.is_file());
    assert_eq!(advance().await.unwrap(), first);
}
