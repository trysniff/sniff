use super::super::history_v3_candidate_collection::seal_collection_manifest;
use super::super::history_v3_identical_tests::tests::passing_events;
use super::super::history_v3_label_review::tests::review_worksheet;
use super::super::history_v3_semantic_census::tests as semantic_fixture;
use super::super::{
    HistoricalV3CandidateCollection, HistoricalV3IdenticalTestExecutionError,
    HistoricalV3IdenticalTestExecutionRequest, HistoricalV3IdenticalTestExecutor,
    HistoricalV3IdenticalTestOutcome, HistoricalV3IdenticalTests, HistoricalV3Materialization,
    HistoricalV3MechanicalQualification, HistoricalV3NextStep, HistoricalV3Protocol,
    HistoricalV3RankJournal, HistoricalV3RawIdenticalTestExecution, HistoricalV3ReplayProgress,
    HistoricalV3ReviewRecordPaths, HistoricalV3ReviewerVerdict, HistoricalV3SemanticCensus,
    HistoricalV3SourceCensus, HistoricalV3SourceReviewInputs, HistoricalV3TestRecipe,
    audit_historical_v3_label_reviews, historical_v3_rank_identity,
    prepare_historical_v3_label_resolution, prepare_historical_v3_stream_task,
    replay_historical_v3_ordered_progress, resolve_historical_v3_label,
    run_historical_v3_identical_tests_stage, run_historical_v3_mechanical_qualification_stage,
    run_historical_v3_source_review_stage, run_historical_v3_test_recipe_stage,
    write_historical_v3_final_label_new, write_historical_v3_label_audit_new,
    write_historical_v3_label_worksheet_new, write_historical_v3_resolution_worksheet_new,
};
use super::{HistoricalV3RunPaths, advance_historical_v3_ordered_step};
use std::path::Path;

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

fn nine_rank_collection(
    protocol: &HistoricalV3Protocol,
    fixture: &semantic_fixture::GitFixture,
) -> HistoricalV3CandidateCollection {
    let mut collection = semantic_fixture::collection(protocol, fixture);
    let identity = collection.candidates[0].clone();
    collection.candidates = (1..=9)
        .map(|pull_request_number| {
            let mut candidate = identity.clone();
            candidate.pull_request_number = pull_request_number;
            candidate
        })
        .collect();
    collection.manifest.candidate_count = collection.candidates.len();
    collection.manifest.stream_task =
        prepare_historical_v3_stream_task(protocol, collection.candidates.clone()).unwrap();
    collection.manifest = seal_collection_manifest(collection.manifest).unwrap();
    collection
}

async fn complete_review_rank(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    fixture: &semantic_fixture::GitFixture,
    stream_rank: usize,
    journal_root: &Path,
    workspace_root: &Path,
    review_root: &Path,
) {
    semantic_fixture::prepare_rank_at(
        protocol,
        collection,
        fixture,
        stream_rank,
        journal_root,
        workspace_root,
    );
    semantic_fixture::prepare_semantic_rank_at(
        protocol,
        collection,
        stream_rank,
        journal_root,
        workspace_root,
    )
    .await;
    run_historical_v3_mechanical_qualification_stage(
        protocol,
        collection,
        stream_rank,
        journal_root,
    )
    .unwrap();
    run_historical_v3_test_recipe_stage(protocol, collection, stream_rank, journal_root).unwrap();
    run_historical_v3_identical_tests_stage(
        protocol,
        collection,
        stream_rank,
        journal_root,
        workspace_root,
        &PassingExecutor,
    )
    .unwrap();
    let source_review = run_historical_v3_source_review_stage(
        protocol,
        collection,
        stream_rank,
        journal_root,
        workspace_root,
    )
    .unwrap();
    let rank = historical_v3_rank_identity(protocol, collection, stream_rank).unwrap();
    let journal = HistoricalV3RankJournal::open(journal_root, &rank).unwrap();
    let history = journal.history();
    let materialization: HistoricalV3Materialization = history[0].read_artifact().unwrap().unwrap();
    let source_census: HistoricalV3SourceCensus = history[1].read_artifact().unwrap().unwrap();
    let semantic_census: HistoricalV3SemanticCensus = history[2].read_artifact().unwrap().unwrap();
    let qualification: HistoricalV3MechanicalQualification =
        history[3].read_artifact().unwrap().unwrap();
    let recipe: HistoricalV3TestRecipe = history[4].read_artifact().unwrap().unwrap();
    let execution: HistoricalV3IdenticalTests = history[5].read_artifact().unwrap().unwrap();
    let inputs = HistoricalV3SourceReviewInputs {
        protocol,
        collection,
        materialization: &materialization,
        source_census: &source_census,
        semantic_census: &semantic_census,
        qualification: &qualification,
        recipe: &recipe,
        execution: &execution,
    };
    let worksheets = [
        review_worksheet(
            &inputs,
            &source_review.artifact,
            "reviewer-a",
            HistoricalV3ReviewerVerdict::Clean,
        ),
        review_worksheet(
            &inputs,
            &source_review.artifact,
            "reviewer-b",
            HistoricalV3ReviewerVerdict::Clean,
        ),
    ];
    let audit =
        audit_historical_v3_label_reviews(&inputs, &source_review.artifact, &worksheets).unwrap();
    let resolution = prepare_historical_v3_label_resolution(
        &inputs,
        &source_review.artifact,
        &worksheets,
        &audit,
    )
    .unwrap();
    let label = resolve_historical_v3_label(
        &inputs,
        &source_review.artifact,
        &worksheets,
        &audit,
        &resolution,
    )
    .unwrap();
    let paths = HistoricalV3ReviewRecordPaths::new(review_root, &rank);
    std::fs::create_dir_all(paths.audit.parent().unwrap()).unwrap();
    write_historical_v3_label_worksheet_new(&paths.reviewer_one, &worksheets[0]).unwrap();
    write_historical_v3_label_worksheet_new(&paths.reviewer_two, &worksheets[1]).unwrap();
    write_historical_v3_label_audit_new(&paths.audit, &audit).unwrap();
    write_historical_v3_resolution_worksheet_new(&paths.resolution, &resolution).unwrap();
    write_historical_v3_final_label_new(&paths.final_label, &label).unwrap();
}

#[tokio::test]
async fn ninth_qualified_rank_publishes_cap_from_eight_persisted_reviews() {
    let fixture = semantic_fixture::fixture();
    for pull_request_number in 1..=9 {
        fixture.add_pull_ref(pull_request_number);
    }
    let protocol = semantic_fixture::protocol();
    let collection = nine_rank_collection(&protocol, &fixture);
    let language = collection.candidates[0].language;
    let journal = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let review = tempfile::tempdir().unwrap();
    let stop_path = review.path().join("stop.json");
    for stream_rank in 1..=8 {
        complete_review_rank(
            &protocol,
            &collection,
            &fixture,
            stream_rank,
            journal.path(),
            workspace.path(),
            review.path(),
        )
        .await;
    }
    semantic_fixture::prepare_rank_at(
        &protocol,
        &collection,
        &fixture,
        9,
        journal.path(),
        workspace.path(),
    );
    semantic_fixture::prepare_semantic_rank_at(
        &protocol,
        &collection,
        9,
        journal.path(),
        workspace.path(),
    )
    .await;
    run_historical_v3_mechanical_qualification_stage(&protocol, &collection, 9, journal.path())
        .unwrap();
    let replay = || {
        replay_historical_v3_ordered_progress(
            &protocol,
            &collection,
            language,
            journal.path(),
            review.path(),
            &stop_path,
        )
    };
    assert!(matches!(
        replay().unwrap(),
        HistoricalV3ReplayProgress::PendingRank {
            processed_ranks: 8,
            next: HistoricalV3NextStep::RepositoryReviewCap,
            ..
        }
    ));
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
            &PassingExecutor,
        )
    };
    let after_cap = advance().await.unwrap();
    assert!(matches!(
        after_cap,
        HistoricalV3ReplayProgress::AwaitingStopPublication { .. }
    ));
    let cap = HistoricalV3ReviewRecordPaths::new(
        review.path(),
        &historical_v3_rank_identity(&protocol, &collection, 9).unwrap(),
    )
    .cap;
    assert!(cap.is_file());
    assert_eq!(replay().unwrap(), after_cap);
    let terminal = advance().await.unwrap();
    assert!(matches!(
        terminal,
        HistoricalV3ReplayProgress::Terminal { .. }
    ));
    assert_eq!(replay().unwrap(), terminal);
    std::fs::write(&cap, b"{}").unwrap();
    assert!(replay().is_err());
    std::fs::remove_file(cap).unwrap();
    assert!(replay().is_err());
}
