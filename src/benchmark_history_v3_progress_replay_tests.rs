use super::super::history_v3_candidate_collection::seal_collection_manifest;
use super::super::history_v3_label_review::tests::review_fixture;
use super::super::history_v3_rank_journal::historical_v3_rank_journal_path;
use super::super::history_v3_semantic_census::tests as semantic_fixture;
use super::super::history_v3_test_recipe::tests::prepare_qualified_rank;
use super::super::{
    HistoricalV3NextStep, HistoricalV3RankStage, HistoricalV3ReplayProgress,
    HistoricalV3ReviewRecordPaths, HistoricalV3ReviewerVerdict, audit_historical_v3_label_reviews,
    historical_v3_rank_identity, prepare_historical_v3_label_resolution,
    prepare_historical_v3_stream_task, resolve_historical_v3_label,
    write_historical_v3_final_label_new, write_historical_v3_label_audit_new,
    write_historical_v3_label_worksheet_new, write_historical_v3_resolution_worksheet_new,
    write_historical_v3_stop_artifact_new,
};
use super::replay_historical_v3_ordered_progress;

#[test]
fn empty_journal_is_pending_not_clean_or_terminal() {
    let fixture = semantic_fixture::fixture();
    let protocol = semantic_fixture::protocol();
    let collection = semantic_fixture::collection(&protocol, &fixture);
    let journal = tempfile::tempdir().unwrap();
    let review = tempfile::tempdir().unwrap();
    let language = collection.candidates[0].language;
    let progress = replay_historical_v3_ordered_progress(
        &protocol,
        &collection,
        language,
        journal.path(),
        review.path(),
        &review.path().join("stop.json"),
    )
    .unwrap();
    assert!(matches!(
        progress,
        HistoricalV3ReplayProgress::PendingRank {
            processed_ranks: 0,
            next: HistoricalV3NextStep::RankStage(HistoricalV3RankStage::Materialization),
            ..
        }
    ));
    let stop_path = review.path().join("stop.json");
    std::fs::write(&stop_path, b"{}").unwrap();
    assert!(
        replay_historical_v3_ordered_progress(
            &protocol,
            &collection,
            language,
            journal.path(),
            review.path(),
            &stop_path,
        )
        .unwrap_err()
        .contains("before the prefix is terminal")
    );
}

#[test]
fn later_rank_state_cannot_hide_behind_a_missing_earlier_rank() {
    let fixture = semantic_fixture::fixture();
    let protocol = semantic_fixture::protocol();
    let mut collection = semantic_fixture::collection(&protocol, &fixture);
    let first = collection.candidates[0].clone();
    let mut second = first.clone();
    second.pull_request_number += 1;
    collection.candidates = vec![first, second];
    collection.manifest.candidate_count = collection.candidates.len();
    collection.manifest.stream_task =
        prepare_historical_v3_stream_task(&protocol, collection.candidates.clone()).unwrap();
    collection.manifest = seal_collection_manifest(collection.manifest).unwrap();
    let second_rank = historical_v3_rank_identity(&protocol, &collection, 2).unwrap();
    let journal = tempfile::tempdir().unwrap();
    let review = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(historical_v3_rank_journal_path(
        journal.path(),
        &second_rank,
    ))
    .unwrap();
    let error = replay_historical_v3_ordered_progress(
        &protocol,
        &collection,
        second_rank.language(),
        journal.path(),
        review.path(),
        &review.path().join("stop.json"),
    )
    .unwrap_err();
    assert!(error.contains("out-of-order state"));
}

#[tokio::test]
async fn partial_human_records_remain_pending_then_publish_and_replay_stop() {
    let fixture = review_fixture().await;
    let inputs = fixture.inputs();
    let language = inputs.qualification.rank.language();
    let review = tempfile::tempdir().unwrap();
    let paths = HistoricalV3ReviewRecordPaths::new(review.path(), &inputs.qualification.rank);
    let stop_path = review.path().join("stop.json");
    let replay = || {
        replay_historical_v3_ordered_progress(
            inputs.protocol,
            inputs.collection,
            language,
            fixture.journal_path(),
            review.path(),
            &stop_path,
        )
    };
    assert!(matches!(
        replay().unwrap(),
        HistoricalV3ReplayProgress::PendingRank {
            processed_ranks: 0,
            next: HistoricalV3NextStep::HumanReview,
            ..
        }
    ));
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
    write_historical_v3_label_audit_new(&paths.audit, &audit).unwrap();
    assert!(replay().unwrap_err().contains("skips independent reviews"));
    write_historical_v3_label_worksheet_new(&paths.reviewer_two, &worksheets[1]).unwrap();
    assert!(matches!(
        replay().unwrap(),
        HistoricalV3ReplayProgress::PendingRank {
            next: HistoricalV3NextStep::HumanReview,
            ..
        }
    ));
    write_historical_v3_resolution_worksheet_new(&paths.resolution, &resolution).unwrap();
    write_historical_v3_final_label_new(&paths.final_label, &label).unwrap();
    let HistoricalV3ReplayProgress::AwaitingStopPublication { artifact } = replay().unwrap() else {
        panic!("complete human records must await terminal stop publication");
    };
    write_historical_v3_stop_artifact_new(&stop_path, &artifact).unwrap();
    assert!(matches!(
        replay().unwrap(),
        HistoricalV3ReplayProgress::Terminal { artifact: replayed } if replayed == artifact
    ));
    let mut altered = audit;
    altered.audit_sha256 = "0".repeat(64);
    std::fs::write(&paths.audit, serde_json::to_vec(&altered).unwrap()).unwrap();
    assert!(replay().is_err());
}

#[tokio::test]
async fn qualified_rank_requires_recipe_and_rejects_a_premature_cap() {
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
    let rank = historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let replay = || {
        replay_historical_v3_ordered_progress(
            &protocol,
            &collection,
            rank.language(),
            journal.path(),
            review.path(),
            &review.path().join("stop.json"),
        )
    };
    assert!(matches!(
        replay().unwrap(),
        HistoricalV3ReplayProgress::PendingRank {
            next: HistoricalV3NextStep::RankStage(HistoricalV3RankStage::TestRecipe),
            ..
        }
    ));
    let paths = HistoricalV3ReviewRecordPaths::new(review.path(), &rank);
    std::fs::create_dir_all(paths.cap.parent().unwrap()).unwrap();
    std::fs::write(&paths.cap, b"{}").unwrap();
    assert!(replay().unwrap_err().contains("precedes eight candidates"));
}
