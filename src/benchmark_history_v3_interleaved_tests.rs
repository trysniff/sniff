use super::super::history_v3_candidate_collection::seal_collection_manifest;
use super::super::history_v3_rank_journal::historical_v3_rank_journal_path;
use super::super::history_v3_semantic_census::tests as semantic_fixture;
use super::super::{
    HistoricalV3CandidateCollection, HistoricalV3CandidateRepository, HistoricalV3Language,
    HistoricalV3NextStep, HistoricalV3RankStage, HistoricalV3ReplayProgress,
    historical_v3_rank_identity, prepare_historical_v3_stream_task,
    replay_historical_v3_ordered_progress, run_historical_v3_mechanical_qualification_stage,
};
use super::tests::UnexpectedExecutor;
use super::{HistoricalV3RunPaths, advance_historical_v3_ordered_step};

fn interleaved_collection(
    protocol: &super::super::HistoricalV3Protocol,
    fixture: &semantic_fixture::GitFixture,
) -> HistoricalV3CandidateCollection {
    let mut collection = semantic_fixture::collection(protocol, fixture);
    let first_rust = collection.candidates[0].clone();
    let mut second_rust = first_rust.clone();
    second_rust.pull_request_number = 8;
    let mut python = first_rust.clone();
    python.language = HistoricalV3Language::Python;
    python.repository_id = 15;
    let selected = (9..=256).find_map(|pull_request_number| {
        python.pull_request_number = pull_request_number;
        let candidates = vec![first_rust.clone(), second_rust.clone(), python.clone()];
        let stream_task = prepare_historical_v3_stream_task(protocol, candidates.clone()).unwrap();
        let languages = stream_task
            .candidates
            .iter()
            .map(|candidate| candidate.identity.language)
            .collect::<Vec<_>>();
        (languages
            == [
                HistoricalV3Language::Rust,
                HistoricalV3Language::Python,
                HistoricalV3Language::Rust,
            ])
        .then_some((candidates, stream_task))
    });
    let (candidates, stream_task) = selected.expect("seeded stream must interleave both languages");
    collection.candidates = candidates;
    collection.manifest.candidate_count = collection.candidates.len();
    collection.manifest.stream_task = stream_task;
    collection
        .manifest
        .repositories
        .push(HistoricalV3CandidateRepository {
            language: HistoricalV3Language::Python,
            repository_id: 15,
            name_with_owner: "fresh/python".to_string(),
        });
    collection.manifest = seal_collection_manifest(collection.manifest).unwrap();
    collection
}

#[tokio::test]
async fn interleaved_language_replay_is_independent_but_same_language_stays_ordered() {
    let fixture = semantic_fixture::fixture();
    fixture.add_pull_ref(8);
    let protocol = semantic_fixture::protocol();
    let collection = interleaved_collection(&protocol, &fixture);
    let first_rust = historical_v3_rank_identity(&protocol, &collection, 1).unwrap();
    let python = historical_v3_rank_identity(&protocol, &collection, 2).unwrap();
    let second_rust = historical_v3_rank_identity(&protocol, &collection, 3).unwrap();
    assert_eq!(first_rust.language(), HistoricalV3Language::Rust);
    assert_eq!(python.language(), HistoricalV3Language::Python);
    assert_eq!(second_rust.language(), HistoricalV3Language::Rust);
    let journal = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let review = tempfile::tempdir().unwrap();
    let rust_stop = review.path().join("rust-stop.json");
    let python_stop = review.path().join("python-stop.json");
    let replay_rust = || {
        replay_historical_v3_ordered_progress(
            &protocol,
            &collection,
            HistoricalV3Language::Rust,
            journal.path(),
            review.path(),
            &rust_stop,
        )
    };
    let replay_python = || {
        replay_historical_v3_ordered_progress(
            &protocol,
            &collection,
            HistoricalV3Language::Python,
            journal.path(),
            review.path(),
            &python_stop,
        )
    };
    semantic_fixture::prepare_rank_at(
        &protocol,
        &collection,
        &fixture,
        first_rust.stream_rank,
        journal.path(),
        workspace.path(),
    );
    semantic_fixture::prepare_semantic_rank_at(
        &protocol,
        &collection,
        first_rust.stream_rank,
        journal.path(),
        workspace.path(),
    )
    .await;
    run_historical_v3_mechanical_qualification_stage(
        &protocol,
        &collection,
        first_rust.stream_rank,
        journal.path(),
    )
    .unwrap();
    let after_rust = advance_historical_v3_ordered_step(
        &protocol,
        &collection,
        HistoricalV3Language::Rust,
        HistoricalV3RunPaths {
            journal_root: journal.path(),
            workspace_root: workspace.path(),
            review_root: review.path(),
            stop_path: &rust_stop,
        },
        &UnexpectedExecutor,
    )
    .await
    .unwrap();
    assert!(matches!(
        after_rust,
        HistoricalV3ReplayProgress::PendingRank {
            processed_ranks: 0,
            ref rank,
            next: HistoricalV3NextStep::RankStage(HistoricalV3RankStage::IdenticalTests),
        } if rank == &first_rust
    ));
    assert_eq!(replay_rust().unwrap(), after_rust);
    assert!(matches!(
        replay_python().unwrap(),
        HistoricalV3ReplayProgress::PendingRank {
            processed_ranks: 0,
            rank,
            next: HistoricalV3NextStep::RankStage(HistoricalV3RankStage::Materialization),
        } if rank == python
    ));
    std::fs::write(&rust_stop, b"{}").unwrap();
    assert!(
        replay_rust()
            .unwrap_err()
            .contains("before the prefix is terminal")
    );
    assert!(replay_python().is_ok());
    std::fs::remove_file(&rust_stop).unwrap();
    std::fs::create_dir_all(historical_v3_rank_journal_path(
        journal.path(),
        &second_rust,
    ))
    .unwrap();
    assert!(replay_rust().unwrap_err().contains("out-of-order state"));
    assert!(replay_python().is_ok());
}
