use super::super::history_v3_candidate_collection::seal_collection_manifest;
use super::super::history_v3_semantic_census::tests as semantic_fixture;
use super::super::{
    HistoricalV3OrderedRankOutcome, HistoricalV3OrderedStopStatus, HistoricalV3ReviewDisposition,
    HistoricalV3VerifiedFinalReview, HistoricalV3VerifiedQualification,
    evaluate_historical_v3_ordered_prefix, historical_v3_rank_identity,
    prepare_historical_v3_stop_artifact, prepare_historical_v3_stream_task,
    verify_historical_v3_stop_artifact, write_historical_v3_stop_artifact_new,
};
use super::{
    prepare_historical_v3_review_cap, read_historical_v3_review_cap,
    verify_historical_v3_review_cap, write_historical_v3_review_cap_new,
};

#[test]
fn commits_only_the_ninth_qualified_candidate_from_the_same_repository() {
    let fixture = semantic_fixture::fixture();
    let protocol = semantic_fixture::protocol();
    let mut collection = semantic_fixture::collection(&protocol, &fixture);
    let identity = collection.candidates[0].clone();
    collection.candidates = (1..=10)
        .map(|pull_request_number| {
            let mut candidate = identity.clone();
            candidate.pull_request_number = pull_request_number;
            candidate
        })
        .collect();
    collection.manifest.candidate_count = collection.candidates.len();
    collection.manifest.stream_task =
        prepare_historical_v3_stream_task(&protocol, collection.candidates.clone()).unwrap();
    collection.manifest = seal_collection_manifest(collection.manifest).unwrap();
    let ranks = collection
        .manifest
        .stream_task
        .candidates
        .iter()
        .map(|candidate| {
            historical_v3_rank_identity(&protocol, &collection, candidate.stream_rank).unwrap()
        })
        .collect::<Vec<_>>();
    let mut outcomes = ranks[..8]
        .iter()
        .cloned()
        .map(|rank| {
            HistoricalV3OrderedRankOutcome::Reviewed(HistoricalV3VerifiedFinalReview::synthetic(
                rank,
                HistoricalV3ReviewDisposition::Rejected,
            ))
        })
        .collect::<Vec<_>>();
    let too_early = HistoricalV3VerifiedQualification::synthetic(ranks[7].clone());
    assert!(
        prepare_historical_v3_review_cap(&protocol, &collection, &too_early, &outcomes[..7])
            .unwrap_err()
            .contains("exact earlier reviewable")
    );

    let ninth = HistoricalV3VerifiedQualification::synthetic(ranks[8].clone());
    let artifact =
        prepare_historical_v3_review_cap(&protocol, &collection, &ninth, &outcomes).unwrap();
    assert_eq!(artifact.prior_reviewable_rank_sha256s.len(), 8);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("review-cap.json");
    write_historical_v3_review_cap_new(&path, &artifact).unwrap();
    assert!(write_historical_v3_review_cap_new(&path, &artifact).is_err());
    let loaded = read_historical_v3_review_cap(&path).unwrap();
    assert_eq!(loaded, artifact);
    let proof =
        verify_historical_v3_review_cap(&protocol, &collection, &ninth, &outcomes, &path).unwrap();
    outcomes.push(HistoricalV3OrderedRankOutcome::Capped(proof));
    assert!(matches!(
        evaluate_historical_v3_ordered_prefix(
            &protocol,
            &collection,
            identity.language,
            &outcomes,
        )
        .unwrap(),
        HistoricalV3OrderedStopStatus::Continue {
            processed_ranks: 9,
            reviewed: 8,
            ..
        }
    ));
    let tenth = HistoricalV3VerifiedQualification::synthetic(ranks[9].clone());
    let tenth_artifact =
        prepare_historical_v3_review_cap(&protocol, &collection, &tenth, &outcomes).unwrap();
    let tenth_path = directory.path().join("review-cap-tenth.json");
    write_historical_v3_review_cap_new(&tenth_path, &tenth_artifact).unwrap();
    let tenth_proof =
        verify_historical_v3_review_cap(&protocol, &collection, &tenth, &outcomes, &tenth_path)
            .unwrap();
    outcomes.push(HistoricalV3OrderedRankOutcome::Capped(tenth_proof));
    assert!(matches!(
        evaluate_historical_v3_ordered_prefix(
            &protocol,
            &collection,
            identity.language,
            &outcomes,
        )
        .unwrap(),
        HistoricalV3OrderedStopStatus::FailedSourceExhausted {
            processed_ranks: 10,
            reviewed: 8,
            ..
        }
    ));
    let stop =
        prepare_historical_v3_stop_artifact(&protocol, &collection, identity.language, &outcomes)
            .unwrap();
    let stop_path = directory.path().join("stop.json");
    write_historical_v3_stop_artifact_new(&stop_path, &stop).unwrap();
    assert_eq!(
        verify_historical_v3_stop_artifact(
            &protocol,
            &collection,
            identity.language,
            &outcomes,
            &stop_path,
        )
        .unwrap(),
        stop
    );

    let mut tampered = artifact;
    tampered.prior_reviewable_rank_sha256s.reverse();
    let tampered_path = directory.path().join("review-cap-tampered.json");
    write_historical_v3_review_cap_new(&tampered_path, &tampered).unwrap();
    assert!(
        verify_historical_v3_review_cap(
            &protocol,
            &collection,
            &ninth,
            &outcomes[..8],
            &tampered_path,
        )
        .is_err()
    );
}
