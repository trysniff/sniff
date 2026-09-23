use super::super::history_v3_candidate_collection::seal_collection_manifest;
use super::super::history_v3_label_review::tests::review_fixture;
use super::super::history_v3_rank_journal::historical_v3_rank_identity_in_validated_collection;
use super::super::history_v3_semantic_census::tests as semantic_fixture;
use super::super::{
    HistoricalV3ReviewDisposition, HistoricalV3ReviewerVerdict, HistoricalV3VerifiedFinalReview,
    audit_historical_v3_label_reviews, prepare_historical_v3_label_resolution,
    prepare_historical_v3_stop_artifact, prepare_historical_v3_stream_task,
    read_historical_v3_stop_artifact, resolve_historical_v3_label,
    validate_historical_v3_candidate_collection_commitment, verify_historical_v3_final_review,
    verify_historical_v3_stop_artifact, write_historical_v3_stop_artifact_new,
};
use super::{
    HistoricalV3OrderedRankOutcome, HistoricalV3OrderedStopStatus,
    evaluate_historical_v3_ordered_prefix,
};

#[tokio::test]
async fn verified_final_review_is_counted_at_its_exact_rank() {
    let fixture = review_fixture().await;
    let inputs = fixture.inputs();
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
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("final-label.json");
    super::super::write_historical_v3_final_label_new(&path, &label).unwrap();
    let proof = verify_historical_v3_final_review(
        &inputs,
        &fixture.bundle,
        &worksheets,
        &audit,
        &resolution,
        &path,
    )
    .unwrap();
    let language = inputs.qualification.rank.language();
    assert!(matches!(
        evaluate_historical_v3_ordered_prefix(inputs.protocol, inputs.collection, language, &[])
            .unwrap(),
        HistoricalV3OrderedStopStatus::Continue {
            processed_ranks: 0,
            reviewed: 0,
            ..
        }
    ));
    assert!(
        prepare_historical_v3_stop_artifact(inputs.protocol, inputs.collection, language, &[])
            .is_err()
    );
    let outcomes = [HistoricalV3OrderedRankOutcome::Reviewed(proof)];
    assert!(matches!(
        evaluate_historical_v3_ordered_prefix(
            inputs.protocol,
            inputs.collection,
            language,
            &outcomes,
        )
        .unwrap(),
        HistoricalV3OrderedStopStatus::FailedSourceExhausted {
            processed_ranks: 1,
            reviewed: 1,
            accepted: 1,
            ..
        }
    ));
    let artifact = prepare_historical_v3_stop_artifact(
        inputs.protocol,
        inputs.collection,
        language,
        &outcomes,
    )
    .unwrap();
    let stop_path = directory.path().join("stop.json");
    write_historical_v3_stop_artifact_new(&stop_path, &artifact).unwrap();
    assert!(write_historical_v3_stop_artifact_new(&stop_path, &artifact).is_err());
    assert_eq!(
        read_historical_v3_stop_artifact(&stop_path).unwrap(),
        artifact
    );
    assert_eq!(
        verify_historical_v3_stop_artifact(
            inputs.protocol,
            inputs.collection,
            language,
            &outcomes,
            &stop_path,
        )
        .unwrap(),
        artifact
    );
    let mut tampered = artifact;
    tampered.stop_sha256 = "0".repeat(64);
    let tampered_path = directory.path().join("tampered-stop.json");
    write_historical_v3_stop_artifact_new(&tampered_path, &tampered).unwrap();
    assert!(
        verify_historical_v3_stop_artifact(
            inputs.protocol,
            inputs.collection,
            language,
            &outcomes,
            &tampered_path,
        )
        .is_err()
    );
}

#[test]
fn first_target_prefix_stops_at_forty_accepted_across_twenty_repositories() {
    let fixture = semantic_fixture::fixture();
    let protocol = semantic_fixture::protocol();
    let mut collection = semantic_fixture::collection(&protocol, &fixture);
    let identity = collection.candidates[0].clone();
    collection.candidates = (0..41)
        .map(|index| {
            let mut candidate = identity.clone();
            candidate.repository_id = 1000 + index / 2;
            candidate.pull_request_number = 1 + index % 2;
            candidate
        })
        .collect();
    for repository_id in 1000..=1020 {
        let mut repository = collection.manifest.repositories[0].clone();
        repository.language = identity.language;
        repository.repository_id = repository_id;
        repository.name_with_owner = format!("fixture/repository-{repository_id}");
        collection.manifest.repositories.push(repository);
    }
    collection.manifest.candidate_count = collection.candidates.len();
    collection.manifest.stream_task =
        prepare_historical_v3_stream_task(&protocol, collection.candidates.clone()).unwrap();
    collection.manifest = seal_collection_manifest(collection.manifest).unwrap();
    validate_historical_v3_candidate_collection_commitment(&protocol, &collection).unwrap();
    let outcomes = collection
        .manifest
        .stream_task
        .candidates
        .iter()
        .map(|candidate| {
            let rank = historical_v3_rank_identity_in_validated_collection(
                &protocol,
                &collection,
                candidate.stream_rank,
            )
            .unwrap();
            HistoricalV3OrderedRankOutcome::Reviewed(HistoricalV3VerifiedFinalReview::synthetic(
                rank,
                HistoricalV3ReviewDisposition::Accepted,
            ))
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        evaluate_historical_v3_ordered_prefix(
            &protocol,
            &collection,
            identity.language,
            &outcomes[..39],
        )
        .unwrap(),
        HistoricalV3OrderedStopStatus::Continue {
            processed_ranks: 39,
            accepted: 39,
            ..
        }
    ));
    assert!(matches!(
        evaluate_historical_v3_ordered_prefix(
            &protocol,
            &collection,
            identity.language,
            &outcomes[..40],
        )
        .unwrap(),
        HistoricalV3OrderedStopStatus::TargetReached {
            processed_ranks: 40,
            accepted: 40,
            ..
        }
    ));
    assert!(
        prepare_historical_v3_stop_artifact(
            &protocol,
            &collection,
            identity.language,
            &outcomes[..39],
        )
        .is_err()
    );
    let artifact = prepare_historical_v3_stop_artifact(
        &protocol,
        &collection,
        identity.language,
        &outcomes[..40],
    )
    .unwrap();
    assert_eq!(artifact.entries.len(), 40);
    let mut reordered = outcomes[..40].to_vec();
    reordered.swap(0, 1);
    assert!(
        evaluate_historical_v3_ordered_prefix(
            &protocol,
            &collection,
            identity.language,
            &reordered,
        )
        .unwrap_err()
        .contains("foreign or skipped rank")
    );
    assert!(evaluate_historical_v3_ordered_prefix(
        &protocol,
        &collection,
        identity.language,
        &outcomes,
    )
    .unwrap_err()
    .contains("first successful prefix"));
}

#[test]
fn adjudication_cap_stops_at_four_hundred_reviews() {
    let fixture = semantic_fixture::fixture();
    let protocol = semantic_fixture::protocol();
    let mut collection = semantic_fixture::collection(&protocol, &fixture);
    let identity = collection.candidates[0].clone();
    collection.candidates = (0..401)
        .map(|index| {
            let mut candidate = identity.clone();
            candidate.repository_id = 2000 + index / 8;
            candidate.pull_request_number = 1 + index % 8;
            candidate
        })
        .collect();
    for repository_id in 2000..=2050 {
        let mut repository = collection.manifest.repositories[0].clone();
        repository.language = identity.language;
        repository.repository_id = repository_id;
        repository.name_with_owner = format!("fixture/repository-{repository_id}");
        collection.manifest.repositories.push(repository);
    }
    collection.manifest.candidate_count = collection.candidates.len();
    collection.manifest.stream_task =
        prepare_historical_v3_stream_task(&protocol, collection.candidates.clone()).unwrap();
    collection.manifest = seal_collection_manifest(collection.manifest).unwrap();
    validate_historical_v3_candidate_collection_commitment(&protocol, &collection).unwrap();
    let outcomes = collection
        .manifest
        .stream_task
        .candidates
        .iter()
        .map(|candidate| {
            let rank = historical_v3_rank_identity_in_validated_collection(
                &protocol,
                &collection,
                candidate.stream_rank,
            )
            .unwrap();
            HistoricalV3OrderedRankOutcome::Reviewed(HistoricalV3VerifiedFinalReview::synthetic(
                rank,
                HistoricalV3ReviewDisposition::Rejected,
            ))
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        evaluate_historical_v3_ordered_prefix(
            &protocol,
            &collection,
            identity.language,
            &outcomes[..399],
        )
        .unwrap(),
        HistoricalV3OrderedStopStatus::Continue {
            processed_ranks: 399,
            reviewed: 399,
            ..
        }
    ));
    assert!(matches!(
        evaluate_historical_v3_ordered_prefix(
            &protocol,
            &collection,
            identity.language,
            &outcomes[..400],
        )
        .unwrap(),
        HistoricalV3OrderedStopStatus::FailedAdjudicationCap {
            processed_ranks: 400,
            reviewed: 400,
            ..
        }
    ));
    assert!(evaluate_historical_v3_ordered_prefix(
        &protocol,
        &collection,
        identity.language,
        &outcomes,
    )
    .unwrap_err()
    .contains("adjudication cap"));
}
