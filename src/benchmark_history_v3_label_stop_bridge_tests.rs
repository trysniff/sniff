use super::super::history_v3_label_review::tests::review_fixture;
use super::super::{
    HistoricalV3ReviewDisposition, HistoricalV3ReviewerVerdict, audit_historical_v3_label_reviews,
    prepare_historical_v3_label_resolution, resolve_historical_v3_label,
};
use super::{
    historical_v3_review_record_from_final_label, read_historical_v3_final_label,
    verify_historical_v3_final_review, write_historical_v3_final_label_new,
};

#[tokio::test]
async fn derives_acceptance_only_from_a_verified_final_label() {
    let fixture = review_fixture().await;
    let worksheets = [
        fixture.worksheet("reviewer-a", HistoricalV3ReviewerVerdict::Slop),
        fixture.worksheet("reviewer-b", HistoricalV3ReviewerVerdict::Slop),
    ];
    let inputs = fixture.inputs();
    let audit = audit_historical_v3_label_reviews(&inputs, &fixture.bundle, &worksheets).unwrap();
    let resolution =
        prepare_historical_v3_label_resolution(&inputs, &fixture.bundle, &worksheets, &audit)
            .unwrap();
    let label =
        resolve_historical_v3_label(&inputs, &fixture.bundle, &worksheets, &audit, &resolution)
            .unwrap();
    let record = historical_v3_review_record_from_final_label(
        &inputs,
        &fixture.bundle,
        &worksheets,
        &audit,
        &resolution,
        &label,
    )
    .unwrap();
    assert_eq!(record.disposition, HistoricalV3ReviewDisposition::Accepted);
    assert_eq!(record.stream_rank, inputs.qualification.rank.stream_rank);
    assert_eq!(record.rank_sha256, inputs.qualification.rank.rank_sha256);
    assert_eq!(
        record.repository_id,
        inputs.qualification.rank.candidate.repository_id
    );
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("final-label.json");
    write_historical_v3_final_label_new(&path, &label).unwrap();
    assert_eq!(read_historical_v3_final_label(&path).unwrap(), label);
    assert!(write_historical_v3_final_label_new(&path, &label).is_err());
    let proof = verify_historical_v3_final_review(
        &inputs,
        &fixture.bundle,
        &worksheets,
        &audit,
        &resolution,
        &path,
    )
    .unwrap();
    assert_eq!(proof.record(), &record);
    assert_eq!(proof.rank(), &inputs.qualification.rank);
    assert_eq!(proof.source_bundle_sha256(), fixture.bundle.bundle_sha256);
    assert_eq!(proof.final_label_sha256(), label.final_sha256);

    let mut tampered = label;
    tampered.final_sha256 = "0".repeat(64);
    let tampered_path = directory.path().join("tampered-final-label.json");
    write_historical_v3_final_label_new(&tampered_path, &tampered).unwrap();
    assert!(
        verify_historical_v3_final_review(
            &inputs,
            &fixture.bundle,
            &worksheets,
            &audit,
            &resolution,
            &tampered_path,
        )
        .is_err()
    );
}

#[tokio::test]
async fn maps_all_closed_final_labels_to_non_accepted_records() {
    let fixture = review_fixture().await;
    for verdict in [
        HistoricalV3ReviewerVerdict::Clean,
        HistoricalV3ReviewerVerdict::IntentionalBoundary,
        HistoricalV3ReviewerVerdict::Ambiguous,
        HistoricalV3ReviewerVerdict::InsufficientContext,
    ] {
        let worksheets = [
            fixture.worksheet("reviewer-a", verdict),
            fixture.worksheet("reviewer-b", verdict),
        ];
        let inputs = fixture.inputs();
        let audit =
            audit_historical_v3_label_reviews(&inputs, &fixture.bundle, &worksheets).unwrap();
        let resolution =
            prepare_historical_v3_label_resolution(&inputs, &fixture.bundle, &worksheets, &audit)
                .unwrap();
        let label =
            resolve_historical_v3_label(&inputs, &fixture.bundle, &worksheets, &audit, &resolution)
                .unwrap();
        let record = historical_v3_review_record_from_final_label(
            &inputs,
            &fixture.bundle,
            &worksheets,
            &audit,
            &resolution,
            &label,
        )
        .unwrap();
        assert_eq!(record.disposition, HistoricalV3ReviewDisposition::Rejected);
    }
}
