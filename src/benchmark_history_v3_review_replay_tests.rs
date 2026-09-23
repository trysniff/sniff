use super::super::history_v3_label_review::tests::review_fixture;
use super::super::{
    HistoricalV3OrderedRankOutcome, HistoricalV3ReviewDisposition, HistoricalV3ReviewerVerdict,
    audit_historical_v3_label_reviews, prepare_historical_v3_label_resolution,
    prepare_historical_v3_stop_artifact, resolve_historical_v3_label,
    verify_historical_v3_stop_from_disk, write_historical_v3_final_label_new,
    write_historical_v3_label_audit_new, write_historical_v3_label_worksheet_new,
    write_historical_v3_resolution_worksheet_new, write_historical_v3_stop_artifact_new,
};
use super::{HistoricalV3ReviewRecordPaths, verify_historical_v3_final_review_from_disk};

#[tokio::test]
async fn replays_review_from_journal_and_all_committed_human_records() {
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
    let root = tempfile::tempdir().unwrap();
    let paths = HistoricalV3ReviewRecordPaths::new(root.path(), &inputs.qualification.rank);
    std::fs::create_dir_all(paths.audit.parent().unwrap()).unwrap();
    write_historical_v3_label_worksheet_new(&paths.reviewer_one, &worksheets[0]).unwrap();
    write_historical_v3_label_worksheet_new(&paths.reviewer_two, &worksheets[1]).unwrap();
    write_historical_v3_label_audit_new(&paths.audit, &audit).unwrap();
    assert!(
        verify_historical_v3_final_review_from_disk(
            inputs.protocol,
            inputs.collection,
            1,
            fixture.journal_path(),
            root.path(),
        )
        .is_err()
    );
    write_historical_v3_resolution_worksheet_new(&paths.resolution, &resolution).unwrap();
    write_historical_v3_final_label_new(&paths.final_label, &label).unwrap();
    let proof = verify_historical_v3_final_review_from_disk(
        inputs.protocol,
        inputs.collection,
        1,
        fixture.journal_path(),
        root.path(),
    )
    .unwrap();
    assert_eq!(
        proof.record().disposition,
        HistoricalV3ReviewDisposition::Accepted
    );
    assert_eq!(proof.rank(), &inputs.qualification.rank);
    let language = inputs.qualification.rank.language();
    let outcomes = [HistoricalV3OrderedRankOutcome::Reviewed(proof)];
    let stop = prepare_historical_v3_stop_artifact(
        inputs.protocol,
        inputs.collection,
        language,
        &outcomes,
    )
    .unwrap();
    let stop_path = root.path().join("stop.json");
    write_historical_v3_stop_artifact_new(&stop_path, &stop).unwrap();
    assert_eq!(
        verify_historical_v3_stop_from_disk(
            inputs.protocol,
            inputs.collection,
            language,
            fixture.journal_path(),
            root.path(),
            &stop_path,
        )
        .unwrap(),
        stop
    );
    let mut altered = audit;
    altered.audit_sha256 = "0".repeat(64);
    std::fs::write(&paths.audit, serde_json::to_vec(&altered).unwrap()).unwrap();
    assert!(
        verify_historical_v3_final_review_from_disk(
            inputs.protocol,
            inputs.collection,
            1,
            fixture.journal_path(),
            root.path(),
        )
        .is_err()
    );
    assert!(
        verify_historical_v3_stop_from_disk(
            inputs.protocol,
            inputs.collection,
            language,
            fixture.journal_path(),
            root.path(),
            &stop_path,
        )
        .is_err()
    );
}
