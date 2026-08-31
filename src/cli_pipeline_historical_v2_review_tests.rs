use super::*;
use crate::benchmark::{
    HistoricalV2CorpusBundle, HistoricalV2FinalLabel, HistoricalV2FinalLabelOutcome,
    install_test_historical_v2_corpus,
};

fn path(path: &Path) -> &str {
    path.to_str().expect("test path is UTF-8")
}

fn write_json(path: &Path, value: &impl serde::Serialize) {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("serialize fixture"),
    )
    .expect("write fixture");
}

#[test]
fn historical_v2_review_operator_completes_consensus_lifecycle_offline() {
    let root = tempfile::tempdir().expect("create operator fixture root");
    install_test_historical_v2_corpus(root.path());
    let historical_root = root.path().join("historical-v2");
    let protocol = historical_root.join("protocol.json");
    let bundle_root = historical_root.join("reviews/rust-001");

    assert_eq!(
        validate_historical_v2_source_review_cli(path(&protocol), path(&bundle_root)).unwrap(),
        0
    );

    let blank = root.path().join("blank.json");
    assert_eq!(
        prepare_historical_v2_labels(path(&protocol), path(&bundle_root), path(&blank)).unwrap(),
        0
    );
    assert!(blank.is_file());
    assert!(
        prepare_historical_v2_labels(path(&protocol), path(&bundle_root), path(&blank)).is_err()
    );

    let corpus = read_json::<HistoricalV2CorpusBundle>(
        &historical_root.join("corpus-bundle.json"),
        "historical-v2 fixture corpus",
    )
    .unwrap();
    let case = corpus
        .cases
        .iter()
        .find(|case| case.language == "rust" && case.slot_number == 1)
        .expect("find Rust fixture case");
    assert_eq!(case.worksheets.len(), 2);
    let first = root.path().join("review-a.json");
    let second = root.path().join("review-b.json");
    write_json(&first, &case.worksheets[0]);
    write_json(&second, &case.worksheets[1]);

    assert_eq!(
        validate_historical_v2_labels(path(&protocol), path(&bundle_root), path(&first)).unwrap(),
        0
    );
    assert_eq!(
        validate_historical_v2_labels(path(&protocol), path(&bundle_root), path(&second)).unwrap(),
        0
    );

    let reviews = vec![path(&first).to_string(), path(&second).to_string()];
    let label_inputs = || HistoricalV2LabelInputs {
        protocol_path: path(&protocol),
        bundle_directory: path(&bundle_root),
        review_paths: &reviews,
    };
    let audit = root.path().join("audit.json");
    assert_eq!(
        audit_historical_v2_labels(label_inputs(), path(&audit)).unwrap(),
        0
    );

    let resolution = root.path().join("resolution.json");
    assert_eq!(
        prepare_historical_v2_resolution(label_inputs(), path(&audit), path(&resolution)).unwrap(),
        0
    );

    let final_label = root.path().join("final-label.json");
    assert_eq!(
        resolve_historical_v2_labels_cli(
            label_inputs(),
            path(&audit),
            path(&resolution),
            path(&final_label),
        )
        .unwrap(),
        0
    );
    let label =
        read_json::<HistoricalV2FinalLabel>(&final_label, "historical-v2 fixture final label")
            .unwrap();
    assert!(matches!(
        label.outcome,
        HistoricalV2FinalLabelOutcome::Accepted { .. }
    ));
}

#[test]
fn historical_v2_review_operator_rejects_wrong_protocol() {
    let root = tempfile::tempdir().expect("create operator fixture root");
    install_test_historical_v2_corpus(root.path());
    let historical_root = root.path().join("historical-v2");
    let protocol = historical_root.join("protocol.json");
    let bundle_root = historical_root.join("reviews/rust-001");
    let mut bytes = fs::read(&protocol).expect("read fixture protocol");
    let index = bytes
        .iter()
        .position(|byte| *byte == b'r')
        .expect("fixture protocol contains text");
    bytes[index] = b'x';
    let wrong_protocol = root.path().join("wrong-protocol.json");
    fs::write(&wrong_protocol, bytes).expect("write wrong protocol");

    assert!(
        validate_historical_v2_source_review_cli(path(&wrong_protocol), path(&bundle_root))
            .is_err()
    );
}
