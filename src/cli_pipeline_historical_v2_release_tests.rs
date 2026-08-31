use super::*;
use crate::benchmark::{
    HistoricalV2CorpusBundle, HistoricalV2ReleaseEvidence, HistoricalV2ReleaseGateStatus,
    install_test_historical_v2_corpus, install_test_historical_v2_empty_release_inputs,
};

fn protocol() -> ValidatedHistoricalV2Protocol {
    validate_historical_v2_protocol(include_bytes!("../sniffbench/historical-v2-protocol.json"))
        .expect("validate fixture protocol")
}

#[test]
fn aggregate_slot_identity_is_exact_and_language_bound() {
    let protocol = protocol();
    assert_eq!(
        parse_slot_identity(&protocol, "typescript-128").unwrap(),
        ("typescript".to_string(), 128)
    );
    for identity in [
        "rust-1",
        "rust-000",
        "rust-129",
        "java-001",
        "RUST-001",
        "rust-001-extra",
    ] {
        assert!(
            parse_slot_identity(&protocol, identity).is_err(),
            "accepted unsafe review identity {identity}"
        );
    }
}

#[test]
fn aggregate_label_package_rejects_missing_and_extra_artifacts() {
    let root = tempfile::tempdir().expect("create label fixture");
    for file in LABEL_FILES {
        fs::write(root.path().join(file), b"{}").expect("write label fixture");
    }
    require_exact_label_files(root.path()).unwrap();

    fs::write(root.path().join("extra.json"), b"{}").expect("write extra label fixture");
    assert!(require_exact_label_files(root.path()).is_err());
    fs::remove_file(root.path().join("extra.json")).expect("remove extra label fixture");
    fs::remove_file(root.path().join(REVIEW_B)).expect("remove required label fixture");
    assert!(require_exact_label_files(root.path()).is_err());
}

#[test]
fn aggregate_output_must_be_create_new_inside_corpus_root() {
    let root = tempfile::tempdir().expect("create corpus fixture");
    fs::create_dir(root.path().join("nested")).expect("create noncanonical root fixture");
    let noncanonical_root = root.path().join("nested").join("..");
    let output = root.path().join("release-evidence.json");
    assert_eq!(
        new_file_under_root(&noncanonical_root, &output, "release evidence").unwrap(),
        output
    );
    fs::write(&output, b"{}").expect("write release evidence fixture");
    assert!(new_file_under_root(root.path(), &output, "release evidence").is_err());

    let outside = root.path().parent().unwrap().join("outside-release.json");
    assert!(new_file_under_root(root.path(), &outside, "release evidence").is_err());
}

#[test]
fn aggregate_loader_validates_every_fixed_review_package() {
    let root = tempfile::tempdir().expect("create aggregate fixture");
    install_test_historical_v2_corpus(root.path());
    let historical_root = root.path().join("historical-v2");
    let protocol_path = historical_root.join("protocol.json");
    let protocol = protocol();
    let bundle = read_json::<HistoricalV2CorpusBundle>(
        &historical_root.join("corpus-bundle.json"),
        "historical-v2 fixture corpus",
    )
    .unwrap();
    let labels_root = historical_root.join(LABELS_DIRECTORY);
    fs::create_dir(&labels_root).expect("create fixture labels root");
    for case in &bundle.cases {
        let identity = format!("{}-{:03}", case.language, case.slot_number);
        let package = labels_root.join(identity);
        fs::create_dir(&package).expect("create fixture label package");
        write_json(&package.join(REVIEW_A), &case.worksheets[0]);
        write_json(&package.join(REVIEW_B), &case.worksheets[1]);
        write_json(&package.join(AUDIT), &case.audit);
        write_json(&package.join(RESOLUTION), &case.resolution);
        write_json(&package.join(FINAL_LABEL), &case.final_label);
    }

    let reviewed = load_review_set(
        protocol_path.to_str().expect("protocol path is UTF-8"),
        &protocol,
        &historical_root,
    )
    .unwrap();
    assert_eq!(reviewed.len(), 240);
    assert_eq!(reviewed[0].language, "go");
    assert_eq!(reviewed[0].slot_number, 1);

    fs::create_dir(labels_root.join("rust-041")).expect("create unmatched fixture package");
    assert!(
        load_review_set(
            protocol_path.to_str().expect("protocol path is UTF-8"),
            &protocol,
            &historical_root,
        )
        .is_err()
    );
}

#[test]
fn aggregate_cli_seals_and_replays_underfilled_release_evidence() {
    let root = tempfile::tempdir().expect("create aggregate release fixture");
    install_test_historical_v2_empty_release_inputs(root.path());
    let protocol = root.path().join("protocol.json");
    let artifact_root = root.path().join("artifact");
    let frame = root.path().join("frame.json");
    let exclusions = root.path().join("exclusions.json");
    let selection = root.path().join("selection.json");
    let state_root = root.path().join("state");
    let corpus_root = root.path().join("corpus");
    let evidence = corpus_root.join("release-evidence.json");
    let output = corpus_root.join("corpus-bundle.json");
    let aggregate = || HistoricalV2AggregateInputs {
        protocol_path: path(&protocol),
        artifact_root: path(&artifact_root),
        frame_path: path(&frame),
        exclusions_path: path(&exclusions),
        selection_path: path(&selection),
        state_root: path(&state_root),
        corpus_root: path(&corpus_root),
        evidence_path: path(&evidence),
    };

    assert_eq!(
        build_historical_v2_release_evidence_cli(aggregate()).unwrap(),
        0
    );
    let sealed = read_json::<HistoricalV2ReleaseEvidence>(
        &evidence,
        "historical-v2 fixture release evidence",
    )
    .unwrap();
    assert_eq!(sealed.status, HistoricalV2ReleaseGateStatus::Underfilled);
    assert_eq!(
        validate_historical_v2_release_evidence_cli(aggregate()).unwrap(),
        0
    );
    assert!(
        publish_historical_v2_corpus_cli(HistoricalV2CorpusPublishInputs {
            aggregate: aggregate(),
            output_path: path(&output),
        })
        .is_err()
    );
    assert!(!output.exists());
}

fn path(path: &Path) -> &str {
    path.to_str().expect("fixture path is UTF-8")
}

fn write_json(path: &Path, value: &impl serde::Serialize) {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("serialize fixture"),
    )
    .expect("write fixture");
}
