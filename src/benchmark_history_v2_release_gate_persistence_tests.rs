use super::super::tests::GateFixture;
use super::*;
use std::fs;

#[test]
fn persisted_release_evidence_round_trips_without_live_mutation() {
    let fixture = GateFixture::new(Vec::new());
    let evidence = fixture.build(&[]).unwrap();
    validate_historical_v2_release_evidence_commitment(PROTOCOL, &evidence).unwrap();
    let output_root = tempfile::tempdir().unwrap();
    let output = output_root.path().join("release-evidence.json");
    write_historical_v2_release_evidence(&fixture.inputs(&[]), &evidence, &output).unwrap();
    assert_eq!(
        load_historical_v2_release_evidence(PROTOCOL, &output).unwrap(),
        evidence
    );
    let error =
        write_historical_v2_release_evidence(&fixture.inputs(&[]), &evidence, &output).unwrap_err();
    assert!(error.contains("failed to create"), "{error}");
}

#[test]
fn persisted_release_evidence_rejects_slot_and_commitment_tampering() {
    let fixture = GateFixture::new(Vec::new());
    let mut evidence = fixture.build(&[]).unwrap();
    evidence.slots.swap(0, 1);
    let error =
        validate_historical_v2_release_evidence_commitment(PROTOCOL, &evidence).unwrap_err();
    assert!(error.contains("order or identity"), "{error}");

    evidence = fixture.build(&[]).unwrap();
    evidence.status = HistoricalV2ReleaseGateStatus::Passed;
    let output_root = tempfile::tempdir().unwrap();
    let output = output_root.path().join("tampered.json");
    fs::write(&output, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
    let error = load_historical_v2_release_evidence(PROTOCOL, &output).unwrap_err();
    assert!(error.contains("commitment changed"), "{error}");
}

const PROTOCOL: &[u8] = include_bytes!("../sniffbench/historical-v2-protocol.json");
