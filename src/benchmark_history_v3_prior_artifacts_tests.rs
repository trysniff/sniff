use super::*;
use crate::benchmark::{
    HISTORICAL_V2_FRAME_SCHEMA_VERSION, HistoricalV2ProjectedRow,
    derive_historical_v2_frame_record, historical_v2_frame_sha256, validate_historical_v2_protocol,
};

fn synthetic_inputs() -> (
    HistoricalV2Frame,
    HistoricalV2ExclusionManifest,
    HistoricalV2SlotSelection,
) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let protocol = validate_historical_v2_protocol(PROTOCOL).unwrap();
    let row = HistoricalV2ProjectedRow {
        source_shard_index: 0,
        source_row_index: 0,
        global_row_index: 0,
        base_commit: "a".repeat(40),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        instance_id: "unique-v3-prior-fixture/repo#1".to_string(),
        license: "MIT".to_string(),
        patch: "diff --git a/src/main.py b/src/main.py\n--- a/src/main.py\n+++ b/src/main.py\n@@ -1,2 +1 @@\n-old one\n-old two\n+new\n".to_string(),
        pull_number: 1,
        repo: "unique-v3-prior-fixture/repo".to_string(),
    };
    let record = derive_historical_v2_frame_record(row, &protocol.protocol.selection.ranking_seed);
    let mut frame = HistoricalV2Frame {
        schema_version: HISTORICAL_V2_FRAME_SCHEMA_VERSION,
        protocol_sha256: protocol.protocol_sha256,
        dataset_revision: protocol.protocol.dataset.revision,
        ranking_seed: protocol.protocol.selection.ranking_seed,
        shards: Vec::new(),
        row_count: 1,
        eligible_count: 1,
        excluded_count: 0,
        records: vec![record],
        frame_sha256: String::new(),
    };
    frame.frame_sha256 = historical_v2_frame_sha256(&frame).unwrap();
    let exclusions = derive_historical_v2_exclusion_manifest(PROTOCOL, root).unwrap();
    let selection = select_historical_v2_slots(PROTOCOL, root, &frame, &exclusions).unwrap();
    (frame, exclusions, selection)
}

#[test]
fn derives_prior_repositories_from_original_partitions_and_fixed_slots() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (frame, exclusions, selection) = synthetic_inputs();
    let frame_bytes = serde_json::to_vec(&frame).unwrap();
    let exclusion_bytes = serde_json::to_vec(&exclusions).unwrap();
    let selection_bytes = serde_json::to_vec(&selection).unwrap();
    let seal = derive_prior_seal(
        root,
        PROTOCOL,
        &frame_bytes,
        &exclusion_bytes,
        &selection_bytes,
    )
    .unwrap();
    assert_eq!(
        seal.inputs.len(),
        exclusions
            .partitions
            .iter()
            .filter(|partition| !partition.repositories.is_empty())
            .count()
            + 1
    );
    assert!(
        seal.repositories
            .contains(&"unique-v3-prior-fixture/repo".to_string())
    );
    assert!(
        seal.repositories
            .contains(&"albinchristo04/bassride".to_string())
    );
    let v2 = seal
        .inputs
        .iter()
        .find(|input| input.artifact_id == "historical-v2")
        .unwrap();
    assert_eq!(v2.repositories, vec!["unique-v3-prior-fixture/repo"]);
    assert_eq!(v2.artifact_sha256, sha256(&selection_bytes));
}

#[test]
fn rejects_an_exclusion_list_that_differs_from_original_sources() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (frame, mut exclusions, selection) = synthetic_inputs();
    exclusions.partitions[0].repositories.remove(0);
    let result = derive_prior_seal(
        root,
        PROTOCOL,
        &serde_json::to_vec(&frame).unwrap(),
        &serde_json::to_vec(&exclusions).unwrap(),
        &serde_json::to_vec(&selection).unwrap(),
    );
    assert!(result.unwrap_err().contains("original sources"));
}

#[test]
fn rejects_a_changed_fixed_slot_selection() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (frame, exclusions, mut selection) = synthetic_inputs();
    selection
        .slots
        .iter_mut()
        .find(|slot| matches!(slot.outcome, HistoricalV2SlotOutcome::Selected { .. }))
        .unwrap()
        .outcome = HistoricalV2SlotOutcome::Unfilled;
    let result = derive_prior_seal(
        root,
        PROTOCOL,
        &serde_json::to_vec(&frame).unwrap(),
        &serde_json::to_vec(&exclusions).unwrap(),
        &serde_json::to_vec(&selection).unwrap(),
    );
    assert!(result.unwrap_err().contains("fixed slots"));
}

#[test]
#[ignore = "requires the frozen historical-v2 frame artifact on disk"]
fn verifies_the_real_frozen_prior_repository_union() {
    let directory = std::env::var_os("SNIFF_HISTORICAL_V2_FRAME_DIR")
        .expect("set SNIFF_HISTORICAL_V2_FRAME_DIR to the extracted frozen frame artifact");
    let directory = Path::new(&directory);
    let source_root = std::env::var_os("SNIFF_HISTORICAL_V2_SOURCE_ROOT")
        .expect("set SNIFF_HISTORICAL_V2_SOURCE_ROOT to the exact LF source-artifact root");
    let seal = derive_frozen_historical_v3_prior_identity_seal(
        Path::new(&source_root),
        &directory.join("frame.json"),
        &directory.join("exclusions.json"),
        &directory.join("selection.json"),
    )
    .unwrap();
    assert_eq!(seal.inputs.len(), 6);
    assert_eq!(seal.repositories.len(), 1279);
    assert_eq!(
        seal.inputs
            .iter()
            .find(|input| input.artifact_id == "historical-v2")
            .unwrap()
            .repositories
            .len(),
        664
    );
}
