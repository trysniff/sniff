use super::*;
use crate::benchmark::{
    HISTORICAL_V2_FRAME_SCHEMA_VERSION, HistoricalV2ProjectedRow,
    derive_historical_v2_frame_record, historical_v2_frame_sha256, validate_historical_v2_protocol,
};

const PROTOCOL: &[u8] = include_bytes!("../sniffbench/historical-v2-protocol.json");
const COMMITTED_V2_TEMPORAL_PROOF: &[u8] =
    include_bytes!("../sniffbench/historical-v3-prior-v2-temporal-proof.json");

#[test]
fn pinned_reader_accepts_exact_limit_and_empty_inputs() {
    for body in [&b"frame"[..], &b""[..]] {
        let bytes = read_pinned_bytes(body, body.len() as u64, &sha256(body), "fixture").unwrap();
        assert_eq!(bytes, body);
    }
}

#[test]
fn pinned_reader_stops_after_one_byte_past_limit() {
    let mut reader = std::io::Cursor::new(b"frame grew beyond checked metadata");
    let error = read_pinned_bytes(&mut reader, 5, &sha256(b"frame"), "fixture").unwrap_err();
    assert!(error.contains("exceeds its read limit"));
    assert_eq!(reader.position(), 6);
    assert!(
        read_pinned_bytes(std::io::repeat(b'x'), 5, &sha256(b"xxxxx"), "fixture")
            .unwrap_err()
            .contains("exceeds its read limit")
    );
}

#[test]
fn pinned_reader_rejects_hash_mismatch_and_overflowing_limit() {
    assert!(
        read_pinned_bytes(&b"changed"[..], 7, &sha256(b"trusted"), "fixture")
            .unwrap_err()
            .contains("changed from the frozen frame run")
    );
    let mut reader = std::io::Cursor::new(b"unread");
    assert!(
        read_pinned_bytes(&mut reader, u64::MAX, &sha256(b"unread"), "fixture")
            .unwrap_err()
            .contains("read limit is invalid")
    );
    assert_eq!(reader.position(), 0);
}

#[test]
fn pinned_reader_preserves_io_failure_as_error() {
    struct BrokenReader;
    impl std::io::Read for BrokenReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("fixture read failed"))
        }
    }
    let error = read_pinned_bytes(BrokenReader, 5, &sha256(b"frame"), "fixture").unwrap_err();
    assert!(error.contains("failed to read historical-v2 fixture"));
    assert!(error.contains("fixture read failed"));
}

#[test]
fn pinned_file_rejects_relative_directory_oversized_and_changed_inputs() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("frame.json");
    fs::write(&path, b"frame").unwrap();
    let hash = sha256(b"frame");
    assert_eq!(
        read_pinned_file(&path, 5, &hash, "fixture").unwrap(),
        b"frame"
    );
    assert!(read_pinned_file(Path::new("relative.json"), 5, &hash, "fixture").is_err());
    assert!(read_pinned_file(root.path(), 5, &hash, "fixture").is_err());
    assert!(read_pinned_file(&path, 4, &hash, "fixture").is_err());
    fs::write(&path, b"other").unwrap();
    assert!(
        read_pinned_file(&path, 5, &hash, "fixture")
            .unwrap_err()
            .contains("changed from the frozen frame run")
    );
}

#[test]
#[cfg(any(unix, windows))]
fn pinned_file_rejects_symlink_even_with_matching_bytes() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("trusted.json");
    let link = root.path().join("alias.json");
    fs::write(&target, b"frame").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &link).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&target, &link).unwrap();
    assert!(
        read_pinned_file(&link, 5, &sha256(b"frame"), "fixture")
            .unwrap_err()
            .contains("not a plain bounded file")
    );
}

#[test]
fn committed_v2_temporal_proof_has_stable_bytes_and_commitments() {
    assert_eq!(
        sha256(COMMITTED_V2_TEMPORAL_PROOF),
        "ba068b5f9fe011b0c7874c0c6d708477fb2cf56ce383e8c410c993c46403e27f"
    );
    let mut proof: HistoricalV3PriorV2TemporalProof =
        serde_json::from_slice(COMMITTED_V2_TEMPORAL_PROOF).unwrap();
    assert_eq!(
        proof.schema_version,
        HISTORICAL_V3_PRIOR_V2_TEMPORAL_PROOF_SCHEMA_VERSION
    );
    assert_eq!(proof.contract, HISTORICAL_V2_TEMPORAL_CONTRACT);
    assert_eq!(proof.frame_file_sha256, FRAME_FILE_SHA256);
    assert_eq!(proof.selection_file_sha256, SELECTION_FILE_SHA256);
    assert_eq!(proof.cutoff_utc, HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC);
    assert_eq!(proof.witnesses.len(), 664);
    assert!(proof.latest_witness_utc < proof.cutoff_utc);
    assert!(
        proof
            .witnesses
            .windows(2)
            .all(|pair| { pair[0].canonical_repository < pair[1].canonical_repository })
    );
    let committed_sha = std::mem::take(&mut proof.proof_sha256);
    assert_eq!(committed_sha, sha256(&serde_json::to_vec(&proof).unwrap()));
}

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
fn temporal_proof_covers_selected_rows_before_cutoff() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (frame, exclusions, selection) = synthetic_inputs();
    let frame_bytes = serde_json::to_vec(&frame).unwrap();
    let selection_bytes = serde_json::to_vec(&selection).unwrap();
    let seal = derive_prior_seal(
        root,
        PROTOCOL,
        &frame_bytes,
        &serde_json::to_vec(&exclusions).unwrap(),
        &selection_bytes,
    )
    .unwrap();
    let proof =
        derive_prior_v2_temporal_proof(&seal, &frame, &selection, &frame_bytes, &selection_bytes)
            .unwrap();
    assert_eq!(proof.witnesses.len(), 1);
    assert_eq!(
        proof.witnesses[0].canonical_repository,
        "unique-v3-prior-fixture/repo"
    );
    assert_eq!(proof.witnesses[0].global_row_index, 0);
    assert_eq!(proof.witnesses[0].pull_number, 1);
    assert_eq!(proof.latest_witness_utc, "2026-01-01T00:00:00Z");
    assert_eq!(proof.prior_seal_sha256, seal.seal_sha256);
}

#[test]
fn temporal_proof_rejects_missing_wrong_and_late_rows() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (frame, exclusions, selection) = synthetic_inputs();
    let frame_bytes = serde_json::to_vec(&frame).unwrap();
    let selection_bytes = serde_json::to_vec(&selection).unwrap();
    let seal = derive_prior_seal(
        root,
        PROTOCOL,
        &frame_bytes,
        &serde_json::to_vec(&exclusions).unwrap(),
        &selection_bytes,
    )
    .unwrap();
    let prove = |frame: &HistoricalV2Frame, selection: &HistoricalV2SlotSelection| {
        derive_prior_v2_temporal_proof(&seal, frame, selection, &frame_bytes, &selection_bytes)
            .unwrap_err()
    };
    let mut missing = selection.clone();
    if let HistoricalV2SlotOutcome::Selected {
        global_row_index, ..
    } = &mut missing
        .slots
        .iter_mut()
        .find(|slot| matches!(slot.outcome, HistoricalV2SlotOutcome::Selected { .. }))
        .unwrap()
        .outcome
    {
        *global_row_index = usize::MAX;
    }
    assert!(prove(&frame, &missing).contains("row is missing"));

    let mut wrong = frame.clone();
    wrong.records[0].canonical_repository = Some("wrong/repo".to_string());
    assert!(prove(&wrong, &selection).contains("does not match"));

    let mut late = frame.clone();
    late.records[0].created_at = HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC.to_string();
    assert!(prove(&late, &selection).contains("not before"));

    let mut malformed = frame.clone();
    malformed.records[0].created_at = "2026-01-01\u{e9}00:00:0".to_string();
    assert!(prove(&malformed, &selection).contains("invalid historical-v3 UTC timestamp"));

    for signed in ["2026-+1-01T00:00:00Z", "2026-+1-01 00:00:00"] {
        malformed.records[0].created_at = signed.to_string();
        assert!(prove(&malformed, &selection).contains("invalid historical-v3 UTC month"));
    }

    let mut legacy = frame;
    legacy.records[0].created_at = "2026-01-01 00:00:00".to_string();
    let proof =
        derive_prior_v2_temporal_proof(&seal, &legacy, &selection, &frame_bytes, &selection_bytes)
            .unwrap();
    assert_eq!(proof.witnesses[0].created_at_utc, "2026-01-01T00:00:00Z");
}

#[test]
fn temporal_proof_rejects_incomplete_seal_coverage() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (frame, exclusions, selection) = synthetic_inputs();
    let frame_bytes = serde_json::to_vec(&frame).unwrap();
    let selection_bytes = serde_json::to_vec(&selection).unwrap();
    let mut seal = derive_prior_seal(
        root,
        PROTOCOL,
        &frame_bytes,
        &serde_json::to_vec(&exclusions).unwrap(),
        &selection_bytes,
    )
    .unwrap();
    seal.inputs
        .iter_mut()
        .find(|input| input.artifact_id == "historical-v2")
        .unwrap()
        .repositories
        .push("unused/repo".to_string());
    assert!(
        derive_prior_v2_temporal_proof(&seal, &frame, &selection, &frame_bytes, &selection_bytes,)
            .unwrap_err()
            .contains("do not cover")
    );
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

#[test]
#[cfg(feature = "sniffbench-frame")]
#[ignore = "requires the frozen historical-v2 frame artifact on disk"]
fn verifies_real_frozen_v2_temporal_proof() {
    let directory = std::env::var_os("SNIFF_HISTORICAL_V2_FRAME_DIR")
        .expect("set SNIFF_HISTORICAL_V2_FRAME_DIR");
    let source_root = std::env::var_os("SNIFF_HISTORICAL_V2_SOURCE_ROOT")
        .expect("set SNIFF_HISTORICAL_V2_SOURCE_ROOT");
    let dataset_root = std::env::var_os("SNIFF_HISTORICAL_V2_DATASET_ROOT")
        .expect("set SNIFF_HISTORICAL_V2_DATASET_ROOT to the exact pinned Parquet shards");
    let directory = Path::new(&directory);
    let source_root = Path::new(&source_root);
    let dataset_root = Path::new(&dataset_root);
    let frame = directory.join("frame.json");
    let exclusions = directory.join("exclusions.json");
    let selection = directory.join("selection.json");
    let proof = derive_frozen_historical_v3_prior_v2_temporal_proof(
        source_root,
        dataset_root,
        &frame,
        &exclusions,
        &selection,
    )
    .unwrap();
    assert_eq!(proof.witnesses.len(), 664);
    assert!(proof.latest_witness_utc < proof.cutoff_utc);
    let committed: HistoricalV3PriorV2TemporalProof =
        serde_json::from_slice(COMMITTED_V2_TEMPORAL_PROOF).unwrap();
    assert_eq!(
        proof, committed,
        "committed historical-v2 temporal proof differs from the pinned source replay"
    );
    validate_frozen_historical_v3_prior_v2_temporal_proof(
        source_root,
        dataset_root,
        &frame,
        &exclusions,
        &selection,
        &committed,
    )
    .unwrap();
    let mut tampered = committed;
    tampered.latest_witness_utc = "2026-01-01T00:00:00Z".to_string();
    assert!(
        validate_frozen_historical_v3_prior_v2_temporal_proof(
            source_root,
            dataset_root,
            &frame,
            &exclusions,
            &selection,
            &tampered,
        )
        .unwrap_err()
        .contains("does not replay")
    );
}
