use sha2::{Digest, Sha256};
use sniff::benchmark::{
    HISTORICAL_V2_EXCLUSION_MANIFEST_SCHEMA_VERSION, HISTORICAL_V2_FRAME_SCHEMA_VERSION,
    HistoricalV2CandidateOutcome, HistoricalV2ExclusionArtifact, HistoricalV2ExclusionManifest,
    HistoricalV2Frame, HistoricalV2FrameDisposition, HistoricalV2PartitionExclusions,
    HistoricalV2ProjectedRow, HistoricalV2SlotOutcome, derive_historical_v2_frame_record,
    historical_v2_frame_sha256, select_historical_v2_slots,
    validate_historical_v2_exclusion_manifest, validate_historical_v2_protocol,
    validate_historical_v2_slot_selection,
};
use std::collections::BTreeSet;
use std::fs;
use tempfile::TempDir;

const PROTOCOL: &[u8] = include_bytes!("../sniffbench/historical-v2-protocol.json");
const PARTITIONS: [&str; 6] = [
    "blind-oss-v1",
    "historical-v1",
    "intentional-boundary-v1",
    "slopcodebench",
    "synthetic-gold-v1",
    "trim",
];

#[test]
fn freezes_global_repository_unique_no_backfill_slots() {
    let fixture = exclusion_fixture(&["owner/python000"]);
    let records = (0..130)
        .map(|index| {
            projected_record(
                index,
                &format!("owner/python{index:03}"),
                u64::try_from(index + 1).unwrap(),
                "py",
            )
        })
        .collect::<Vec<_>>();
    let frame = committed_frame(records);

    let selection =
        select_historical_v2_slots(PROTOCOL, fixture.root.path(), &frame, &fixture.manifest)
            .unwrap();

    assert_eq!(selection.slots.len(), 768);
    assert_eq!(selection.excluded_partition_count, 1);
    assert_eq!(selection.repository_collision_count, 0);
    assert_eq!(selection.selected_count, 128);
    assert_eq!(selection.language_capacity_count, 1);
    assert_eq!(
        selection
            .slots
            .iter()
            .filter(|slot| slot.language == "python")
            .count(),
        128
    );
    assert!(
        selection
            .slots
            .iter()
            .filter(|slot| slot.language == "python")
            .all(|slot| matches!(slot.outcome, HistoricalV2SlotOutcome::Selected { .. }))
    );
    assert_eq!(
        selection
            .candidate_decisions
            .iter()
            .map(|decision| decision.global_rank)
            .collect::<Vec<_>>(),
        (1..=130).collect::<Vec<_>>()
    );

    let selected_repositories = selection
        .candidate_decisions
        .iter()
        .filter_map(|decision| {
            matches!(
                decision.outcome,
                HistoricalV2CandidateOutcome::Selected { .. }
            )
            .then_some(decision.canonical_repository.as_str())
        })
        .collect::<Vec<_>>();
    assert_eq!(
        selected_repositories.len(),
        selected_repositories
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
    );

    validate_historical_v2_slot_selection(
        PROTOCOL,
        fixture.root.path(),
        &frame,
        &fixture.manifest,
        &selection,
    )
    .unwrap();
}

#[test]
fn lowest_global_rank_claims_a_repository_across_languages() {
    let fixture = exclusion_fixture(&[]);
    let frame = committed_frame(vec![
        projected_record(0, "owner/shared", 1001, "py"),
        projected_record(1, "owner/shared", 1002, "rs"),
    ]);
    let selection =
        select_historical_v2_slots(PROTOCOL, fixture.root.path(), &frame, &fixture.manifest)
            .unwrap();
    let shared = &selection.candidate_decisions;
    assert_eq!(selection.selected_count, 1);
    assert_eq!(selection.repository_collision_count, 1);
    assert!(matches!(
        shared[0].outcome,
        HistoricalV2CandidateOutcome::Selected { .. }
    ));
    assert!(matches!(
        shared[1].outcome,
        HistoricalV2CandidateOutcome::RepositoryAlreadySelected {
            selected_global_row_index
        } if selected_global_row_index == shared[0].global_row_index
    ));
}

#[test]
fn unfilled_slots_remain_explicit_and_cannot_be_mutated() {
    let fixture = exclusion_fixture(&[]);
    let frame = committed_frame(vec![projected_record(0, "owner/one", 1, "go")]);
    let selection =
        select_historical_v2_slots(PROTOCOL, fixture.root.path(), &frame, &fixture.manifest)
            .unwrap();
    assert_eq!(selection.selected_count, 1);
    assert_eq!(selection.unfilled_slot_count, 767);
    assert!(matches!(
        selection.slots[0].outcome,
        HistoricalV2SlotOutcome::Selected { .. }
    ));
    assert!(
        selection.slots[1..128]
            .iter()
            .all(|slot| matches!(slot.outcome, HistoricalV2SlotOutcome::Unfilled))
    );

    let mut changed = selection.clone();
    changed.slots[1].outcome = changed.slots[0].outcome.clone();
    assert!(
        validate_historical_v2_slot_selection(
            PROTOCOL,
            fixture.root.path(),
            &frame,
            &fixture.manifest,
            &changed,
        )
        .is_err()
    );
}

#[test]
fn exclusion_artifact_tampering_fails_closed() {
    let fixture = exclusion_fixture(&["owner/excluded"]);
    validate_historical_v2_exclusion_manifest(PROTOCOL, fixture.root.path(), &fixture.manifest)
        .unwrap();
    fs::write(fixture.root.path().join("blind-oss-v1.json"), b"changed").unwrap();
    assert!(validate_historical_v2_exclusion_manifest(
        PROTOCOL,
        fixture.root.path(),
        &fixture.manifest,
    )
    .is_err());
}

#[test]
fn exclusion_partitions_and_paths_are_exact() {
    let fixture = exclusion_fixture(&[]);
    let mut reordered = fixture.manifest.clone();
    reordered.partitions.swap(0, 1);
    commit_manifest(&mut reordered);
    assert!(
        validate_historical_v2_exclusion_manifest(PROTOCOL, fixture.root.path(), &reordered)
            .is_err()
    );

    let mut unsafe_path = fixture.manifest.clone();
    unsafe_path.partitions[0].artifacts[0].artifact_path = "../outside.json".to_string();
    commit_manifest(&mut unsafe_path);
    assert!(
        validate_historical_v2_exclusion_manifest(PROTOCOL, fixture.root.path(), &unsafe_path)
            .is_err()
    );
}

#[test]
fn candidate_rank_is_recomputed_instead_of_trusted() {
    let fixture = exclusion_fixture(&[]);
    let mut frame = committed_frame(vec![projected_record(0, "owner/one", 1, "kt")]);
    let HistoricalV2FrameDisposition::Eligible { rank_sha256, .. } =
        &mut frame.records[0].disposition
    else {
        panic!("fixture row must be eligible");
    };
    *rank_sha256 = "0".repeat(64);
    frame.frame_sha256 = historical_v2_frame_sha256(&frame).unwrap();
    let error =
        select_historical_v2_slots(PROTOCOL, fixture.root.path(), &frame, &fixture.manifest)
            .unwrap_err();
    assert!(error.contains("candidate rank changed"));
}

#[test]
fn repeated_eligible_pull_request_fails_closed() {
    let fixture = exclusion_fixture(&[]);
    let frame = committed_frame(vec![
        projected_record(0, "owner/repeated", 7, "py"),
        projected_record(1, "owner/repeated", 7, "rs"),
    ]);
    let error =
        select_historical_v2_slots(PROTOCOL, fixture.root.path(), &frame, &fixture.manifest)
            .unwrap_err();
    assert!(error.contains("repeats an eligible pull request"));
}

struct ExclusionFixture {
    root: TempDir,
    manifest: HistoricalV2ExclusionManifest,
}

fn exclusion_fixture(excluded_repositories: &[&str]) -> ExclusionFixture {
    let root = tempfile::tempdir().unwrap();
    let protocol = validate_historical_v2_protocol(PROTOCOL).unwrap();
    let mut partitions = Vec::new();
    for partition in PARTITIONS {
        let artifact_path = format!("{partition}.json");
        let bytes = format!("{{\"partition\":\"{partition}\"}}").into_bytes();
        fs::write(root.path().join(&artifact_path), &bytes).unwrap();
        partitions.push(HistoricalV2PartitionExclusions {
            partition: partition.to_string(),
            artifacts: vec![HistoricalV2ExclusionArtifact {
                artifact_path,
                artifact_sha256: sha256(&bytes),
            }],
            repositories: if partition == "blind-oss-v1" {
                excluded_repositories
                    .iter()
                    .map(|repository| (*repository).to_string())
                    .collect()
            } else {
                Vec::new()
            },
        });
    }
    let mut manifest = HistoricalV2ExclusionManifest {
        schema_version: HISTORICAL_V2_EXCLUSION_MANIFEST_SCHEMA_VERSION,
        protocol_sha256: protocol.protocol_sha256,
        partitions,
        repository_count: excluded_repositories.len(),
        manifest_sha256: String::new(),
    };
    commit_manifest(&mut manifest);
    validate_historical_v2_exclusion_manifest(PROTOCOL, root.path(), &manifest).unwrap();
    ExclusionFixture { root, manifest }
}

fn committed_frame(records: Vec<sniff::benchmark::HistoricalV2FrameRecord>) -> HistoricalV2Frame {
    let protocol = validate_historical_v2_protocol(PROTOCOL).unwrap();
    let mut frame = HistoricalV2Frame {
        schema_version: HISTORICAL_V2_FRAME_SCHEMA_VERSION,
        protocol_sha256: protocol.protocol_sha256,
        dataset_revision: protocol.protocol.dataset.revision,
        ranking_seed: protocol.protocol.selection.ranking_seed,
        shards: Vec::new(),
        row_count: records.len(),
        eligible_count: records.len(),
        excluded_count: 0,
        records,
        frame_sha256: String::new(),
    };
    frame.frame_sha256 = historical_v2_frame_sha256(&frame).unwrap();
    frame
}

fn projected_record(
    global_row_index: usize,
    repository: &str,
    pull_number: u64,
    extension: &str,
) -> sniff::benchmark::HistoricalV2FrameRecord {
    let protocol = validate_historical_v2_protocol(PROTOCOL).unwrap();
    derive_historical_v2_frame_record(
        HistoricalV2ProjectedRow {
            source_shard_index: 0,
            source_row_index: global_row_index,
            global_row_index,
            base_commit: format!("{pull_number:040x}"),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            instance_id: format!("{repository}#{pull_number}"),
            license: "MIT".to_string(),
            patch: format!(
                "diff --git a/src/file.{extension} b/src/file.{extension}\n--- a/src/file.{extension}\n+++ b/src/file.{extension}\n@@ -1,2 +1 @@\n-old one\n-old two\n+new\n"
            ),
            pull_number: i64::try_from(pull_number).unwrap(),
            repo: repository.to_string(),
        },
        &protocol.protocol.selection.ranking_seed,
    )
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn commit_manifest(manifest: &mut HistoricalV2ExclusionManifest) {
    manifest.manifest_sha256 = sha256(
        &serde_json::to_vec(&(
            manifest.schema_version,
            &manifest.protocol_sha256,
            &manifest.partitions,
            manifest.repository_count,
        ))
        .unwrap(),
    );
}
