use sniff::benchmark::{
    HistoricalV2ExclusionManifest, derive_historical_v2_exclusion_manifest,
    validate_historical_v2_exclusion_manifest,
};
use std::fs;
use std::path::{Path, PathBuf};

const PROTOCOL: &[u8] = include_bytes!("../sniffbench/historical-v2-protocol.json");
const SOURCE_PATHS: [&str; 17] = [
    "gold_fixtures/repo/go/main.go",
    "gold_fixtures/repo/go/math.go",
    "gold_fixtures/repo/helpers.py",
    "gold_fixtures/repo/helpers.ts",
    "gold_fixtures/repo/javascript/helpers.js",
    "gold_fixtures/repo/javascript/main.js",
    "gold_fixtures/repo/kotlin/main.kt",
    "gold_fixtures/repo/kotlin/math.kt",
    "gold_fixtures/repo/python_main.py",
    "gold_fixtures/repo/rust/main.rs",
    "gold_fixtures/repo/rust/math.rs",
    "gold_fixtures/repo/ts_main.ts",
    "sniffbench/blind-oss-v1-source-seal.json",
    "sniffbench/non-blind-v1-history-worksheet.json",
    "sniffbench/non-blind-v1-intentional-boundary-frame-task.json",
    "sniffbench/non-blind-v1-intentional-boundary-protocol.json",
    "sniffbench/non-blind-v1-selection-policy.json",
];

#[test]
fn derives_the_real_six_partition_manifest_deterministically() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let first = derive_historical_v2_exclusion_manifest(PROTOCOL, root).unwrap();
    let second = derive_historical_v2_exclusion_manifest(PROTOCOL, root).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.repository_count, 615);
    assert_eq!(partition_counts(&first), [12, 600, 600, 2, 1, 0]);
    assert_eq!(artifact_counts(&first), [1, 3, 5, 1, 12, 1]);
    validate_historical_v2_exclusion_manifest(PROTOCOL, root, &first).unwrap();
}

#[test]
fn changed_source_commitment_fails_derivation() {
    let fixture = copied_fixture();
    let path = fixture
        .path()
        .join("sniffbench/non-blind-v1-history-worksheet.json");
    let mut worksheet: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    worksheet["candidates"][0]["repository"] = serde_json::json!("github.com/changed/repo");
    fs::write(&path, serde_json::to_vec_pretty(&worksheet).unwrap()).unwrap();
    assert!(derive_historical_v2_exclusion_manifest(PROTOCOL, fixture.path()).is_err());
}

#[test]
fn missing_or_extra_gold_source_fails_derivation() {
    let missing = copied_fixture();
    fs::remove_file(missing.path().join("gold_fixtures/repo/helpers.py")).unwrap();
    assert!(derive_historical_v2_exclusion_manifest(PROTOCOL, missing.path()).is_err());

    let extra = copied_fixture();
    fs::write(
        extra.path().join("gold_fixtures/repo/extra.py"),
        b"def extra(): pass\n",
    )
    .unwrap();
    assert!(derive_historical_v2_exclusion_manifest(PROTOCOL, extra.path()).is_err());
}

fn copied_fixture() -> tempfile::TempDir {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture = tempfile::tempdir().unwrap();
    for relative in SOURCE_PATHS {
        let destination = fixture.path().join(native_path(relative));
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::copy(source_root.join(native_path(relative)), destination).unwrap();
    }
    fixture
}

fn native_path(relative: &str) -> PathBuf {
    relative.split('/').collect()
}

fn partition_counts(manifest: &HistoricalV2ExclusionManifest) -> [usize; 6] {
    manifest
        .partitions
        .iter()
        .map(|partition| partition.repositories.len())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn artifact_counts(manifest: &HistoricalV2ExclusionManifest) -> [usize; 6] {
    manifest
        .partitions
        .iter()
        .map(|partition| partition.artifacts.len())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}
