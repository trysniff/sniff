use super::*;
use crate::benchmark::committed_public_id_census_policy;
use std::time::{SystemTime, UNIX_EPOCH};

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "sniff-public-id-census-manifest-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let Ok(temp) = fs::canonicalize(std::env::temp_dir()) else {
            return;
        };
        let Ok(root) = fs::canonicalize(&self.0) else {
            return;
        };
        if root != temp && root.starts_with(&temp) {
            let _ = fs::remove_dir_all(root);
        }
    }
}

fn fixture() -> (TestRoot, PublicIdCensusManifest) {
    let root = TestRoot::new();
    let policy = committed_public_id_census_policy().unwrap();
    let preflight = super::super::replay::tests::preflight_fixture();
    let exchanges = super::super::replay::tests::transcript();
    let derived = super::super::replay_public_id_census(&policy, &preflight, &exchanges).unwrap();
    fs::create_dir(root.0.join("raw")).unwrap();
    fs::create_dir(root.0.join("frames")).unwrap();
    let exchange_paths = exchanges
        .iter()
        .enumerate()
        .map(|(index, exchange)| {
            let path = format!("raw/{index:03}.json");
            fs::write(root.0.join(&path), serde_json::to_vec(exchange).unwrap()).unwrap();
            path
        })
        .collect::<Vec<_>>();
    let frame_paths = policy
        .languages
        .iter()
        .map(|language| {
            let path = format!("frames/{}.csv", language.to_ascii_lowercase());
            fs::write(root.0.join(&path), &derived.frames[language]).unwrap();
            (language.clone(), path)
        })
        .collect::<BTreeMap<_, _>>();
    let manifest = prepare_public_id_census_manifest(
        policy,
        preflight,
        &root.0,
        &exchange_paths,
        &frame_paths,
    )
    .unwrap();
    (root, manifest)
}

#[test]
fn prepared_manifest_replays_every_raw_exchange_and_six_frames() {
    let (root, manifest) = fixture();
    assert_eq!(manifest.exchanges.len(), 12);
    assert_eq!(manifest.frames.len(), 6);
    assert_eq!(manifest.listed_repository_count, 4);
    assert_eq!(manifest.in_window_repository_count, 2);
    assert_eq!(
        manifest
            .frames
            .iter()
            .map(|frame| frame.repository_count)
            .sum::<usize>(),
        2
    );
    validate_public_id_census_manifest(&manifest, &root.0).unwrap();
}

#[test]
fn rejects_changed_or_missing_raw_exchange() {
    let (root, manifest) = fixture();
    fs::write(
        root.0.join(&manifest.exchanges[0].artifact_path),
        b"{}" as &[u8],
    )
    .unwrap();
    assert!(validate_public_id_census_manifest(&manifest, &root.0).is_err());
    let (root, manifest) = fixture();
    fs::remove_file(root.0.join(&manifest.exchanges[0].artifact_path)).unwrap();
    assert!(validate_public_id_census_manifest(&manifest, &root.0).is_err());
}

#[test]
fn rejects_changed_frame_even_when_manifest_hash_is_recomputed() {
    let (root, mut manifest) = fixture();
    manifest.frames[0].repository_count += 1;
    manifest.manifest_sha256 = manifest.computed_manifest_sha256().unwrap();
    assert!(validate_public_id_census_manifest(&manifest, &root.0).is_err());
}

#[test]
fn rejects_path_escape_and_duplicate_frame_path() {
    let (root, mut manifest) = fixture();
    manifest.exchanges[0].artifact_path = "../outside.json".to_string();
    manifest.manifest_sha256 = manifest.computed_manifest_sha256().unwrap();
    assert!(validate_public_id_census_manifest(&manifest, &root.0).is_err());
    let (root, mut manifest) = fixture();
    manifest.frames[1].artifact_path = manifest.frames[0].artifact_path.clone();
    manifest.manifest_sha256 = manifest.computed_manifest_sha256().unwrap();
    assert!(validate_public_id_census_manifest(&manifest, &root.0).is_err());
}

#[test]
fn rejects_oversized_raw_exchange_before_loading_it() {
    let root = TestRoot::new();
    let path = root.0.join("oversized.json");
    let file = fs::File::create(&path).unwrap();
    file.set_len(MAX_RAW_EXCHANGE_BYTES + 1).unwrap();
    let canonical = canonical_root(&root.0).unwrap();
    assert!(
        read_artifact(&canonical, "oversized.json", MAX_RAW_EXCHANGE_BYTES)
            .unwrap_err()
            .contains("read limit")
    );
}

#[test]
fn rejects_distinct_frame_paths_to_the_same_backing_file() {
    let (root, mut manifest) = fixture();
    let alias = root.0.join("frames/alias.csv");
    fs::hard_link(root.0.join(&manifest.frames[0].artifact_path), &alias).unwrap();
    manifest.frames[1].artifact_path = "frames/alias.csv".to_string();
    manifest.manifest_sha256 = manifest.computed_manifest_sha256().unwrap();
    assert!(
        validate_public_id_census_manifest(&manifest, &root.0)
            .unwrap_err()
            .contains("frame identity or path changed")
    );
}
