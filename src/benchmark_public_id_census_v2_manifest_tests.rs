use super::*;
use std::fs;
use tempfile::TempDir;

fn fixture() -> (TempDir, PublicIdCensusV2Manifest) {
    let (policy, preflight, exchanges, replay) = super::super::replay::tests::fixture_transcript();
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("raw")).unwrap();
    fs::create_dir(root.path().join("frames")).unwrap();
    fs::write(
        root.path().join("preflight.json"),
        serde_json::to_vec(&preflight).unwrap(),
    )
    .unwrap();
    let fetched_contract = ARTIFACT_CONTRACT.replace("\r\n", "\n");
    let contract_preflight = PublicIdCensusV2ContractPreflight {
        public_contract_url: format!(
            "https://raw.githubusercontent.com/trysniff/sniff/{}/sniffbench/historical-v3-id-census-v2/artifact-contract.json",
            "a".repeat(40)
        ),
        fetched_contract_sha256: sha256(fetched_contract.as_bytes()),
        fetched_contract,
        fetched_at_utc: "2026-09-27T00:00:01Z".to_string(),
        response_status: 200,
    };
    fs::write(
        root.path().join("contract-preflight.json"),
        serde_json::to_vec(&contract_preflight).unwrap(),
    )
    .unwrap();
    let exchange_paths = exchanges
        .iter()
        .enumerate()
        .map(|(sequence, exchange)| {
            let relative = format!("raw/{sequence:08}.json");
            fs::write(
                root.path().join(&relative),
                serde_json::to_vec(exchange).unwrap(),
            )
            .unwrap();
            relative
        })
        .collect::<Vec<_>>();
    let mut frame_paths = BTreeMap::new();
    for language in &policy.languages {
        let relative = format!("frames/{}.csv", language.to_ascii_lowercase());
        fs::write(root.path().join(&relative), &replay.frames[language]).unwrap();
        frame_paths.insert(language.clone(), relative);
    }
    fs::write(
        root.path().join("null-ledger.json"),
        public_id_census_v2_null_ledger_bytes(&replay).unwrap(),
    )
    .unwrap();
    let manifest = prepare_public_id_census_v2_manifest(
        policy,
        preflight,
        contract_preflight,
        root.path(),
        &exchange_paths,
        &frame_paths,
    )
    .unwrap();
    (root, manifest)
}

#[test]
fn manifest_replays_six_frames_and_null_ledger() {
    let (root, manifest) = fixture();
    assert_eq!(manifest.schema_version, 1);
    assert_eq!(manifest.frames.len(), 6);
    assert_eq!(manifest.crawled_null_count, 1);
    assert_eq!(manifest.probe_only_null_count, 0);
    assert_eq!(manifest.listed_repository_count, 5);
    validate_public_id_census_v2_manifest(&manifest, root.path()).unwrap();
    assert_eq!(manifest.manifest_sha256.len(), 64);
}

#[test]
fn contract_preflight_must_be_bound_and_precede_all_source_attempts() {
    let (root, manifest) = fixture();
    fs::write(root.path().join("contract-preflight.json"), b"{}").unwrap();
    assert!(validate_public_id_census_v2_manifest(&manifest, root.path()).is_err());

    let (root, mut manifest) = fixture();
    manifest.contract_preflight.fetched_at_utc = "2026-09-29T00:00:00Z".to_string();
    let bytes = serde_json::to_vec(&manifest.contract_preflight).unwrap();
    fs::write(root.path().join("contract-preflight.json"), &bytes).unwrap();
    manifest.contract_preflight_artifact_sha256 = sha256(&bytes);
    manifest.manifest_sha256 = manifest.computed_manifest_sha256().unwrap();
    assert!(validate_public_id_census_v2_manifest(&manifest, root.path()).is_err());
}

#[test]
fn manifest_reader_requires_exact_canonical_file_bytes() {
    let (root, manifest) = fixture();
    let path = root.path().join("manifest.json");
    fs::write(
        &path,
        public_id_census_v2_manifest_bytes(&manifest).unwrap(),
    )
    .unwrap();
    assert_eq!(
        read_public_id_census_v2_manifest(root.path()).unwrap(),
        manifest
    );
    fs::write(&path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    assert!(read_public_id_census_v2_manifest(root.path()).is_err());
    assert!(validate_public_id_census_v2_manifest(&manifest, root.path()).is_err());
}

#[test]
fn changed_ledger_is_rejected_even_with_recomputed_hashes() {
    let (root, mut manifest) = fixture();
    let path = root.path().join("null-ledger.json");
    let mut ledger: PublicIdCensusV2NullLedger =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    ledger.records[0].crawled = false;
    let bytes = serde_json::to_vec(&ledger).unwrap();
    fs::write(path, &bytes).unwrap();
    manifest.null_ledger_artifact_sha256 = sha256(&bytes);
    manifest.manifest_sha256 = manifest.computed_manifest_sha256().unwrap();
    assert!(validate_public_id_census_v2_manifest(&manifest, root.path()).is_err());
}

#[test]
fn changed_raw_exchange_or_recomputed_count_is_rejected() {
    let (root, manifest) = fixture();
    fs::write(root.path().join("raw/00000001.json"), b"{}").unwrap();
    assert!(validate_public_id_census_v2_manifest(&manifest, root.path()).is_err());

    let (root, mut manifest) = fixture();
    manifest.crawled_null_count += 1;
    manifest.manifest_sha256 = manifest.computed_manifest_sha256().unwrap();
    assert!(validate_public_id_census_v2_manifest(&manifest, root.path()).is_err());
}

#[test]
fn extra_raw_or_frame_file_is_not_part_of_the_manifest() {
    let (root, manifest) = fixture();
    fs::write(root.path().join("raw/unlisted.json"), b"{}").unwrap();
    assert!(validate_public_id_census_v2_manifest(&manifest, root.path()).is_err());

    let (root, manifest) = fixture();
    fs::write(root.path().join("frames/unlisted.csv"), b"repo,metadata\n").unwrap();
    assert!(validate_public_id_census_v2_manifest(&manifest, root.path()).is_err());
}
