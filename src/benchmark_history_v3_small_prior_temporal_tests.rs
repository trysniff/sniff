use super::*;

const POLICY: &[u8] = include_bytes!("../sniffbench/non-blind-v1-selection-policy.json");
const EXCLUSIONS: &[u8] = include_bytes!("../sniffbench/historical-v2-prior-exclusions.json");
const RESPONSE: &[u8] =
    include_bytes!("../sniffbench/historical-v3-small-prior-identities-response.json");

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn proves_policy_bound_research_and_synthetic_repositories() {
    let proof = derive_small_prior_temporal_proof(POLICY, EXCLUSIONS, RESPONSE, root()).unwrap();
    assert_eq!(proof.witnesses.len(), 3);
    assert_eq!(
        proof
            .witnesses
            .iter()
            .map(|witness| witness.repository.as_str())
            .collect::<Vec<_>>(),
        [
            "gabeorlanski/scb-problems",
            "sprocketlab/slop-code-bench",
            "trysniff/sniff",
        ]
    );
    assert_eq!(
        proof.witnesses[2].gold_tree_oid.as_deref(),
        Some(GOLD_TREE_OID)
    );
    validate_small_prior_temporal_proof(POLICY, EXCLUSIONS, RESPONSE, root(), &proof).unwrap();
    let mut changed = proof;
    changed.witnesses[0].github_repository_id += 1;
    assert!(
        validate_small_prior_temporal_proof(POLICY, EXCLUSIONS, RESPONSE, root(), &changed)
            .is_err()
    );
}

#[test]
fn rejects_changed_frozen_policy_and_capture() {
    let mut policy = POLICY.to_vec();
    policy.push(b' ');
    assert!(derive_small_prior_temporal_proof(&policy, EXCLUSIONS, RESPONSE, root()).is_err());
    let mut exclusions = EXCLUSIONS.to_vec();
    exclusions.push(b' ');
    assert!(derive_small_prior_temporal_proof(POLICY, &exclusions, RESPONSE, root()).is_err());
    let mut response = RESPONSE.to_vec();
    response.push(b' ');
    assert!(derive_small_prior_temporal_proof(POLICY, EXCLUSIONS, &response, root()).is_err());
}

#[test]
fn rejects_changed_frozen_partition_membership_and_gold_hash() {
    let original: HistoricalV2ExclusionManifest = serde_json::from_slice(EXCLUSIONS).unwrap();
    for partition in ["slopcodebench", "synthetic-gold-v1"] {
        let mut changed = original.clone();
        changed
            .partitions
            .iter_mut()
            .find(|entry| entry.partition == partition)
            .unwrap()
            .repositories
            .clear();
        assert!(
            validate_exclusion_membership(&changed, root()).is_err(),
            "{partition}"
        );
    }
    let mut changed = original;
    changed
        .partitions
        .iter_mut()
        .find(|entry| entry.partition == "synthetic-gold-v1")
        .unwrap()
        .artifacts[0]
        .artifact_sha256 = "0".repeat(64);
    assert!(validate_exclusion_membership(&changed, root()).is_err());
}

#[test]
fn rejects_changed_identity_revision_tree_and_cutoff() {
    let original: serde_json::Value = serde_json::from_slice(RESPONSE).unwrap();
    for (pointer, changed) in [
        ("/harness/nameWithOwner", serde_json::json!("another/repo")),
        ("/harness/databaseId", serde_json::json!(0)),
        ("/harness/source/oid", serde_json::json!("wrong-revision")),
        ("/problems/source/__typename", serde_json::json!("Tree")),
        ("/synthetic/gold/oid", serde_json::json!("wrong-tree")),
        ("/synthetic/gold/__typename", serde_json::json!("Blob")),
        (
            "/synthetic/createdAt",
            serde_json::json!(HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC),
        ),
        ("/synthetic", serde_json::Value::Null),
    ] {
        let mut changed_response = original.clone();
        *changed_response.pointer_mut(pointer).unwrap() = changed;
        let data: GraphqlData = serde_json::from_value(changed_response).unwrap();
        assert!(validate_response(data).is_err(), "{pointer}");
    }
    let mut duplicate = original;
    duplicate["problems"]["databaseId"] = duplicate["harness"]["databaseId"].clone();
    assert!(validate_response(serde_json::from_value(duplicate).unwrap()).is_err());
}
