use super::*;
use crate::benchmark::{SourceSnapshot, write_test_source_seal};
use std::fs;

fn fixture() -> (tempfile::TempDir, BenchmarkSourceSeal, String) {
    let root = tempfile::tempdir().unwrap();
    let source = "pub fn first() -> i32 { 1 }\npub fn second() -> i32 { 2 }\n";
    fs::write(root.path().join("blind.rs"), source).unwrap();
    let snapshots = vec![SourceSnapshot {
        repository: "https://github.com/example/blind".to_string(),
        revision: "1".repeat(40),
        repository_path: "src/blind.rs".to_string(),
        artifact_path: "blind.rs".to_string(),
        sha256: format!("{:x}", Sha256::digest(source.as_bytes())),
    }];
    let (seal_path, seal_hash, _) = write_test_source_seal(root.path(), &snapshots);
    let seal = serde_json::from_slice(&fs::read(root.path().join(seal_path)).unwrap()).unwrap();
    (root, seal, seal_hash)
}

#[test]
fn assignments_replay_with_exact_census_and_two_slots() {
    let (root, seal, seal_hash) = fixture();
    let task = prepare_label_review(&seal, root.path(), &seal_hash).unwrap();
    let excluded = vec![task.methods[0].method_id.clone()];
    let manifest = prepare_model_review_assignments(
        &seal,
        root.path(),
        &seal_hash,
        b"source-only prompt v1",
        8,
        &excluded,
    )
    .unwrap();
    assert_eq!(manifest.included_method_count, 1);
    assert_eq!(manifest.excluded_method_ids, excluded);
    assert_eq!(manifest.shards.len(), 1);
    assert_eq!(
        manifest.shards[0].method_ids,
        vec![task.methods[1].method_id.clone()]
    );
    assert_eq!(manifest.shards[0].reviewer_slots, 2);
    validate_model_review_assignments(
        &seal,
        root.path(),
        &seal_hash,
        b"source-only prompt v1",
        &manifest,
    )
    .unwrap();

    let mut forged = manifest.clone();
    forged.shards[0].method_ids[0] = task.methods[0].method_id.clone();
    forged.manifest_sha256 = forged.computed_sha256().unwrap();
    assert!(
        validate_model_review_assignments(
            &seal,
            root.path(),
            &seal_hash,
            b"source-only prompt v1",
            &forged,
        )
        .is_err()
    );
    assert!(
        validate_model_review_assignments(
            &seal,
            root.path(),
            &seal_hash,
            b"different prompt",
            &manifest,
        )
        .is_err()
    );
}

#[test]
fn assignments_reject_unknown_repeated_and_all_excluded_methods() {
    let (root, seal, seal_hash) = fixture();
    let task = prepare_label_review(&seal, root.path(), &seal_hash).unwrap();
    let id = task.methods[0].method_id.clone();
    for exclusions in [vec![id.clone(), id], vec!["unknown".to_string()]] {
        assert!(
            prepare_model_review_assignments(
                &seal,
                root.path(),
                &seal_hash,
                b"prompt",
                8,
                &exclusions,
            )
            .is_err()
        );
    }
    let all = task
        .methods
        .iter()
        .map(|method| method.method_id.clone())
        .collect::<Vec<_>>();
    assert!(
        prepare_model_review_assignments(&seal, root.path(), &seal_hash, b"prompt", 8, &all,)
            .is_err()
    );
    assert!(
        prepare_model_review_assignments(&seal, root.path(), &seal_hash, b"prompt", 9, &[],)
            .is_err()
    );
}
