use super::*;
use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn frozen_harness_covers_every_supported_language() {
    let harness = historical_v2_execution_harness().unwrap();
    for language in REQUIRED_LANGUAGES {
        assert!(
            harness
                .supported_images
                .iter()
                .any(|image| image.languages.iter().any(|value| value == language)),
            "missing {language}"
        );
    }
}

#[test]
fn exact_image_resolution_has_no_language_fallback() {
    let harness = historical_v2_execution_harness().unwrap();
    assert_eq!(
        resolve_historical_v2_base_image(&harness, "typescript", "node_20:latest")
            .unwrap()
            .dockerfile_path,
        "base_dockerfiles/Dockerfile_node_20"
    );
    assert!(resolve_historical_v2_base_image(&harness, "python", "node_20").is_err());
    assert!(resolve_historical_v2_base_image(&harness, "rust", "rust_latest").is_err());
}

#[test]
fn changing_any_frozen_policy_breaks_the_commitment() {
    let harness = historical_v2_execution_harness().unwrap();
    let mut changed = harness.clone();
    changed.test_network_enabled = true;
    let bytes = serde_json::to_vec(&changed).unwrap();
    assert!(validate_historical_v2_execution_harness(&bytes).is_err());
}

#[test]
fn malformed_image_inventory_fails_closed() {
    let harness = historical_v2_execution_harness().unwrap();
    let mut changed = harness.clone();
    changed.supported_images[0].dockerfile_path = "../Dockerfile".to_string();
    changed.execution_harness_sha256 = harness_sha256(&changed).unwrap();
    let bytes = serde_json::to_vec(&changed).unwrap();
    assert!(validate_historical_v2_execution_harness(&bytes).is_err());
}

#[test]
fn repository_verifier_binds_clean_git_tree_and_blobs() {
    let root = tempfile::tempdir().unwrap();
    git_ok(root.path(), &["init", "-b", "main"]);
    git_ok(
        root.path(),
        &["config", "user.email", "fixture@example.test"],
    );
    git_ok(root.path(), &["config", "user.name", "Fixture"]);
    fs::create_dir(root.path().join("base_dockerfiles")).unwrap();
    fs::write(
        root.path().join("base_dockerfiles/Dockerfile_node_20"),
        "FROM node:20\n",
    )
    .unwrap();
    git_ok(root.path(), &["add", "."]);
    git_ok(root.path(), &["commit", "-m", "fixture"]);
    git_ok(
        root.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/example/harness.git",
        ],
    );
    let harness = HistoricalV2ExecutionHarness {
        schema_version: 1,
        execution_harness_contract: "fixture".to_string(),
        upstream_repository: "github.com/example/harness".to_string(),
        upstream_revision: git_text(root.path(), &["rev-parse", "HEAD"]),
        base_dockerfiles_tree_oid: git_text(root.path(), &["rev-parse", "HEAD:base_dockerfiles"]),
        execution_platform: "linux/amd64".to_string(),
        install_network_enabled: true,
        test_network_enabled: false,
        dataset_labels_forbidden: true,
        install_failures_are_terminal: true,
        supported_images: vec![HistoricalV2ExecutionBaseImage {
            base_image_name: "node_20".to_string(),
            languages: vec!["typescript".to_string()],
            dockerfile_path: "base_dockerfiles/Dockerfile_node_20".to_string(),
            git_blob_oid: git_text(
                root.path(),
                &["rev-parse", "HEAD:base_dockerfiles/Dockerfile_node_20"],
            ),
        }],
        execution_harness_sha256: "fixture".to_string(),
    };
    validate_harness_repository_identity(root.path(), &harness).unwrap();

    fs::write(
        root.path().join("base_dockerfiles/Dockerfile_node_20"),
        "FROM node:22\n",
    )
    .unwrap();
    assert!(validate_harness_repository_identity(root.path(), &harness).is_err());
}

fn git_ok(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_text(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}
