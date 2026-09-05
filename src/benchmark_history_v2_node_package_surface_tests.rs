use super::*;
use std::fs;
use std::process::Command;

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

#[test]
fn node_package_surface_census_binds_git_targets_and_replays_exactly() {
    let root = tempfile::tempdir().unwrap();
    git(root.path(), &["init", "--quiet"]);
    git(root.path(), &["config", "user.name", "SniffBench"]);
    git(
        root.path(),
        &["config", "user.email", "bench@example.invalid"],
    );
    git(
        root.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/example/node-surfaces.git",
        ],
    );
    fs::create_dir_all(root.path().join("packages/pkg/src")).unwrap();
    fs::write(
        root.path().join("packages/pkg/package.json"),
        r#"{
  "name": "@example/pkg",
  "exports": {
    ".": {"types": "./src/index.ts", "default": "./dist/index.js"},
    "./feature": "./src/feature.ts"
  }
}"#,
    )
    .unwrap();
    fs::write(
        root.path().join("packages/pkg/src/index.ts"),
        "export const value = 1;\n",
    )
    .unwrap();
    fs::write(
        root.path().join("packages/pkg/src/feature.ts"),
        "export const feature = 1;\n",
    )
    .unwrap();
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "--quiet", "-m", "fixture"]);
    let revision = git(root.path(), &["rev-parse", "HEAD"]);
    let repository = "github.com/example/node-surfaces";
    let inventory =
        super::super::inventory_intentional_boundary_repository(repository, &revision, root.path())
            .unwrap();

    let census =
        census_historical_v2_node_package_surfaces(repository, &revision, root.path(), &inventory)
            .unwrap();

    assert_eq!(census.documents.len(), 1);
    assert_eq!(census.exposures.len(), 3);
    assert_eq!(
        census
            .exposure_count_by_entry_kind
            .get(&HistoricalV2NodePackageEntryKind::Exports),
        Some(&3)
    );
    let tracked = census
        .exposures
        .iter()
        .find(|exposure| exposure.target_repository_path == "packages/pkg/src/index.ts")
        .unwrap();
    assert_eq!(
        tracked.target_status,
        HistoricalV2NodePackageTargetStatus::TrackedRegularFile
    );
    assert!(tracked.target_object_id.is_some());
    let missing = census
        .exposures
        .iter()
        .find(|exposure| exposure.target_repository_path == "packages/pkg/dist/index.js")
        .unwrap();
    assert_eq!(
        missing.target_status,
        HistoricalV2NodePackageTargetStatus::MissingFromInventory
    );
    assert_eq!(missing.target_object_id, None);
    validate_historical_v2_node_package_surface_census_commitment(root.path(), &inventory, &census)
        .unwrap();

    let mut tampered = census.clone();
    tampered.exposures[0].public_subpath = "./invented".to_string();
    tampered.exposures[0].exposure_id = exposure_id(&tampered.exposures[0]).unwrap();
    tampered.census_sha256 = node_package_surface_census_sha256(&tampered).unwrap();
    assert!(
        validate_historical_v2_node_package_surface_census_commitment(
            root.path(),
            &inventory,
            &tampered,
        )
        .unwrap_err()
        .contains("changed")
    );
}
