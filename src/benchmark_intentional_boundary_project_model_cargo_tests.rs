use super::*;
use std::cell::Cell;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

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

fn repository() -> (TempDir, IntentionalBoundaryRepositoryInventory) {
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
            "https://github.com/example/cargo-model.git",
        ],
    );
    for (path, source) in [
        (
            "Cargo.toml",
            "[package]\nname='sample'\nversion='1.2.3'\nedition='2021'\n",
        ),
        ("src/lib.rs", "pub fn api() {}\n"),
        ("src/main.rs", "fn main() {}\n"),
        ("build.rs", "fn main() {}\n"),
        ("examples/demo.rs", "fn main() {}\n"),
    ] {
        let target = root.path().join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(target, source).unwrap();
    }
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "--quiet", "-m", "fixture"]);
    let revision = git(root.path(), &["rev-parse", "HEAD"]);
    let inventory = super::super::inventory_intentional_boundary_repository(
        "github.com/example/cargo-model",
        &revision,
        root.path(),
    )
    .unwrap();
    (root, inventory)
}

fn metadata(root: &Path) -> Vec<u8> {
    let path = |relative: &str| {
        fs::canonicalize(root.join(relative))
            .unwrap()
            .to_string_lossy()
            .into_owned()
    };
    serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "workspace_root": path("."),
        "workspace_members": ["opaque-package-id"],
        "packages": [{
            "id": "opaque-package-id",
            "name": "sample",
            "version": "1.2.3",
            "manifest_path": path("Cargo.toml"),
            "future_package_field": {"ignored": true},
            "targets": [
                {
                    "name": "sample",
                    "kind": ["lib"],
                    "crate_types": ["lib"],
                    "src_path": path("src/lib.rs"),
                    "edition": "2021"
                },
                {
                    "name": "sample",
                    "kind": ["bin"],
                    "crate_types": ["bin"],
                    "src_path": path("src/main.rs"),
                    "required-features": ["cli"]
                },
                {
                    "name": "build-script-build",
                    "kind": ["custom-build"],
                    "crate_types": ["bin"],
                    "src_path": path("build.rs")
                },
                {
                    "name": "demo",
                    "kind": ["example"],
                    "crate_types": ["bin"],
                    "src_path": path("examples/demo.rs")
                },
                {
                    "name": "future",
                    "kind": ["future-kind"],
                    "crate_types": ["future-kind"],
                    "src_path": path("src/lib.rs")
                }
            ]
        }],
        "future_top_level_field": [1, 2, 3]
    }))
    .unwrap()
}

#[test]
fn normalizes_every_cargo_target_to_a_typed_outcome() {
    let (root, inventory) = repository();

    let census = parse_intentional_boundary_cargo_metadata(
        root.path(),
        &inventory,
        "Cargo.toml",
        &"a".repeat(64),
        &metadata(root.path()),
    )
    .unwrap();

    assert_eq!(census.executions.len(), 1);
    assert_eq!(census.targets.len(), 5);
    assert_eq!(census.target_count_by_status.get("boundary"), Some(&3));
    assert_eq!(census.target_count_by_status.get("non_boundary"), Some(&1));
    assert_eq!(census.target_count_by_status.get("unresolved"), Some(&1));
    assert!(census.targets.iter().all(|target| {
        target.target_id.starts_with("ibpmt-v1:")
            && target
                .source_repository_path
                .as_deref()
                .is_some_and(|path| {
                    !path.contains(root.path().to_string_lossy().as_ref()) && !path.contains('\\')
                })
    }));
    assert!(census.targets.iter().any(|target| matches!(
        target.target_status,
        TargetStatus::Boundary {
            declaration_kind: IntentionalBoundaryManifestDeclarationKind::PublishedModule,
            ..
        }
    )));
    assert!(census.targets.iter().any(|target| matches!(
        target.target_status,
        TargetStatus::Unresolved {
            reason: UnresolvedReason::UnknownTargetKind,
            ..
        }
    )));
}

#[test]
fn normalized_cargo_model_identity_does_not_depend_on_checkout_path() {
    let (left_root, left_inventory) = repository();
    let (right_root, right_inventory) = repository();

    let left = parse_intentional_boundary_cargo_metadata(
        left_root.path(),
        &left_inventory,
        "Cargo.toml",
        &"b".repeat(64),
        &metadata(left_root.path()),
    )
    .unwrap();
    let right = parse_intentional_boundary_cargo_metadata(
        right_root.path(),
        &right_inventory,
        "Cargo.toml",
        &"b".repeat(64),
        &metadata(right_root.path()),
    )
    .unwrap();

    assert_eq!(
        left.executions[0].normalized_model_sha256,
        right.executions[0].normalized_model_sha256
    );
    assert_eq!(
        left.executions[0].execution_id,
        right.executions[0].execution_id
    );
    assert_eq!(
        left.targets
            .iter()
            .map(|target| &target.target_id)
            .collect::<Vec<_>>(),
        right
            .targets
            .iter()
            .map(|target| &target.target_id)
            .collect::<Vec<_>>()
    );
}

#[test]
fn records_an_untracked_cargo_source_as_unresolved() {
    let (root, inventory) = repository();
    fs::write(root.path().join("untracked.rs"), "fn hidden() {}\n").unwrap();
    let mut model: serde_json::Value = serde_json::from_slice(&metadata(root.path())).unwrap();
    model["packages"][0]["targets"][0]["src_path"] = serde_json::Value::String(
        fs::canonicalize(root.path().join("untracked.rs"))
            .unwrap()
            .to_string_lossy()
            .into_owned(),
    );

    let census = parse_intentional_boundary_cargo_metadata(
        root.path(),
        &inventory,
        "Cargo.toml",
        &"c".repeat(64),
        &serde_json::to_vec(&model).unwrap(),
    )
    .unwrap();

    assert!(census.targets.iter().any(|target| matches!(
        target.target_status,
        TargetStatus::Unresolved {
            reason: UnresolvedReason::SourceNotTracked,
            ..
        }
    )));
}

#[test]
fn accepts_an_empty_virtual_workspace_as_a_zero_target_execution() {
    let (root, inventory) = repository();
    let output = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "workspace_root": fs::canonicalize(root.path()).unwrap().to_string_lossy(),
        "workspace_members": [],
        "packages": []
    }))
    .unwrap();

    let census = parse_intentional_boundary_cargo_metadata(
        root.path(),
        &inventory,
        "Cargo.toml",
        &"d".repeat(64),
        &output,
    )
    .unwrap();

    assert_eq!(census.executions.len(), 1);
    assert!(census.targets.is_empty());
    assert_eq!(census.executions[0].target_count, 0);
    validate_intentional_boundary_cargo_metadata(
        root.path(),
        &inventory,
        "Cargo.toml",
        &"d".repeat(64),
        &output,
        &census,
    )
    .unwrap();
}

#[test]
fn replay_validation_rejects_project_model_tampering() {
    let (root, inventory) = repository();
    let output = metadata(root.path());
    let mut census = parse_intentional_boundary_cargo_metadata(
        root.path(),
        &inventory,
        "Cargo.toml",
        &"e".repeat(64),
        &output,
    )
    .unwrap();
    census.targets[0].target_id = "invented-target".to_string();

    assert!(
        validate_intentional_boundary_cargo_metadata(
            root.path(),
            &inventory,
            "Cargo.toml",
            &"e".repeat(64),
            &output,
            &census,
        )
        .unwrap_err()
        .contains("changed")
    );
}

#[test]
fn collector_executes_each_uncovered_cargo_workspace_and_commits_the_result() {
    let (root, inventory) = repository();
    let call_count = Cell::new(0);

    let census = census_cargo_project_models_with_executor(
        &inventory.repository,
        &inventory.revision,
        root.path(),
        &inventory,
        |execution_root, manifest_path| {
            call_count.set(call_count.get() + 1);
            assert_eq!(execution_root, root.path());
            assert_eq!(manifest_path, "Cargo.toml");
            Ok(CargoMetadataExecutionOutput {
                toolchain_identity_sha256: "f".repeat(64),
                stdout: String::from_utf8(metadata(root.path())).unwrap(),
            })
        },
    )
    .unwrap();

    assert_eq!(call_count.get(), 1);
    assert_eq!(census.executions.len(), 1);
    assert_eq!(census.targets.len(), 5);
    assert_eq!(
        census
            .execution_count_by_provider
            .get(&Provider::CargoMetadata),
        Some(&1)
    );
}

#[test]
fn collector_rejects_repository_mutation_by_the_metadata_boundary() {
    let (root, inventory) = repository();

    let error = census_cargo_project_models_with_executor(
        &inventory.repository,
        &inventory.revision,
        root.path(),
        &inventory,
        |_, _| {
            fs::write(root.path().join("src/lib.rs"), "pub fn changed() {}\n").unwrap();
            Ok(CargoMetadataExecutionOutput {
                toolchain_identity_sha256: "1".repeat(64),
                stdout: String::from_utf8(metadata(root.path())).unwrap(),
            })
        },
    )
    .unwrap_err();

    assert!(error.contains("dirty") || error.contains("changed"));
}

#[test]
fn real_cargo_metadata_runs_through_the_hardened_sandbox() {
    let (root, inventory) = repository();

    let census = census_intentional_boundary_cargo_project_models(
        &inventory.repository,
        &inventory.revision,
        root.path(),
        &inventory,
    )
    .unwrap();

    assert_eq!(census.executions.len(), 1);
    assert_eq!(census.executions[0].provider, Provider::CargoMetadata);
    assert_eq!(census.target_count_by_status.get("boundary"), Some(&3));
    assert_eq!(census.target_count_by_status.get("non_boundary"), Some(&1));
    assert!(!census.target_count_by_status.contains_key("unresolved"));
    assert!(
        !root.path().join("Cargo.lock").exists(),
        "Cargo metadata must not create a lockfile in the immutable checkout"
    );
}
