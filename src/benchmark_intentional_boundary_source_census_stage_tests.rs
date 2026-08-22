use super::*;
use crate::benchmark::{
    IntentionalBoundaryMaterializationOutcome, inventory_intentional_boundary_repository_typed,
};
use std::fs;
use std::path::Path;
use std::process::Command;

const TASK: &[u8] =
    include_bytes!("../sniffbench/non-blind-v1-intentional-boundary-frame-task.json");

fn task() -> IntentionalBoundaryFrameTask {
    serde_json::from_slice(TASK).unwrap()
}

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn repository(files: &[(&str, &[u8])]) -> tempfile::TempDir {
    let repository = tempfile::tempdir().unwrap();
    git(repository.path(), &["init", "--quiet"]);
    git(repository.path(), &["config", "user.name", "SniffBench"]);
    git(
        repository.path(),
        &["config", "user.email", "sniffbench@example.invalid"],
    );
    for (path, bytes) in files {
        let path = repository.path().join(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, bytes).unwrap();
    }
    git(repository.path(), &["add", "."]);
    git(repository.path(), &["commit", "--quiet", "-m", "fixture"]);
    repository
}

fn materialize(
    source: &Path,
) -> (
    tempfile::TempDir,
    IntentionalBoundaryFrameTask,
    IntentionalBoundaryMaterialization,
    IntentionalBoundaryRepositoryInventory,
    std::path::PathBuf,
) {
    let task = task();
    let state = tempfile::tempdir().unwrap();
    let destination = state.path().join("rank-0001");
    let outcome = super::super::intentional_boundary_materialization::
        materialize_intentional_boundary_repository_fixture(&task, 1, &destination, source)
        .unwrap();
    let IntentionalBoundaryMaterializationOutcome::Completed(completed) = outcome else {
        panic!("committed fixture must materialize");
    };
    let inventory = inventory_intentional_boundary_repository_typed(
        &completed.artifact.repository,
        &completed.artifact.revision,
        &completed.checkout_root,
    )
    .unwrap();
    (
        state,
        task,
        completed.artifact,
        inventory,
        completed.checkout_root,
    )
}

#[test]
fn completes_with_exact_materialization_inventory_and_source_lineage() {
    let source = repository(&[("src/lib.rs", b"pub fn value() -> u8 { 1 }\n")]);
    let (_state, task, materialization, inventory, root) = materialize(source.path());

    let outcome =
        census_intentional_boundary_repository_stage(&task, &materialization, &root, &inventory)
            .unwrap();
    let IntentionalBoundarySourceCensusStageOutcome::Completed(stage) = &outcome else {
        panic!("supported source must complete");
    };

    assert_eq!(stage.population_rank, 1);
    assert_eq!(
        stage.materialization_sha256,
        materialization.materialization_sha256
    );
    assert_eq!(stage.inventory_sha256, inventory.inventory_sha256);
    assert_eq!(stage.source_census.source_file_count, 1);
    assert_eq!(stage.source_census.method_count, 1);
    assert_eq!(stage.stage_sha256.len(), 64);
    validate_intentional_boundary_source_census_stage_outcome(
        &task,
        &materialization,
        &root,
        &inventory,
        &outcome,
    )
    .unwrap();
}

#[test]
fn excludes_only_after_proving_the_complete_tree_has_no_supported_source() {
    let source = repository(&[("README.md", b"fixture\n")]);
    let (_state, task, materialization, inventory, root) = materialize(source.path());

    let outcome =
        census_intentional_boundary_repository_stage(&task, &materialization, &root, &inventory)
            .unwrap();
    let IntentionalBoundarySourceCensusStageOutcome::Excluded(exclusion) = &outcome else {
        panic!("source-free repository must be excluded");
    };

    assert_eq!(
        exclusion.reason,
        IntentionalBoundarySourceCensusExclusionReason::NoSupportedSources
    );
    assert_eq!(exclusion.tracked_entry_count, 1);
    assert!(exclusion.failures.is_empty());
    validate_intentional_boundary_source_census_stage_outcome(
        &task,
        &materialization,
        &root,
        &inventory,
        &outcome,
    )
    .unwrap();
}

#[test]
fn preserves_every_unsupported_shape_failure_before_excluding() {
    let source = repository(&[
        ("README.md", b"fixture\n"),
        ("src/bad.go", b"package sample\nfunc broken( {\n"),
        ("src/non_utf8.py", b"def value():\n    return '\xff'\n"),
    ]);
    let head = git(source.path(), &["rev-parse", "HEAD"]);
    let readme_blob = git(source.path(), &["rev-parse", "HEAD:README.md"]);
    git(
        source.path(),
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{head},vendor/dependency"),
        ],
    );
    git(
        source.path(),
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("120000,{readme_blob},src/link.rs"),
        ],
    );
    git(
        source.path(),
        &["commit", "--quiet", "-m", "unsupported shapes"],
    );
    git(source.path(), &["checkout", "--force", "HEAD"]);
    let (_state, task, materialization, inventory, root) = materialize(source.path());

    let outcome =
        census_intentional_boundary_repository_stage(&task, &materialization, &root, &inventory)
            .unwrap();
    let IntentionalBoundarySourceCensusStageOutcome::Excluded(exclusion) = &outcome else {
        panic!("unsupported project shape must be excluded");
    };

    assert_eq!(
        exclusion.reason,
        IntentionalBoundarySourceCensusExclusionReason::UnsupportedProjectShape
    );
    assert_eq!(exclusion.failures.len(), 4);
    assert!(matches!(
        exclusion.failures[0],
        IntentionalBoundarySourceCensusFailureEvidence::SupportedSourceCannotBeParsed { .. }
    ));
    assert!(matches!(
        exclusion.failures[1],
        IntentionalBoundarySourceCensusFailureEvidence::SupportedSourceIsNotRegularBlob { .. }
    ));
    assert!(matches!(
        exclusion.failures[2],
        IntentionalBoundarySourceCensusFailureEvidence::SupportedSourceIsNotUtf8 { .. }
    ));
    assert!(matches!(
        exclusion.failures[3],
        IntentionalBoundarySourceCensusFailureEvidence::RepositoryContainsGitlink { .. }
    ));
    validate_intentional_boundary_source_census_stage_outcome(
        &task,
        &materialization,
        &root,
        &inventory,
        &outcome,
    )
    .unwrap();
}

#[test]
fn replay_rejects_completed_and_excluded_artifact_tampering() {
    let source = repository(&[("src/lib.rs", b"pub fn value() -> u8 { 1 }\n")]);
    let (_state, task, materialization, inventory, root) = materialize(source.path());
    let mut completed =
        census_intentional_boundary_repository_stage(&task, &materialization, &root, &inventory)
            .unwrap();
    let IntentionalBoundarySourceCensusStageOutcome::Completed(stage) = &mut completed else {
        panic!("fixture must complete");
    };
    stage.source_census.method_count += 1;
    let error = validate_intentional_boundary_source_census_stage_outcome(
        &task,
        &materialization,
        &root,
        &inventory,
        &completed,
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        IntentionalBoundarySourceCensusStageErrorKind::InvalidInput
    );

    let source = repository(&[("README.md", b"fixture\n")]);
    let (_state, task, materialization, inventory, root) = materialize(source.path());
    let mut excluded =
        census_intentional_boundary_repository_stage(&task, &materialization, &root, &inventory)
            .unwrap();
    let IntentionalBoundarySourceCensusStageOutcome::Excluded(exclusion) = &mut excluded else {
        panic!("fixture must be excluded");
    };
    exclusion.tracked_entry_count += 1;
    let error = validate_intentional_boundary_source_census_stage_outcome(
        &task,
        &materialization,
        &root,
        &inventory,
        &excluded,
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        IntentionalBoundarySourceCensusStageErrorKind::InvalidInput
    );
}

#[test]
fn preserves_typed_infrastructure_failures_without_reason_string_parsing() {
    let inventory_error = IntentionalBoundaryInventoryError {
        kind: IntentionalBoundaryInventoryErrorKind::InfrastructureUnavailable,
        detail: "git runtime unavailable".to_string(),
    };
    let mapped = map_inventory_error(inventory_error);
    assert_eq!(
        mapped.kind,
        IntentionalBoundarySourceCensusStageErrorKind::InfrastructureUnavailable
    );
    assert_eq!(mapped.detail, "git runtime unavailable");

    let materialization_error = IntentionalBoundaryMaterializationError {
        kind: IntentionalBoundaryMaterializationErrorKind::InfrastructureFailed,
        detail: "bounded Git execution failed".to_string(),
    };
    let mapped = map_materialization_error(materialization_error);
    assert_eq!(
        mapped.kind,
        IntentionalBoundarySourceCensusStageErrorKind::InfrastructureFailed
    );
    assert_eq!(mapped.detail, "bounded Git execution failed");
}
