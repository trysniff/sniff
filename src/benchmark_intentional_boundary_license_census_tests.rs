use super::*;
use crate::benchmark::{
    IntentionalBoundaryMaterializationOutcome, census_intentional_boundary_repository_stage,
    inventory_intentional_boundary_repository_typed,
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

struct Fixture {
    _state: tempfile::TempDir,
    task: IntentionalBoundaryFrameTask,
    materialization: IntentionalBoundaryMaterialization,
    inventory: IntentionalBoundaryRepositoryInventory,
    source_census: IntentionalBoundarySourceCensusStage,
    root: std::path::PathBuf,
}

fn materialize(source: &Path) -> Fixture {
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
    let source_outcome = census_intentional_boundary_repository_stage(
        &task,
        &completed.artifact,
        &completed.checkout_root,
        &inventory,
    )
    .unwrap();
    let IntentionalBoundarySourceCensusStageOutcome::Completed(source_census) = source_outcome
    else {
        panic!("fixture must contain supported source");
    };
    Fixture {
        _state: state,
        task,
        materialization: completed.artifact,
        inventory,
        source_census,
        root: completed.checkout_root,
    }
}

fn census(fixture: &Fixture) -> IntentionalBoundaryLicenseCensusStageOutcome {
    census_intentional_boundary_repository_licenses(
        &fixture.task,
        &fixture.materialization,
        &fixture.root,
        &fixture.inventory,
        &fixture.source_census,
    )
    .unwrap()
}

#[test]
fn completes_with_every_nonempty_committed_license_candidate() {
    let source = repository(&[
        ("src/lib.rs", b"pub fn value() -> u8 { 1 }\n"),
        ("LICENSE", b"sample license\n"),
        ("LICENSES/MIT.txt", b"secondary license\n"),
        ("docs/LICENSE", b"out of scope\n"),
    ]);
    let fixture = materialize(source.path());
    let outcome = census(&fixture);
    let IntentionalBoundaryLicenseCensusStageOutcome::Completed(stage) = &outcome else {
        panic!("non-empty license files must complete");
    };

    assert_eq!(stage.population_rank, 1);
    assert_eq!(stage.inventory_sha256, fixture.inventory.inventory_sha256);
    assert_eq!(
        stage.source_census_stage_sha256,
        fixture.source_census.stage_sha256
    );
    assert_eq!(stage.matched_candidate_count, 2);
    assert_eq!(
        stage
            .license_artifacts
            .iter()
            .map(|artifact| artifact.repository_path.as_str())
            .collect::<Vec<_>>(),
        ["LICENSE", "LICENSES/MIT.txt"]
    );
    assert!(stage.rejected_candidates.is_empty());
    assert_eq!(stage.stage_sha256.len(), 64);
    validate_intentional_boundary_license_census_stage_outcome(
        &fixture.task,
        &fixture.materialization,
        &fixture.root,
        &fixture.inventory,
        &fixture.source_census,
        &outcome,
    )
    .unwrap();
}

#[test]
fn excludes_missing_license_only_after_complete_tree_inspection() {
    let source = repository(&[
        ("src/lib.rs", b"pub fn value() -> u8 { 1 }\n"),
        ("docs/LICENSE", b"not a root license candidate\n"),
        ("README.md", b"fixture\n"),
    ]);
    let fixture = materialize(source.path());
    let outcome = census(&fixture);
    let IntentionalBoundaryLicenseCensusStageOutcome::Excluded(exclusion) = &outcome else {
        panic!("repository without a license candidate must be excluded");
    };

    assert_eq!(
        exclusion.reason,
        IntentionalBoundaryLicenseCensusExclusionReason::MissingLicense
    );
    assert_eq!(
        exclusion.tracked_entry_count,
        fixture.inventory.tracked_entries.len()
    );
    assert_eq!(exclusion.matched_candidate_count, 0);
    assert!(exclusion.rejected_candidates.is_empty());
    assert!(exclusion.failures.is_empty());
    validate_intentional_boundary_license_census_stage_outcome(
        &fixture.task,
        &fixture.materialization,
        &fixture.root,
        &fixture.inventory,
        &fixture.source_census,
        &outcome,
    )
    .unwrap();
}

#[test]
fn rejects_empty_candidates_as_evidence_backed_missing_license() {
    let source = repository(&[
        ("src/lib.rs", b"pub fn value() -> u8 { 1 }\n"),
        ("LICENSE", b" \n\t"),
    ]);
    let fixture = materialize(source.path());
    let outcome = census(&fixture);
    let IntentionalBoundaryLicenseCensusStageOutcome::Excluded(exclusion) = &outcome else {
        panic!("empty license candidate must not count");
    };

    assert_eq!(
        exclusion.reason,
        IntentionalBoundaryLicenseCensusExclusionReason::MissingLicense
    );
    assert_eq!(exclusion.matched_candidate_count, 1);
    assert_eq!(exclusion.rejected_candidates.len(), 1);
    assert!(matches!(
        exclusion.rejected_candidates[0],
        IntentionalBoundaryLicenseCandidateRejection::EmptyOrWhitespace { .. }
    ));
}

#[test]
fn preserves_nonblob_license_candidate_before_unsupported_exclusion() {
    let source = repository(&[
        ("src/lib.rs", b"pub fn value() -> u8 { 1 }\n"),
        ("COPYING", b"real license\n"),
        ("target.txt", b"symlink target\n"),
    ]);
    let target_blob = git(source.path(), &["rev-parse", "HEAD:target.txt"]);
    git(
        source.path(),
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("120000,{target_blob},LICENSE"),
        ],
    );
    git(source.path(), &["commit", "--quiet", "-m", "license link"]);
    git(source.path(), &["checkout", "--force", "HEAD"]);
    let fixture = materialize(source.path());
    let outcome = census(&fixture);
    let IntentionalBoundaryLicenseCensusStageOutcome::Excluded(exclusion) = &outcome else {
        panic!("nonblob candidate must fail closed");
    };

    assert_eq!(
        exclusion.reason,
        IntentionalBoundaryLicenseCensusExclusionReason::UnsupportedProjectShape
    );
    assert_eq!(exclusion.matched_candidate_count, 2);
    assert_eq!(exclusion.failures.len(), 1);
    assert!(matches!(
        exclusion.failures[0],
        IntentionalBoundaryLicenseFailureEvidence::CandidateIsNotBlob {
            entry_kind: BoundaryGitEntryKind::SymbolicLink,
            ..
        }
    ));
}

#[test]
fn replay_rejects_lineage_and_evidence_tampering() {
    let source = repository(&[
        ("src/lib.rs", b"pub fn value() -> u8 { 1 }\n"),
        ("LICENSE", b"sample license\n"),
    ]);
    let fixture = materialize(source.path());
    let mut outcome = census(&fixture);
    let IntentionalBoundaryLicenseCensusStageOutcome::Completed(stage) = &mut outcome else {
        panic!("fixture must complete");
    };
    corrupt_sha256(&mut stage.license_artifacts[0].content_sha256);
    let error = validate_intentional_boundary_license_census_stage_outcome(
        &fixture.task,
        &fixture.materialization,
        &fixture.root,
        &fixture.inventory,
        &fixture.source_census,
        &outcome,
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        IntentionalBoundaryLicenseCensusStageErrorKind::InvalidInput
    );

    let mut changed_source = fixture.source_census.clone();
    corrupt_sha256(&mut changed_source.stage_sha256);
    let error = census_intentional_boundary_repository_licenses(
        &fixture.task,
        &fixture.materialization,
        &fixture.root,
        &fixture.inventory,
        &changed_source,
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        IntentionalBoundaryLicenseCensusStageErrorKind::InvalidInput
    );
}

fn corrupt_sha256(value: &mut String) {
    let replacement = if value.starts_with('0') { "1" } else { "0" };
    value.replace_range(..1, replacement);
}

#[test]
fn preserves_typed_source_and_inventory_error_kinds() {
    let source_error = IntentionalBoundarySourceCensusStageError {
        kind: IntentionalBoundarySourceCensusStageErrorKind::InfrastructureUnavailable,
        detail: "source parser unavailable".to_string(),
    };
    let mapped = map_source_error(source_error);
    assert_eq!(
        mapped.kind,
        IntentionalBoundaryLicenseCensusStageErrorKind::InfrastructureUnavailable
    );

    let inventory_error = IntentionalBoundaryInventoryError {
        kind: IntentionalBoundaryInventoryErrorKind::InfrastructureFailed,
        detail: "bounded Git failed".to_string(),
    };
    let mapped = map_inventory_error(inventory_error);
    assert_eq!(
        mapped.kind,
        IntentionalBoundaryLicenseCensusStageErrorKind::InfrastructureFailed
    );
}
