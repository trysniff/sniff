use super::super::validate_historical_v2_materialization_exclusion;
use super::*;
use std::process::Command;

#[test]
fn materializes_exact_base_and_deterministic_patched_tree() {
    let source = tempfile::tempdir().unwrap();
    initialize_repository(source.path());
    fs::write(source.path().join("main.rs"), "fn value() -> i32 { 1 }\n").unwrap();
    git_ok(source.path(), &["add", "."]);
    git_ok(source.path(), &["commit", "-m", "base"]);
    let base = git_text(source.path(), &["rev-parse", "HEAD"]).unwrap();
    fs::write(source.path().join("main.rs"), "fn value() -> i32 { 2 }\n").unwrap();
    let patch = git_text(source.path(), &["diff", "--binary", "HEAD"]).unwrap() + "\n";
    git_ok(source.path(), &["reset", "--hard", "HEAD"]);

    let parent = tempfile::tempdir().unwrap();
    let expected_patch_sha256 = sha256(patch.as_bytes());
    let first = materialize_from_url(
        "github.com/example/repo",
        &source.path().to_string_lossy(),
        &base,
        &patch,
        &expected_patch_sha256,
        &parent.path().join("first"),
    )
    .unwrap();
    let second = materialize_from_url(
        "github.com/example/repo",
        &source.path().to_string_lossy(),
        &base,
        &patch,
        &expected_patch_sha256,
        &parent.path().join("second"),
    )
    .unwrap();

    assert_eq!(first.0, second.0);
    assert_ne!(first.0.base_tree_oid, first.0.patched_tree_oid);
    assert_eq!(
        fs::read_to_string(first.1.patched_root.join("main.rs")).unwrap(),
        "fn value() -> i32 { 2 }\n"
    );
    validate_historical_v2_materialization(&first.0, &first.1).unwrap();
    validate_historical_v2_materialization(&second.0, &second.1).unwrap();

    let crossed = HistoricalV2MaterializedRoots {
        repository_root: first.1.repository_root.clone(),
        base_root: first.1.base_root.clone(),
        patched_root: second.1.patched_root.clone(),
    };
    assert!(validate_historical_v2_materialization(&first.0, &crossed).is_err());
}

#[test]
fn rejects_changed_patch_before_creating_work() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("slot");
    let error = materialize_from_url(
        "github.com/example/repo",
        "unused",
        &"1".repeat(40),
        "patch",
        &"2".repeat(64),
        &root,
    )
    .unwrap_err();
    assert!(error.contains("fixed selection hash"));
    assert!(!root.exists());
}

#[test]
fn unavailable_base_is_a_sealed_terminal_exclusion() {
    let source = tempfile::tempdir().unwrap();
    initialize_repository(source.path());
    fs::write(source.path().join("main.rs"), "fn value() -> i32 { 1 }\n").unwrap();
    git_ok(source.path(), &["add", "."]);
    git_ok(source.path(), &["commit", "-m", "base"]);

    let patch = "not reached\n";
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("slot");
    let outcome = materialize_from_url_typed(
        "github.com/example/repo",
        &source.path().to_string_lossy(),
        &"f".repeat(40),
        patch,
        &sha256(patch.as_bytes()),
        &root,
    )
    .unwrap();
    let HistoricalV2StageResult::Excluded(exclusion) = outcome else {
        panic!("unavailable base revision was not excluded");
    };

    assert_eq!(
        exclusion.reason,
        HistoricalV2MaterializationExclusionReason::BaseRevisionUnavailable
    );
    assert!(matches!(
        exclusion.evidence,
        HistoricalV2MaterializationExclusionEvidence::BaseRevisionUnavailable { .. }
    ));
    validate_historical_v2_materialization_exclusion(&exclusion).unwrap();
    assert!(!root.exists());
}

#[test]
fn rejected_patch_is_not_misclassified_as_infrastructure() {
    let source = tempfile::tempdir().unwrap();
    initialize_repository(source.path());
    fs::write(source.path().join("main.rs"), "fn value() -> i32 { 1 }\n").unwrap();
    git_ok(source.path(), &["add", "."]);
    git_ok(source.path(), &["commit", "-m", "base"]);
    let base = git_text(source.path(), &["rev-parse", "HEAD"]).unwrap();

    let patch = "this is not a Git patch\n";
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("slot");
    let outcome = materialize_from_url_typed(
        "github.com/example/repo",
        &source.path().to_string_lossy(),
        &base,
        patch,
        &sha256(patch.as_bytes()),
        &root,
    )
    .unwrap();
    let HistoricalV2StageResult::Excluded(exclusion) = outcome else {
        panic!("rejected historical patch was not excluded");
    };

    assert_eq!(
        exclusion.reason,
        HistoricalV2MaterializationExclusionReason::HistoricalPatchDoesNotApply
    );
    let HistoricalV2MaterializationExclusionEvidence::HistoricalPatchRejected {
        patch_sha256,
        command,
    } = &exclusion.evidence
    else {
        panic!("rejected patch evidence is missing");
    };
    assert_eq!(patch_sha256, &sha256(patch.as_bytes()));
    assert!(
        command
            .command_label
            .starts_with("git apply --check --index --whitespace=nowarn ")
    );
    validate_historical_v2_materialization_exclusion(&exclusion).unwrap();
    assert!(!root.exists());
}

#[test]
fn exclusion_commitment_rejects_tampering() {
    let revision = "1".repeat(40);
    let patch_sha256 = "2".repeat(64);
    let mut exclusion = seal_materialization_exclusion(
        "github.com/example/repo",
        &revision,
        &patch_sha256,
        HistoricalV2MaterializationExclusionReason::RepositoryUnavailable,
        HistoricalV2MaterializationExclusionEvidence::RepositoryProbe {
            url: "https://github.com/example/repo.git/info/refs?service=git-upload-pack"
                .to_string(),
            status: 404,
        },
    )
    .unwrap();
    validate_historical_v2_materialization_exclusion(&exclusion).unwrap();

    exclusion.exclusion_sha256 = "0".repeat(64);
    assert!(validate_historical_v2_materialization_exclusion(&exclusion).is_err());
}

#[test]
fn changed_patch_is_typed_invalid_input() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("slot");
    let error = materialize_from_url_typed(
        "github.com/example/repo",
        "unused",
        &"1".repeat(40),
        "patch",
        &"2".repeat(64),
        &root,
    )
    .unwrap_err();

    assert_eq!(error.stage, HistoricalV2SlotStage::Materialization);
    assert_eq!(error.kind, HistoricalV2SlotStageErrorKind::InvalidInput);
    assert!(!root.exists());
}

fn initialize_repository(root: &Path) {
    git_ok(root, &["init", "-b", "main"]);
    git_ok(root, &["config", "user.email", "fixture@example.test"]);
    git_ok(root, &["config", "user.name", "Fixture"]);
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
