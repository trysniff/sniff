#[cfg(unix)]
use super::validate_artifact;
use super::{
    SOURCE_SEAL_SCHEMA_VERSION, SourceRepositoryDraft, SourceSelectionDraft, copy_committed_file,
    create_source_seal,
};
use std::fs;
use std::process::Command;

fn git(root: &std::path::Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn repository() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("src")).unwrap();
    fs::write(
        root.path().join("src/lib.rs"),
        "pub fn selected() -> i32 { 1 }\n",
    )
    .unwrap();
    fs::write(root.path().join("LICENSE"), "test license\n").unwrap();
    git(root.path(), &["init"]);
    git(root.path(), &["config", "user.email", "seal@example.test"]);
    git(root.path(), &["config", "user.name", "Seal Test"]);
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "-m", "fixture"]);
    root
}

fn draft(root: &std::path::Path) -> SourceSelectionDraft {
    SourceSelectionDraft {
        schema_version: SOURCE_SEAL_SCHEMA_VERSION,
        selection_id: "blind-fixture".to_string(),
        selected_at: "2026-08-12T00:00:00Z".to_string(),
        selection_methodology: "Selected without inspecting Sniff output.".to_string(),
        selection_attestation: "No labels or Sniff findings existed at selection time.".to_string(),
        repositories: vec![SourceRepositoryDraft {
            repository: "https://example.test/selected".to_string(),
            revision: git(root, &["rev-parse", "HEAD"]),
            local_path: root.to_string_lossy().into_owned(),
            license_path: "LICENSE".to_string(),
        }],
    }
}

#[test]
fn source_seal_copies_a_clean_revision_and_derives_its_method_census() {
    let repository = repository();
    let bundle = tempfile::tempdir().unwrap();
    let output = bundle.path().join("seal.json");

    let seal = create_source_seal(draft(repository.path()), bundle.path(), &output).unwrap();

    assert_eq!(seal.sources.len(), 1);
    assert_eq!(seal.methods.len(), 1);
    assert_eq!(seal.methods[0].name, "selected");
    assert!(output.is_file());
    assert!(bundle.path().join("seal.sources").is_dir());
}

#[test]
fn source_seal_rejects_dirty_or_revision_mismatched_checkouts() {
    let repository = repository();
    let bundle = tempfile::tempdir().unwrap();
    let mut dirty = draft(repository.path());
    fs::write(repository.path().join("untracked.txt"), "dirty\n").unwrap();

    let error = create_source_seal(
        dirty.clone(),
        bundle.path(),
        &bundle.path().join("dirty.json"),
    )
    .unwrap_err();

    assert!(error.contains("must be clean"));
    fs::remove_file(repository.path().join("untracked.txt")).unwrap();
    dirty.repositories[0].revision = "0".repeat(40);

    let error =
        create_source_seal(dirty, bundle.path(), &bundle.path().join("wrong.json")).unwrap_err();

    assert!(error.contains("revision mismatch"));
}

#[test]
fn source_seal_rejects_sparse_checkouts() {
    let repository = repository();
    let bundle = tempfile::tempdir().unwrap();
    git(
        repository.path(),
        &["config", "core.sparseCheckout", "true"],
    );

    let error = create_source_seal(
        draft(repository.path()),
        bundle.path(),
        &bundle.path().join("sparse.json"),
    )
    .unwrap_err();

    assert!(error.contains("must not use sparse checkout"));
}

#[test]
fn committed_copy_uses_the_declared_revision_instead_of_worktree_bytes() {
    let repository = repository();
    let revision = git(repository.path(), &["rev-parse", "HEAD"]);
    let copied = repository.path().join("copied.rs");
    fs::write(
        repository.path().join("src/lib.rs"),
        "pub fn selected() -> i32 { 2 }\n",
    )
    .unwrap();

    copy_committed_file(
        repository.path(),
        &revision,
        std::path::Path::new("src/lib.rs"),
        &copied,
        "source file",
    )
    .unwrap();

    assert_eq!(
        fs::read_to_string(copied).unwrap(),
        "pub fn selected() -> i32 { 1 }\n"
    );
}

#[cfg(unix)]
#[test]
fn source_seal_artifacts_cannot_escape_through_parent_symlinks() {
    use std::os::unix::fs::symlink;

    let bundle = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("source.rs"), "fn escaped() {}\n").unwrap();
    symlink(outside.path(), bundle.path().join("redirect")).unwrap();

    let error = validate_artifact(
        bundle.path(),
        "redirect/source.rs",
        &"0".repeat(64),
        "source seal source",
    )
    .unwrap_err();

    assert!(error.contains("escapes the source-seal bundle"));
}
