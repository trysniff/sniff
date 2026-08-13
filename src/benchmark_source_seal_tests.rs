use super::super::source_selection::test_selection_artifacts;
#[cfg(unix)]
use super::validate_artifact;
use super::{
    SourceRepositoryDraft, copy_committed_file, create_composite_source_seal, create_source_seal,
    dominant_method_language, validate_source_seal,
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
    let repository = repository_path(&root);
    fs::create_dir_all(repository.join("src")).unwrap();
    fs::write(
        repository.join("src/lib.rs"),
        "pub fn selected() -> i32 { 1 }\n",
    )
    .unwrap();
    fs::write(repository.join("LICENSE"), "test license\n").unwrap();
    git(&repository, &["init"]);
    git(&repository, &["config", "user.email", "seal@example.test"]);
    git(&repository, &["config", "user.name", "Seal Test"]);
    git(&repository, &["add", "."]);
    git(&repository, &["commit", "-m", "fixture"]);
    root
}

fn repository_path(root: &tempfile::TempDir) -> std::path::PathBuf {
    root.path().join("example/selected")
}

fn selection(root: &std::path::Path) -> (super::SourceSelectionDraft, Vec<u8>, Vec<u8>) {
    test_selection_artifacts(vec![SourceRepositoryDraft {
        repository: "https://github.com/example/selected".to_string(),
        revision: git(root, &["rev-parse", "HEAD"]),
        license_path: "LICENSE".to_string(),
        selection_language: "rust".to_string(),
        observed_method_count: 1,
        context_paths: Vec::new(),
    }])
}

fn composite_selection(repositories: Vec<SourceRepositoryDraft>) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut components = Vec::new();
    let mut frames = Vec::new();
    for repository in repositories {
        let (_, audit, frame) =
            super::super::source_selection::test_selection_artifacts(vec![repository]);
        let strict: super::super::SourceSelectionAudit = serde_json::from_slice(&audit).unwrap();
        let mut policy = strict.policy;
        policy.selection_id = format!("test-component-{}", components.len() + 1);
        let mut worksheet = super::super::prepare_source_selection(policy.clone(), &frame).unwrap();
        worksheet.candidates = strict.assessments;
        let component =
            super::super::audit_source_selection_component(policy, &frame, worksheet).unwrap();
        components.push(component);
        frames.push(frame);
    }
    let language_quotas = components
        .iter()
        .flat_map(|component| component.selected_counts.iter())
        .fold(
            std::collections::BTreeMap::new(),
            |mut counts, (language, count)| {
                *counts.entry(language.clone()).or_insert(0) += count;
                counts
            },
        );
    let policy = super::super::SourceSelectionCompositePolicy {
        schema_version: super::super::SOURCE_SELECTION_COMPOSITE_POLICY_SCHEMA_VERSION,
        selection_id: "test-composite-selection".to_string(),
        selected_at: "2026-08-14T00:00:00Z".to_string(),
        language_quotas,
        components: components
            .iter()
            .map(
                |component| super::super::SourceSelectionComponentCommitment {
                    selection_id: component.policy.selection_id.clone(),
                    policy_sha256: component.policy_sha256.clone(),
                    frame_sha256: component.frame_sha256.clone(),
                },
            )
            .collect(),
        attestation: "Fixture components were committed before sealing.".to_string(),
    };
    let audit = super::super::combine_source_selections(policy, components).unwrap();
    let mut bytes = serde_json::to_vec_pretty(&audit).unwrap();
    bytes.push(b'\n');
    (bytes, frames)
}

#[test]
fn source_seal_copies_a_clean_revision_and_derives_its_method_census() {
    let repository = repository();
    let repository_path = repository_path(&repository);
    let bundle = tempfile::tempdir().unwrap();
    let output = bundle.path().join("seal.json");
    let (draft, audit, frame) = selection(&repository_path);

    let seal = create_source_seal(draft, &audit, &frame, repository.path(), &output).unwrap();

    assert_eq!(seal.sources.len(), 1);
    assert_eq!(seal.methods.len(), 1);
    assert_eq!(seal.methods[0].name, "selected");
    assert!(output.is_file());
    assert!(bundle.path().join("seal.sources").is_dir());
}

#[test]
fn composite_source_seal_embeds_and_revalidates_every_component_frame() {
    let repository = repository();
    let repository_path = repository_path(&repository);
    let revision = git(&repository_path, &["rev-parse", "HEAD"]);
    let second_path = repository.path().join("example/second");
    fs::create_dir_all(second_path.join("src")).unwrap();
    fs::write(
        second_path.join("src/lib.py"),
        "def selected():\n    return 1\n",
    )
    .unwrap();
    fs::write(second_path.join("LICENSE"), "test license\n").unwrap();
    git(&second_path, &["init"]);
    git(&second_path, &["config", "user.email", "seal@example.test"]);
    git(&second_path, &["config", "user.name", "Seal Test"]);
    git(&second_path, &["add", "."]);
    git(&second_path, &["commit", "-m", "fixture"]);
    let second_revision = git(&second_path, &["rev-parse", "HEAD"]);
    let (audit, frames) = composite_selection(vec![
        SourceRepositoryDraft {
            repository: "https://github.com/example/selected".to_string(),
            revision,
            license_path: "LICENSE".to_string(),
            selection_language: "rust".to_string(),
            observed_method_count: 1,
            context_paths: Vec::new(),
        },
        SourceRepositoryDraft {
            repository: "https://github.com/example/second".to_string(),
            revision: second_revision,
            license_path: "LICENSE".to_string(),
            selection_language: "python".to_string(),
            observed_method_count: 1,
            context_paths: Vec::new(),
        },
    ]);
    let bundle = tempfile::tempdir().unwrap();
    let output = bundle.path().join("seal.json");

    let seal = create_composite_source_seal(&audit, &frames, repository.path(), &output).unwrap();

    assert_eq!(seal.selection_components.len(), 2);
    assert_eq!(seal.methods.len(), 2);
    validate_source_seal(&seal, bundle.path()).unwrap();
    let frame = bundle
        .path()
        .join(&seal.selection_components[1].frame_artifact_path);
    fs::write(frame, b"tampered\n").unwrap();
    let error = validate_source_seal(&seal, bundle.path()).unwrap_err();
    assert!(error.contains("component frame hash mismatch"));
}

#[test]
fn composite_source_seal_rejects_reordered_frames() {
    let repository = repository();
    let repository_path = repository_path(&repository);
    let revision = git(&repository_path, &["rev-parse", "HEAD"]);
    let (audit, mut frames) = composite_selection(vec![
        SourceRepositoryDraft {
            repository: "https://github.com/example/selected".to_string(),
            revision: revision.clone(),
            license_path: "LICENSE".to_string(),
            selection_language: "rust".to_string(),
            observed_method_count: 1,
            context_paths: Vec::new(),
        },
        SourceRepositoryDraft {
            repository: "https://github.com/example/selected-two".to_string(),
            revision,
            license_path: "LICENSE".to_string(),
            selection_language: "python".to_string(),
            observed_method_count: 1,
            context_paths: Vec::new(),
        },
    ]);
    frames.swap(0, 1);
    let bundle = tempfile::tempdir().unwrap();

    let error = create_composite_source_seal(
        &audit,
        &frames,
        repository.path(),
        &bundle.path().join("seal.json"),
    )
    .unwrap_err();

    assert!(error.contains("component frame hash mismatch"));
}

#[test]
fn source_seal_keeps_tests_as_context_without_inflating_the_method_census() {
    let repository = repository();
    let repository_path = repository_path(&repository);
    fs::create_dir(repository_path.join("tests")).unwrap();
    fs::write(
        repository_path.join("tests/selected.rs"),
        "#[test]\nfn selected_works() { assert_eq!(1, 1); }\n",
    )
    .unwrap();
    git(&repository_path, &["add", "."]);
    git(&repository_path, &["commit", "-m", "add test context"]);
    let bundle = tempfile::tempdir().unwrap();
    let (draft, audit, frame) = selection(&repository_path);

    let seal = create_source_seal(
        draft,
        &audit,
        &frame,
        repository.path(),
        &bundle.path().join("seal.json"),
    )
    .unwrap();

    assert_eq!(seal.methods.len(), 1);
    assert_eq!(seal.context_sources.len(), 1);
    assert_eq!(seal.context_sources[0].repository_path, "tests/selected.rs");
}

#[test]
fn source_seal_rejects_tampered_selection_artifacts() {
    let repository = repository();
    let repository_path = repository_path(&repository);
    let bundle = tempfile::tempdir().unwrap();
    let (draft, audit, frame) = selection(&repository_path);
    let output = bundle.path().join("seal.json");
    let seal = create_source_seal(draft, &audit, &frame, repository.path(), &output).unwrap();
    let audit_path = bundle.path().join(&seal.selection_audit_artifact_path);
    fs::write(audit_path, b"{}\n").unwrap();

    let error = validate_source_seal(&seal, bundle.path()).unwrap_err();

    assert!(error.contains("source selection audit hash mismatch"));
}

#[test]
fn source_seal_rejects_dirty_or_revision_mismatched_checkouts() {
    let repository = repository();
    let repository_path = repository_path(&repository);
    let bundle = tempfile::tempdir().unwrap();
    let (mut dirty, audit, frame) = selection(&repository_path);
    fs::write(repository_path.join("untracked.txt"), "dirty\n").unwrap();

    let error = create_source_seal(
        dirty.clone(),
        &audit,
        &frame,
        repository.path(),
        &bundle.path().join("dirty.json"),
    )
    .unwrap_err();

    assert!(error.contains("must be clean"));
    fs::remove_file(repository_path.join("untracked.txt")).unwrap();
    dirty.repositories[0].revision = "0".repeat(40);

    let error = create_source_seal(
        dirty,
        &audit,
        &frame,
        repository.path(),
        &bundle.path().join("wrong.json"),
    )
    .unwrap_err();

    assert!(error.contains("does not match its audited artifacts"));
}

#[test]
fn source_seal_rejects_sparse_checkouts() {
    let repository = repository();
    let repository_path = repository_path(&repository);
    let bundle = tempfile::tempdir().unwrap();
    git(&repository_path, &["config", "core.sparseCheckout", "true"]);
    let (draft, audit, frame) = selection(&repository_path);

    let error = create_source_seal(
        draft,
        &audit,
        &frame,
        repository.path(),
        &bundle.path().join("sparse.json"),
    )
    .unwrap_err();

    assert!(error.contains("must not use sparse checkout"));
}

#[test]
fn committed_copy_uses_the_declared_revision_instead_of_worktree_bytes() {
    let repository = repository();
    let repository_path = repository_path(&repository);
    let revision = git(&repository_path, &["rev-parse", "HEAD"]);
    let copied = repository_path.join("copied.rs");
    fs::write(
        repository_path.join("src/lib.rs"),
        "pub fn selected() -> i32 { 2 }\n",
    )
    .unwrap();

    copy_committed_file(
        &repository_path,
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

#[test]
fn dominant_method_language_is_counted_with_a_deterministic_tie_break() {
    assert_eq!(
        dominant_method_language(["rust", "python", "rust"].into_iter()),
        Some("rust".to_string())
    );
    assert_eq!(
        dominant_method_language(["typescript", "javascript"].into_iter()),
        Some("javascript".to_string())
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
