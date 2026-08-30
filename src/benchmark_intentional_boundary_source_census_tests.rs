use super::*;
use crate::benchmark::inventory_intentional_boundary_repository;
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

fn git_bytes(root: &Path, args: &[&str]) -> Vec<u8> {
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
    output.stdout
}

fn repository() -> (TempDir, String) {
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
            "https://github.com/example/census.git",
        ],
    );
    fs::create_dir_all(root.path().join("src/generated")).unwrap();
    fs::create_dir_all(root.path().join("tests")).unwrap();
    fs::write(
        root.path().join("src/lib.rs"),
        "pub fn production() -> u8 { 1 }\n",
    )
    .unwrap();
    fs::write(
        root.path().join("src/generated/model.rs"),
        "pub fn generated() -> u8 { 2 }\n",
    )
    .unwrap();
    fs::write(
        root.path().join("tests/value.rs"),
        "#[test] fn behavior() { assert_eq!(1, 1); }\n",
    )
    .unwrap();
    fs::write(root.path().join("README.md"), "fixture\n").unwrap();
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "--quiet", "-m", "fixture"]);
    let revision = git(root.path(), &["rev-parse", "HEAD"]);
    (root, revision)
}

#[test]
fn censuses_every_supported_committed_source_without_walker_roles() {
    let (root, revision) = repository();
    let inventory = inventory_intentional_boundary_repository(
        "github.com/example/census",
        &revision,
        root.path(),
    )
    .unwrap();

    let census = census_intentional_boundary_repository(
        "github.com/example/census",
        &revision,
        root.path(),
        &inventory,
    )
    .unwrap();

    assert_eq!(census.tracked_entry_count, 4);
    assert_eq!(census.source_file_count, 3);
    assert_eq!(census.method_count, 3);
    assert_eq!(
        census
            .source_files
            .iter()
            .map(|file| file.repository_path.as_str())
            .collect::<Vec<_>>(),
        ["src/generated/model.rs", "src/lib.rs", "tests/value.rs"]
    );
    validate_intentional_boundary_source_census(
        "github.com/example/census",
        &revision,
        root.path(),
        &inventory,
        &census,
    )
    .unwrap();
}

#[test]
fn parser_consumes_the_verified_blob_bytes_not_a_separate_read() {
    let source = b"pub fn exact() -> u8 { 1 }\n";
    let parsed = crate::parser::parse_source_checked("src/lib.rs", source).unwrap();

    assert_eq!(parsed.source.as_bytes(), source);
    assert_eq!(parsed.methods.len(), 1);
    assert_eq!(parsed.methods[0].name, "exact");
}

#[test]
fn clean_ident_expansion_is_censused_from_the_committed_blob() {
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
            "https://github.com/example/ident.git",
        ],
    );
    fs::create_dir_all(root.path().join("src")).unwrap();
    fs::write(root.path().join(".gitattributes"), "*.rs ident\n").unwrap();
    let committed_source = b"// $Id$\npub fn exact() -> u8 { 1 }\n";
    let source_path = root.path().join("src/lib.rs");
    fs::write(&source_path, committed_source).unwrap();
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "--quiet", "-m", "fixture"]);
    let revision = git(root.path(), &["rev-parse", "HEAD"]);
    let object_id = git(root.path(), &["rev-parse", "HEAD:src/lib.rs"]);

    fs::remove_file(&source_path).unwrap();
    git(root.path(), &["checkout", "--", "src/lib.rs"]);
    let worktree_source = fs::read(&source_path).unwrap();
    let blob_source = git_bytes(root.path(), &["cat-file", "blob", &object_id]);
    assert_ne!(worktree_source, blob_source);
    assert!(String::from_utf8(worktree_source).unwrap().contains("$Id:"));
    assert_eq!(blob_source, committed_source);
    assert!(
        git(
            root.path(),
            &["status", "--porcelain=v1", "--untracked-files=all"]
        )
        .is_empty()
    );

    let inventory = inventory_intentional_boundary_repository(
        "github.com/example/ident",
        &revision,
        root.path(),
    )
    .unwrap();
    let census = census_intentional_boundary_repository(
        "github.com/example/ident",
        &revision,
        root.path(),
        &inventory,
    )
    .unwrap();

    let source = census
        .source_files
        .iter()
        .find(|source| source.repository_path == "src/lib.rs")
        .unwrap();
    assert_eq!(source.object_id, object_id);
    assert_eq!(source.byte_length, committed_source.len() as u64);
    assert_eq!(source.source_sha256, sha256(committed_source));
    assert_eq!(source.methods.len(), 1);
    assert_eq!(source.methods[0].symbol_name, "exact");
}

#[test]
fn replay_rejects_census_tampering() {
    let (root, revision) = repository();
    let inventory = inventory_intentional_boundary_repository(
        "github.com/example/census",
        &revision,
        root.path(),
    )
    .unwrap();
    let mut census = census_intentional_boundary_repository(
        "github.com/example/census",
        &revision,
        root.path(),
        &inventory,
    )
    .unwrap();
    census.source_files[0].methods[0].is_exported = false;

    assert!(
        validate_intentional_boundary_source_census(
            "github.com/example/census",
            &revision,
            root.path(),
            &inventory,
            &census,
        )
        .unwrap_err()
        .contains("changed")
    );
}
