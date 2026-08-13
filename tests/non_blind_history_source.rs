use sniff::benchmark::{
    HistoricalDiffHunk, HistoricalRevisionSide, census_historical_source_delta,
    historical_diff_hunks,
};
use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn zero_context_diff_parser_preserves_exact_ranges() {
    let diff = b"diff --git a/src/main.rs b/src/main.rs\n--- a/src/main.rs\n+++ b/src/main.rs\n@@ -2,2 +2 @@ fn target() {\n-old\n-lines\n+new\n";

    let hunks = historical_diff_hunks(None, "src/main.rs", diff).unwrap();

    assert_eq!(
        hunks,
        [HistoricalDiffHunk {
            previous_path: None,
            path: "src/main.rs".to_string(),
            parent_start: 2,
            parent_count: 2,
            commit_start: 2,
            commit_count: 1,
        }]
    );
}

#[test]
fn zero_count_diff_ranges_preserve_their_insertion_coordinates() {
    let added = historical_diff_hunks(None, "src/main.rs", b"@@ -20,0 +21,2 @@\n+a\n+b\n").unwrap();
    let deleted = historical_diff_hunks(None, "src/main.rs", b"@@ -7,2 +6,0 @@\n-a\n-b\n").unwrap();

    assert_eq!((added[0].parent_start, added[0].parent_count), (20, 0));
    assert_eq!((added[0].commit_start, added[0].commit_count), (21, 2));
    assert_eq!((deleted[0].parent_start, deleted[0].parent_count), (7, 2));
    assert_eq!((deleted[0].commit_start, deleted[0].commit_count), (6, 0));
}

#[test]
fn immutable_snapshots_produce_exact_method_and_reduction_census() {
    let fixture = source_fixture();
    let diff = git_bytes(
        fixture.repository.path(),
        &[
            "diff",
            "--unified=0",
            "--no-ext-diff",
            "--no-color",
            &fixture.parent_revision,
            &fixture.commit_revision,
            "--",
            "src/main.rs",
        ],
    );
    let hunks = historical_diff_hunks(None, "src/main.rs", &diff).unwrap();

    let census = census_historical_source_delta(
        &fixture.parent_revision,
        &fixture.commit_revision,
        fixture.parent.path(),
        fixture.commit.path(),
        &hunks,
    )
    .unwrap();

    assert!(census.supported_project_shape);
    assert_eq!(census.parent_method_count, Some(20));
    assert_eq!(census.parent_method_counts["rust"], 20);
    assert_eq!(census.quota_language.as_deref(), Some("rust"));
    assert_eq!(census.license_path.as_deref(), Some("LICENSE"));
    assert_eq!(census.production_paths.len(), 1);
    assert!(census.source_non_whitespace_lines_after < census.source_non_whitespace_lines_before);
    assert!(
        census.affected_methods.iter().any(
            |method| method.symbol == "target" && method.side == HistoricalRevisionSide::Parent
        )
    );
    assert!(
        census.affected_methods.iter().any(
            |method| method.symbol == "target" && method.side == HistoricalRevisionSide::Commit
        )
    );
    assert!(census.parse_failure.is_none());
}

#[test]
fn context_only_hunks_do_not_become_production_changes() {
    let fixture = source_fixture();
    let hunks = historical_diff_hunks(None, "README.md", b"@@ -0,0 +1 @@\n+docs\n").unwrap();

    let census = census_historical_source_delta(
        &fixture.parent_revision,
        &fixture.commit_revision,
        fixture.parent.path(),
        fixture.commit.path(),
        &hunks,
    )
    .unwrap();

    assert_eq!(census.qualifying_production_change, Some(false));
    assert!(census.production_paths.is_empty());
    assert!(census.affected_methods.is_empty());
    assert!(census.quota_language.is_none());
}

#[test]
fn promisor_backed_snapshots_are_rejected() {
    let fixture = source_fixture();
    git(
        fixture.parent.path(),
        &["config", "remote.origin.promisor", "true"],
    );

    let error = census_historical_source_delta(
        &fixture.parent_revision,
        &fixture.commit_revision,
        fixture.parent.path(),
        fixture.commit.path(),
        &[],
    )
    .unwrap_err();

    assert!(error.contains("dirty, shallow, sparse, partial"));
}

#[test]
fn shallow_snapshots_are_rejected() {
    let fixture = source_fixture();
    let shallow = tempfile::tempdir().unwrap();
    let source = format!("file:///{}", fixture.repository.path().display()).replace('\\', "/");
    let output = Command::new("git")
        .args(["clone", "--quiet", "--depth", "1", &source])
        .arg(shallow.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let error = census_historical_source_delta(
        &fixture.commit_revision,
        &fixture.commit_revision,
        shallow.path(),
        fixture.commit.path(),
        &[],
    )
    .unwrap_err();

    assert!(error.contains("dirty, shallow, sparse, partial"));
}

struct SourceFixture {
    repository: tempfile::TempDir,
    parent: tempfile::TempDir,
    commit: tempfile::TempDir,
    parent_revision: String,
    commit_revision: String,
}

fn source_fixture() -> SourceFixture {
    let repository = tempfile::tempdir().unwrap();
    git(repository.path(), &["init", "-b", "main"]);
    git(
        repository.path(),
        &["config", "user.email", "fixture@example.com"],
    );
    git(repository.path(), &["config", "user.name", "Fixture"]);
    fs::create_dir_all(repository.path().join("src")).unwrap();
    fs::write(repository.path().join("LICENSE"), "fixture license\n").unwrap();
    fs::write(repository.path().join("src/main.rs"), parent_source()).unwrap();
    git(repository.path(), &["add", "."]);
    git(repository.path(), &["commit", "-m", "initial"]);
    let parent_revision = git_text(repository.path(), &["rev-parse", "HEAD"]);
    fs::write(repository.path().join("src/main.rs"), commit_source()).unwrap();
    git(repository.path(), &["add", "."]);
    git(repository.path(), &["commit", "-m", "simplify target"]);
    let commit_revision = git_text(repository.path(), &["rev-parse", "HEAD"]);

    let parent = tempfile::tempdir().unwrap();
    let commit = tempfile::tempdir().unwrap();
    clone_at(repository.path(), parent.path(), &parent_revision);
    clone_at(repository.path(), commit.path(), &commit_revision);
    SourceFixture {
        repository,
        parent,
        commit,
        parent_revision,
        commit_revision,
    }
}

fn parent_source() -> String {
    let mut source =
        String::from("fn target() {\n    let value = 1;\n    println!(\"{}\", value);\n}\n");
    for index in 1..20 {
        source.push_str(&format!("fn helper_{index}() {{}}\n"));
    }
    source
}

fn commit_source() -> String {
    let mut source = String::from("fn target() { println!(\"{}\", 1); }\n");
    for index in 1..20 {
        source.push_str(&format!("fn helper_{index}() {{}}\n"));
    }
    source
}

fn clone_at(source: &Path, destination: &Path, revision: &str) {
    let output = Command::new("git")
        .args(["clone", "--quiet", "--no-local"])
        .arg(source)
        .arg(destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    git(destination, &["checkout", "--quiet", "--detach", revision]);
}

fn git(root: &Path, args: &[&str]) {
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
}

fn git_text(root: &Path, args: &[&str]) -> String {
    String::from_utf8(git_bytes(root, args))
        .unwrap()
        .trim()
        .to_string()
}

fn git_bytes(root: &Path, args: &[&str]) -> Vec<u8> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success());
    output.stdout
}
