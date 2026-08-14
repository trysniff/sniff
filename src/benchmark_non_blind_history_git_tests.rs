use super::*;
use std::fs;

const POLICY: &[u8] = include_bytes!("../sniffbench/non-blind-v1-selection-policy.json");

#[test]
fn complete_local_history_selects_the_exact_ranked_commit() {
    let repository = fixture_repository();
    let policy: NonBlindSelectionPolicy = serde_json::from_slice(POLICY).unwrap();

    let discovery =
        inspect_historical_git_repository(&policy, "github.com/example/history", repository.path())
            .unwrap();

    assert_eq!(discovery.default_branch, "main");
    assert_eq!(discovery.reachable_commit_count, 3);
    assert_eq!(discovery.matching_commit_count, 1);
    let selected = discovery.selected_commit.unwrap();
    assert_eq!(selected.rank, 1);
    assert_eq!(selected.subject, "simplify parser");
    assert_eq!(selected.changed_paths.len(), 1);
    assert_eq!(selected.changed_paths[0].status, "M");
    assert_eq!(selected.changed_paths[0].path, "src/main.rs");
    assert!(selected.changed_paths[0].previous_path.is_none());
}

#[test]
fn changed_path_parser_preserves_rename_score_and_both_paths() {
    let fields = [b"R100".as_slice(), b"src/old.rs", b"src/new.rs"];

    let paths = parse_changed_path_fields(&fields).unwrap();

    assert_eq!(
        paths,
        [HistoricalChangedPath {
            status: "R100".to_string(),
            previous_path: Some("src/old.rs".to_string()),
            path: "src/new.rs".to_string(),
        }]
    );
}

#[test]
fn changed_path_parser_uses_the_ledger_canonical_order() {
    let fields = [
        b"A".as_slice(),
        b"z-last.rs",
        b"M",
        b"a-first.rs",
        b"R100",
        b"old-middle.rs",
        b"m-middle.rs",
    ];

    let paths = parse_changed_path_fields(&fields).unwrap();

    assert_eq!(
        paths
            .iter()
            .map(|path| path.path.as_str())
            .collect::<Vec<_>>(),
        ["a-first.rs", "m-middle.rs", "z-last.rs"]
    );
}

#[test]
fn dirty_or_sparse_history_fails_closed() {
    let repository = fixture_repository();
    let policy: NonBlindSelectionPolicy = serde_json::from_slice(POLICY).unwrap();
    fs::write(repository.path().join("untracked.txt"), "dirty\n").unwrap();
    assert!(
        inspect_historical_git_repository(
            &policy,
            "github.com/example/history",
            repository.path(),
        )
        .unwrap_err()
        .contains("dirty")
    );
    fs::remove_file(repository.path().join("untracked.txt")).unwrap();
    git(
        repository.path(),
        &["config", "core.sparseCheckout", "true"],
    );
    assert!(
        inspect_historical_git_repository(
            &policy,
            "github.com/example/history",
            repository.path(),
        )
        .unwrap_err()
        .contains("sparse checkout")
    );
}

fn fixture_repository() -> tempfile::TempDir {
    let repository = tempfile::tempdir().unwrap();
    git(repository.path(), &["init", "-b", "main"]);
    git(
        repository.path(),
        &["config", "user.email", "fixture@example.com"],
    );
    git(repository.path(), &["config", "user.name", "Fixture"]);
    fs::create_dir_all(repository.path().join("src")).unwrap();
    fs::write(
        repository.path().join("src/main.rs"),
        "fn parser() {\n    println!(\"old\");\n}\n",
    )
    .unwrap();
    fs::write(repository.path().join("LICENSE"), "fixture license\n").unwrap();
    git(repository.path(), &["add", "."]);
    git(repository.path(), &["commit", "-m", "initial"]);
    fs::write(
        repository.path().join("src/main.rs"),
        "fn parser() { println!(\"new\"); }\n",
    )
    .unwrap();
    git(repository.path(), &["add", "."]);
    git(repository.path(), &["commit", "-m", "simplify parser"]);
    fs::write(repository.path().join("README.md"), "fixture\n").unwrap();
    git(repository.path(), &["add", "."]);
    git(repository.path(), &["commit", "-m", "add documentation"]);
    let head = git_output(repository.path(), &["rev-parse", "HEAD"]);
    git(
        repository.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/example/history.git",
        ],
    );
    git(
        repository.path(),
        &["update-ref", "refs/remotes/origin/main", head.trim()],
    );
    git(
        repository.path(),
        &[
            "symbolic-ref",
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/main",
        ],
    );
    repository
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

fn git_output(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap()
}
