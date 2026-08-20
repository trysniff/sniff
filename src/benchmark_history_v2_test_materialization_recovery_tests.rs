use super::*;
use sha2::{Digest, Sha256};
use std::process::Command;

#[test]
fn interrupted_test_materialization_is_removed_and_recovery_is_idempotent() {
    let fixture = Fixture::new();
    let (materialization, roots) = fixture.materialize();
    let slot_root = roots.repository_root.parent().unwrap();
    for (name, revision) in [
        ("base-tested", materialization.base_revision.as_str()),
        (
            "patched-tested",
            materialization.patched_commit_oid.as_str(),
        ),
    ] {
        git_ok(
            &roots.repository_root,
            &[
                "worktree",
                "add",
                "--detach",
                "--force",
                &slot_root.join(name).to_string_lossy(),
                revision,
            ],
        );
    }
    fs::write(slot_root.join("test.patch"), b"partial patch").unwrap();
    fs::write(
        slot_root.join("test-commit-message.txt"),
        b"partial commit message",
    )
    .unwrap();

    assert!(recover_historical_v2_test_materialization(&materialization, &roots).unwrap());
    assert!(!slot_root.join("base-tested").exists());
    assert!(!slot_root.join("patched-tested").exists());
    assert!(!slot_root.join("test.patch").exists());
    assert!(!slot_root.join("test-commit-message.txt").exists());
    assert!(!recover_historical_v2_test_materialization(&materialization, &roots).unwrap());
}

struct Fixture {
    source: tempfile::TempDir,
    output: tempfile::TempDir,
    base_revision: String,
    historical_patch: String,
}

impl Fixture {
    fn new() -> Self {
        let source = tempfile::tempdir().unwrap();
        git_ok(source.path(), &["init", "-b", "main"]);
        git_ok(
            source.path(),
            &["config", "user.email", "fixture@example.test"],
        );
        git_ok(source.path(), &["config", "user.name", "Fixture"]);
        git_ok(source.path(), &["config", "core.autocrlf", "false"]);
        fs::write(
            source.path().join("lib.rs"),
            b"pub fn value() -> i32 { 1 }\n",
        )
        .unwrap();
        git_ok(source.path(), &["add", "."]);
        git_ok(source.path(), &["commit", "-m", "base"]);
        let base_revision = git_text(source.path(), &["rev-parse", "HEAD"]);
        fs::write(
            source.path().join("lib.rs"),
            b"pub fn value() -> i32 { 2 }\n",
        )
        .unwrap();
        let historical_patch = format!(
            "{}\n",
            git_text(source.path(), &["diff", "--binary", "HEAD"])
        );
        git_ok(source.path(), &["reset", "--hard", "HEAD"]);
        Self {
            source,
            output: tempfile::tempdir().unwrap(),
            base_revision,
            historical_patch,
        }
    }

    fn materialize(&self) -> (HistoricalV2Materialization, HistoricalV2MaterializedRoots) {
        super::super::history_v2_materialization::materialize_from_url(
            "example/recovery-fixture",
            &self.source.path().to_string_lossy(),
            &self.base_revision,
            &self.historical_patch,
            &sha256(self.historical_patch.as_bytes()),
            &self.output.path().join("slot"),
        )
        .unwrap()
    }
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

fn git_text(root: &Path, args: &[&str]) -> String {
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
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
