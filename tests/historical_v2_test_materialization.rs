#[path = "../src/bounded_process.rs"]
mod bounded_process;
#[path = "../src/benchmark_history_v2_materialization_exclusion.rs"]
mod history_v2_materialization_exclusion;
#[path = "../src/benchmark_history_v2_materialization_git.rs"]
mod history_v2_materialization_git;
#[path = "../src/benchmark_history_v2_materialization_schema.rs"]
mod history_v2_materialization_schema;
#[path = "../src/benchmark_history_v2_materialization_stage_schema.rs"]
mod history_v2_materialization_stage_schema;
#[path = "../src/benchmark_history_v2_test_materialization_exclusion.rs"]
mod history_v2_test_materialization_exclusion;
#[path = "../src/benchmark_history_v2_test_materialization_schema.rs"]
mod history_v2_test_materialization_schema;
#[path = "../src/benchmark_history_v2_test_materialization_stage_schema.rs"]
mod history_v2_test_materialization_stage_schema;
#[path = "../src/benchmark_non_blind_history_materialize.rs"]
mod non_blind_history_materialize;

pub use history_v2_materialization_exclusion::*;
pub use history_v2_materialization_schema::*;
pub use history_v2_materialization_stage_schema::*;
pub use history_v2_test_materialization_exclusion::*;
pub use history_v2_test_materialization_schema::*;
pub use history_v2_test_materialization_stage_schema::*;
pub use non_blind_history_materialize::*;
pub use sniff::benchmark::{
    HistoricalV2SlotStage, HistoricalV2SlotStageError, HistoricalV2SlotStageErrorKind,
    HistoricalV2StageResult,
};

#[path = "../src/benchmark_history_v2_materialization.rs"]
mod history_v2_materialization;
#[path = "../src/benchmark_history_v2_test_materialization.rs"]
mod history_v2_test_materialization;

pub use history_v2_materialization::*;
pub use history_v2_test_materialization::*;

use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn applies_identical_test_patch_to_both_snapshots_deterministically() {
    let fixture = Fixture::new();
    let first = fixture.materialize("first");
    let second = fixture.materialize("second");

    assert_eq!(first.test_artifact, second.test_artifact);
    assert_eq!(
        fs::read_to_string(first.test_roots.base_test_root.join("test.rs")).unwrap(),
        "#[test]\nfn value_is_positive() {}\n"
    );
    assert_eq!(
        fs::read_to_string(first.test_roots.patched_test_root.join("test.rs")).unwrap(),
        "#[test]\nfn value_is_positive() {}\n"
    );
    assert_eq!(
        fs::read_to_string(first.test_roots.base_test_root.join("main.rs")).unwrap(),
        "fn value() -> i32 { 1 }\n"
    );
    assert_eq!(
        fs::read_to_string(first.test_roots.patched_test_root.join("main.rs")).unwrap(),
        "fn value() -> i32 { 2 }\n"
    );
    validate_historical_v2_test_materialization(
        &first.materialization,
        &first.materialized_roots,
        &sha256(fixture.test_patch.as_bytes()),
        &first.test_artifact,
        &first.test_roots,
    )
    .unwrap();
}

#[test]
fn rejects_patch_that_does_not_apply_to_both_before_retaining_work() {
    let fixture = Fixture::new();
    let (materialization, materialized_roots) = fixture.materialize_snapshots("one-sided");
    let one_sided_patch = fixture.patch_main_to_three();
    let outcome = materialize_historical_v2_test_snapshots_typed(
        &materialization,
        &materialized_roots,
        &one_sided_patch,
        &sha256(one_sided_patch.as_bytes()),
    )
    .unwrap();
    let HistoricalV2StageResult::Excluded(exclusion) = outcome else {
        panic!("one-sided test patch was not excluded");
    };

    assert_eq!(
        exclusion.reason,
        HistoricalV2TestMaterializationExclusionReason::TestPatchDoesNotApply
    );
    let HistoricalV2TestMaterializationExclusionEvidence::TestPatchRejected { rejections, .. } =
        &exclusion.evidence
    else {
        panic!("one-sided test patch rejection evidence is missing");
    };
    assert_eq!(rejections.len(), 1);
    assert_eq!(
        rejections[0].side,
        HistoricalV2TestMaterializationSide::Patched
    );
    validate_historical_v2_test_materialization_exclusion(&exclusion).unwrap();
    assert!(!fixture.parent.path().join("one-sided/base-tested").exists());
    assert!(
        !fixture
            .parent
            .path()
            .join("one-sided/patched-tested")
            .exists()
    );
    validate_historical_v2_materialization(&materialization, &materialized_roots).unwrap();
}

#[test]
fn records_every_snapshot_that_rejects_the_test_patch() {
    let fixture = Fixture::new();
    let (materialization, materialized_roots) = fixture.materialize_snapshots("both-reject");
    let patch = "not a Git patch\n";
    let outcome = materialize_historical_v2_test_snapshots_typed(
        &materialization,
        &materialized_roots,
        patch,
        &sha256(patch.as_bytes()),
    )
    .unwrap();
    let HistoricalV2StageResult::Excluded(exclusion) = outcome else {
        panic!("invalid test patch was not excluded");
    };
    let HistoricalV2TestMaterializationExclusionEvidence::TestPatchRejected { rejections, .. } =
        &exclusion.evidence
    else {
        panic!("test patch rejection evidence is missing");
    };

    assert_eq!(
        rejections.iter().map(|item| item.side).collect::<Vec<_>>(),
        vec![
            HistoricalV2TestMaterializationSide::Base,
            HistoricalV2TestMaterializationSide::Patched,
        ]
    );
    validate_historical_v2_test_materialization_exclusion(&exclusion).unwrap();
    assert!(
        !fixture
            .parent
            .path()
            .join("both-reject/base-tested")
            .exists()
    );
    assert!(
        !fixture
            .parent
            .path()
            .join("both-reject/patched-tested")
            .exists()
    );
}

#[test]
fn rejects_changed_test_patch_hash_before_creating_worktrees() {
    let fixture = Fixture::new();
    let (materialization, materialized_roots) = fixture.materialize_snapshots("changed-hash");
    let error = materialize_historical_v2_test_snapshots_typed(
        &materialization,
        &materialized_roots,
        &fixture.test_patch,
        &"0".repeat(64),
    )
    .unwrap_err();

    assert_eq!(error.stage, HistoricalV2SlotStage::TestMaterialization);
    assert_eq!(error.kind, HistoricalV2SlotStageErrorKind::InvalidInput);
    assert!(
        !fixture
            .parent
            .path()
            .join("changed-hash/base-tested")
            .exists()
    );
    assert!(
        !fixture
            .parent
            .path()
            .join("changed-hash/patched-tested")
            .exists()
    );
}

#[test]
fn validator_rejects_crossed_tested_roots() {
    let fixture = Fixture::new();
    let first = fixture.materialize("cross-first");
    let second = fixture.materialize("cross-second");
    let crossed = HistoricalV2TestMaterializedRoots {
        base_test_root: first.test_roots.base_test_root.clone(),
        patched_test_root: second.test_roots.patched_test_root.clone(),
    };

    assert!(
        validate_historical_v2_test_materialization(
            &first.materialization,
            &first.materialized_roots,
            &sha256(fixture.test_patch.as_bytes()),
            &first.test_artifact,
            &crossed,
        )
        .is_err()
    );
}

struct Fixture {
    source: tempfile::TempDir,
    parent: tempfile::TempDir,
    base_revision: String,
    historical_patch: String,
    test_patch: String,
}

struct MaterializedFixture {
    materialization: HistoricalV2Materialization,
    materialized_roots: HistoricalV2MaterializedRoots,
    test_artifact: HistoricalV2TestMaterialization,
    test_roots: HistoricalV2TestMaterializedRoots,
}

impl Fixture {
    fn new() -> Self {
        let source = tempfile::tempdir().unwrap();
        initialize_repository(source.path());
        fs::write(source.path().join("main.rs"), "fn value() -> i32 { 1 }\n").unwrap();
        git_ok(source.path(), &["add", "."]);
        git_ok(source.path(), &["commit", "-m", "base"]);
        let base_revision = git_text(source.path(), &["rev-parse", "HEAD"]);

        fs::write(source.path().join("main.rs"), "fn value() -> i32 { 2 }\n").unwrap();
        let historical_patch = git_text(source.path(), &["diff", "--binary", "HEAD"]) + "\n";
        git_ok(source.path(), &["reset", "--hard", "HEAD"]);

        fs::write(
            source.path().join("test.rs"),
            "#[test]\nfn value_is_positive() {}\n",
        )
        .unwrap();
        git_ok(source.path(), &["add", "test.rs"]);
        let test_patch = git_text(source.path(), &["diff", "--cached", "--binary", "HEAD"]) + "\n";
        git_ok(source.path(), &["reset", "--hard", "HEAD"]);

        Self {
            source,
            parent: tempfile::tempdir().unwrap(),
            base_revision,
            historical_patch,
            test_patch,
        }
    }

    fn materialize(&self, name: &str) -> MaterializedFixture {
        let (materialization, materialized_roots) = self.materialize_snapshots(name);
        let (test_artifact, test_roots) = materialize_historical_v2_test_snapshots(
            &materialization,
            &materialized_roots,
            &self.test_patch,
            &sha256(self.test_patch.as_bytes()),
        )
        .unwrap();
        MaterializedFixture {
            materialization,
            materialized_roots,
            test_artifact,
            test_roots,
        }
    }

    fn materialize_snapshots(
        &self,
        name: &str,
    ) -> (HistoricalV2Materialization, HistoricalV2MaterializedRoots) {
        history_v2_materialization::materialize_from_url(
            "github.com/example/repo",
            &self.source.path().to_string_lossy(),
            &self.base_revision,
            &self.historical_patch,
            &sha256(self.historical_patch.as_bytes()),
            &self.parent.path().join(name),
        )
        .unwrap()
    }

    fn patch_main_to_three(&self) -> String {
        fs::write(
            self.source.path().join("main.rs"),
            "fn value() -> i32 { 3 }\n",
        )
        .unwrap();
        let patch = git_text(self.source.path(), &["diff", "--binary", "HEAD"]) + "\n";
        git_ok(self.source.path(), &["reset", "--hard", "HEAD"]);
        patch
    }
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
