use super::*;
use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn commits_complete_base_and_patched_source_snapshots_deterministically() {
    let fixture = Fixture::new();
    let first = fixture.materialize("first");
    let second = fixture.materialize("second");
    let first_census = census_historical_v2_sources(&first.0, &first.1).unwrap();
    let second_census = census_historical_v2_sources(&second.0, &second.1).unwrap();

    assert_eq!(first_census, second_census);
    assert_eq!(first_census.base.tracked_entry_count, 2);
    assert_eq!(first_census.base.source_file_count, 2);
    assert_eq!(first_census.base.method_count, 2);
    assert_eq!(first_census.patched.method_count, 2);
    assert_eq!(
        first_census.base.method_counts_by_language,
        BTreeMap::from([("rust".to_string(), 2)])
    );
    assert_eq!(source_lines(&first_census.base, "src/lib.rs"), 4);
    assert_eq!(source_lines(&first_census.patched, "src/lib.rs"), 3);
    assert_ne!(
        source_hash(&first_census.base, "src/lib.rs"),
        source_hash(&first_census.patched, "src/lib.rs")
    );
    assert_eq!(
        source_hash(&first_census.base, "tests/value.rs"),
        source_hash(&first_census.patched, "tests/value.rs")
    );
    validate_historical_v2_source_census(&first.0, &first.1, &first_census).unwrap();
}

#[test]
fn replay_rejects_source_census_tampering() {
    let fixture = Fixture::new();
    let materialized = fixture.materialize("tampered");
    let mut census = census_historical_v2_sources(&materialized.0, &materialized.1).unwrap();
    census.base.source_files[0].methods[0].parser_unit_id = "invented".to_string();

    assert!(
        validate_historical_v2_source_census(&materialized.0, &materialized.1, &census)
            .unwrap_err()
            .contains("changed")
    );
}

#[test]
fn source_method_ids_are_stable_only_for_identical_units() {
    let fixture = Fixture::new();
    let materialized = fixture.materialize("identities");
    let census = census_historical_v2_sources(&materialized.0, &materialized.1).unwrap();
    let base_test = source_method(&census.base, "tests/value.rs");
    let patched_test = source_method(&census.patched, "tests/value.rs");
    let base_production = source_method(&census.base, "src/lib.rs");
    let patched_production = source_method(&census.patched, "src/lib.rs");

    assert_eq!(base_test.parser_unit_id, patched_test.parser_unit_id);
    assert_ne!(
        base_production.parser_unit_id,
        patched_production.parser_unit_id
    );
}

fn source_lines(census: &HistoricalV2SourceSnapshotCensus, path: &str) -> usize {
    source_file(census, path).non_whitespace_lines
}

fn source_hash<'a>(census: &'a HistoricalV2SourceSnapshotCensus, path: &str) -> &'a str {
    &source_file(census, path).source_sha256
}

fn source_method<'a>(
    census: &'a HistoricalV2SourceSnapshotCensus,
    path: &str,
) -> &'a HistoricalV2SourceMethod {
    &source_file(census, path).methods[0]
}

fn source_file<'a>(
    census: &'a HistoricalV2SourceSnapshotCensus,
    path: &str,
) -> &'a HistoricalV2SourceFile {
    census
        .source_files
        .iter()
        .find(|file| file.repository_path == path)
        .unwrap()
}

struct Fixture {
    source: tempfile::TempDir,
    parent: tempfile::TempDir,
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
        fs::create_dir_all(source.path().join("src")).unwrap();
        fs::create_dir_all(source.path().join("tests")).unwrap();
        fs::write(
            source.path().join("src/lib.rs"),
            "pub fn value() -> u8 {\n    let value = 1;\n    value\n}\n",
        )
        .unwrap();
        fs::write(
            source.path().join("tests/value.rs"),
            "#[test] fn value_is_one() { assert_eq!(1, 1); }\n",
        )
        .unwrap();
        git_ok(source.path(), &["add", "."]);
        git_ok(source.path(), &["commit", "-m", "base"]);
        let base_revision = git_text(source.path(), &["rev-parse", "HEAD"]);
        fs::write(
            source.path().join("src/lib.rs"),
            "pub fn value() -> u8 {\n    1\n}\n",
        )
        .unwrap();
        let historical_patch = git_text(source.path(), &["diff", "--binary", "HEAD"]) + "\n";
        git_ok(source.path(), &["reset", "--hard", "HEAD"]);
        Self {
            source,
            parent: tempfile::tempdir().unwrap(),
            base_revision,
            historical_patch,
        }
    }

    fn materialize(
        &self,
        name: &str,
    ) -> (HistoricalV2Materialization, HistoricalV2MaterializedRoots) {
        let materialized = super::super::history_v2_materialization::materialize_from_url(
            "github.com/example/repo",
            &self.source.path().to_string_lossy(),
            &self.base_revision,
            &self.historical_patch,
            &sha256(self.historical_patch.as_bytes()),
            &self.parent.path().join(name),
        )
        .unwrap();
        git_ok(
            &materialized.1.repository_root,
            &[
                "remote",
                "set-url",
                "origin",
                "https://github.com/example/repo.git",
            ],
        );
        materialized
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
