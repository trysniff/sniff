use super::*;
use std::collections::BTreeSet;

#[test]
fn validates_an_opaque_exact_before_and_after_bundle() {
    let fixture = BundleFixture::new();
    validate_historical_v2_source_review_bundle(fixture.root.path(), &fixture.bundle).unwrap();

    let value = serde_json::to_value(&fixture.bundle).unwrap();
    let keys = object_keys(&value);
    for forbidden in [
        "canonical_repository",
        "pull_number",
        "instance_id",
        "patch",
        "problem_statement",
        "pr_description",
        "sniff_findings",
        "sniff_verdict",
    ] {
        assert!(
            !keys.contains(forbidden),
            "review bundle leaked {forbidden}"
        );
    }
}

#[test]
fn rejects_source_tampering() {
    let fixture = BundleFixture::new();
    let path = fixture.root.path().join(
        fixture.bundle.snapshots[0].artifacts[0]
            .artifact_path
            .as_ref()
            .unwrap(),
    );
    fs::write(path, b"fn changed() {}\n").unwrap();
    let error = validate_historical_v2_source_review_bundle(fixture.root.path(), &fixture.bundle)
        .unwrap_err();
    assert!(error.contains("review object changed"), "{error}");
}

#[test]
fn rejects_an_injected_bundle_file() {
    let fixture = BundleFixture::new();
    fs::write(fixture.root.path().join("labels.json"), b"{}\n").unwrap();
    let error = validate_historical_v2_source_review_bundle(fixture.root.path(), &fixture.bundle)
        .unwrap_err();
    assert!(error.contains("unexpected or missing files"), "{error}");
}

#[test]
fn rejects_behavior_evidence_missing_one_side() {
    let fixture = BundleFixture::new();
    let mut bundle = fixture.bundle.clone();
    bundle
        .behavior
        .events
        .retain(|event| event.side == HistoricalV2ExecutionSide::Base);
    bundle.bundle_sha256 = bundle_sha256(&bundle).unwrap();
    write_manifest(fixture.root.path(), &bundle);
    let error =
        validate_historical_v2_source_review_bundle(fixture.root.path(), &bundle).unwrap_err();
    assert!(error.contains("behavior evidence"), "{error}");
}

#[test]
fn rejects_a_missing_after_snapshot() {
    let fixture = BundleFixture::new();
    let mut bundle = fixture.bundle.clone();
    bundle.snapshots.pop();
    bundle.bundle_sha256 = bundle_sha256(&bundle).unwrap();
    write_manifest(fixture.root.path(), &bundle);
    let error =
        validate_historical_v2_source_review_bundle(fixture.root.path(), &bundle).unwrap_err();
    assert!(error.contains("bundle commitment"), "{error}");
}

struct BundleFixture {
    root: tempfile::TempDir,
    bundle: HistoricalV2SourceReviewBundle,
}

impl BundleFixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let before = "fn simplify(value: i32) -> i32 {\n    let prepared = value + 1;\n    prepared * 2\n}\n";
        let after = "fn simplify(value: i32) -> i32 {\n    (value + 1) * 2\n}\n";
        let before_method = exact_method("src/lib.rs", before);
        let after_method = exact_method("src/lib.rs", after);
        let before_artifact = source_artifact(root.path(), before.as_bytes());
        let after_artifact = source_artifact(root.path(), after.as_bytes());
        let snapshots = vec![
            snapshot(
                HistoricalV2ReviewSnapshotSide::Before,
                '1',
                '2',
                before_artifact,
            ),
            snapshot(
                HistoricalV2ReviewSnapshotSide::After,
                '3',
                '4',
                after_artifact,
            ),
        ];
        let mut changed_methods = vec![
            review_method(HistoricalRevisionSide::Parent, before_method),
            review_method(HistoricalRevisionSide::Commit, after_method),
        ];
        changed_methods.sort();
        let behavior = HistoricalV2ReviewBehaviorEvidence {
            test_plan_sha256: "a".repeat(64),
            execution_sha256: "b".repeat(64),
            events: vec![
                test_event(HistoricalV2ExecutionSide::Base),
                test_event(HistoricalV2ExecutionSide::Patched),
            ],
        };
        let mut bundle = HistoricalV2SourceReviewBundle {
            schema_version: HISTORICAL_V2_SOURCE_REVIEW_BUNDLE_SCHEMA_VERSION,
            bundle_contract: BUNDLE_CONTRACT.to_string(),
            protocol_sha256: "c".repeat(64),
            selection_sha256: "d".repeat(64),
            assessment_identity_sha256: "e".repeat(64),
            terminal_checkpoint_sha256: "f".repeat(64),
            review_item_id: format!("hvr-v1:{}", "1".repeat(64)),
            language: "rust".to_string(),
            source_only: true,
            sniff_output_included: false,
            dataset_judgments_included: false,
            public_surface_preserved: true,
            public_surface_delta_sha256: "2".repeat(64),
            snapshots,
            changed_methods,
            behavior,
            bundle_sha256: String::new(),
        };
        bundle.bundle_sha256 = bundle_sha256(&bundle).unwrap();
        write_manifest(root.path(), &bundle);
        Self { root, bundle }
    }
}

fn source_artifact(root: &Path, bytes: &[u8]) -> HistoricalV2ReviewSourceArtifact {
    let content_sha256 = review_sha256(bytes);
    let relative = object_artifact_path(&content_sha256);
    let path = root.join(&relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
    HistoricalV2ReviewSourceArtifact {
        repository_path: "src/lib.rs".to_string(),
        mode: "100644".to_string(),
        kind: BoundaryGitEntryKind::RegularBlob,
        object_id: "9".repeat(40),
        byte_length: Some(bytes.len() as u64),
        artifact_path: Some(relative),
        content_sha256: Some(content_sha256),
    }
}

fn snapshot(
    side: HistoricalV2ReviewSnapshotSide,
    revision: char,
    tree: char,
    artifact: HistoricalV2ReviewSourceArtifact,
) -> HistoricalV2ReviewSourceSnapshot {
    HistoricalV2ReviewSourceSnapshot {
        side,
        revision: revision.to_string().repeat(40),
        tree_oid: tree.to_string().repeat(40),
        inventory_sha256: revision.to_string().repeat(64),
        source_snapshot_sha256: tree.to_string().repeat(64),
        tracked_entry_count: 1,
        artifacts: vec![artifact],
    }
}

fn exact_method(path: &str, source: &str) -> crate::types::MethodRecord {
    crate::parser::parse_source_checked(path, source.as_bytes())
        .unwrap()
        .methods
        .into_iter()
        .next()
        .unwrap()
}

fn review_method(
    side: HistoricalRevisionSide,
    method: crate::types::MethodRecord,
) -> HistoricalV2ReviewChangedMethod {
    HistoricalV2ReviewChangedMethod {
        side,
        language: "rust".to_string(),
        repository_path: "src/lib.rs".to_string(),
        symbol_name: method.name,
        start_line: method.start_line,
        end_line: method.end_line,
        source_sha256: review_sha256(method.source.as_bytes()),
    }
}

fn test_event(side: HistoricalV2ExecutionSide) -> HistoricalV2ExecutionCommandEvidence {
    HistoricalV2ExecutionCommandEvidence {
        side,
        phase: HistoricalV2ExecutionPhase::Test,
        command_index: 0,
        command_sha256: "3".repeat(64),
        exit_code: Some(0),
        timed_out: false,
        duration_millis: 1,
        stdout_sha256: "4".repeat(64),
        stderr_sha256: "5".repeat(64),
        retained_stdout: String::new(),
        retained_stderr: String::new(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn write_manifest(root: &Path, bundle: &HistoricalV2SourceReviewBundle) {
    let mut bytes = serde_json::to_vec_pretty(bundle).unwrap();
    bytes.push(b'\n');
    fs::write(root.join(MANIFEST_NAME), bytes).unwrap();
}

fn object_keys(value: &serde_json::Value) -> BTreeSet<&str> {
    fn visit<'a>(value: &'a serde_json::Value, keys: &mut BTreeSet<&'a str>) {
        match value {
            serde_json::Value::Object(object) => {
                for (key, value) in object {
                    keys.insert(key);
                    visit(value, keys);
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    visit(value, keys);
                }
            }
            _ => {}
        }
    }
    let mut keys = BTreeSet::new();
    visit(value, &mut keys);
    keys
}
