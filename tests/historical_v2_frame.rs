use sniff::benchmark::{
    HistoricalV2FrameDisposition, HistoricalV2FrameExclusionReason, HistoricalV2ProjectedRow,
    classify_historical_v2_patch, derive_historical_v2_frame_record, historical_v2_rank_sha256,
};

const PYTHON_REDUCTION: &str = r#"diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -1,4 +1,2 @@
-temporary = prepare()
-unused = normalize(temporary)
-result = finish(unused)
+result = finish(prepare())
 return result
"#;

fn projected_row(patch: &str) -> HistoricalV2ProjectedRow {
    HistoricalV2ProjectedRow {
        source_shard_index: 0,
        source_row_index: 7,
        global_row_index: 7,
        base_commit: "a".repeat(40),
        created_at: "2025-01-02 03:04:05".to_string(),
        instance_id: "owner__repo-42".to_string(),
        license: "mit".to_string(),
        patch: patch.to_string(),
        pull_number: 42,
        repo: "Owner/Repo".to_string(),
    }
}

#[test]
fn classifies_only_a_single_language_net_reduction() {
    let facts = classify_historical_v2_patch(PYTHON_REDUCTION).unwrap();

    assert_eq!(facts.language, "python");
    assert_eq!(facts.changed_paths, ["src/app.py"]);
    assert_eq!(facts.added_non_whitespace_lines, 1);
    assert_eq!(facts.deleted_non_whitespace_lines, 3);
}

#[test]
fn rejects_mixed_language_and_expanding_patches() {
    let mixed = format!(
        "{PYTHON_REDUCTION}diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,2 +1 @@\n-let value = 1;\n-value\n+1\n"
    );
    assert_eq!(
        classify_historical_v2_patch(&mixed),
        Err(HistoricalV2FrameExclusionReason::MultipleSupportedLanguages)
    );

    let expansion = PYTHON_REDUCTION.replace(
        "-temporary = prepare()\n-unused = normalize(temporary)\n-result = finish(unused)",
        "+temporary = prepare()\n+unused = normalize(temporary)\n+result = finish(unused)",
    );
    assert_eq!(
        classify_historical_v2_patch(&expansion),
        Err(HistoricalV2FrameExclusionReason::NoNetSupportedLanguageReduction)
    );
}

#[test]
fn rejects_quoted_or_unsafe_diff_paths() {
    let quoted = PYTHON_REDUCTION.replace("+++ b/src/app.py", "+++ \"b/src/app.py\"");
    assert_eq!(
        classify_historical_v2_patch(&quoted),
        Err(HistoricalV2FrameExclusionReason::MalformedPatch)
    );

    let traversal = PYTHON_REDUCTION.replace("+++ b/src/app.py", "+++ b/../src/app.py");
    assert_eq!(
        classify_historical_v2_patch(&traversal),
        Err(HistoricalV2FrameExclusionReason::MalformedPatch)
    );
}

#[test]
fn derives_canonical_identity_and_typed_exclusions() {
    let record =
        derive_historical_v2_frame_record(projected_row(PYTHON_REDUCTION), &"1".repeat(40));
    assert_eq!(record.canonical_repository.as_deref(), Some("owner/repo"));
    assert_eq!(record.pull_number, Some(42));
    assert!(matches!(
        record.disposition,
        HistoricalV2FrameDisposition::Eligible { .. }
    ));

    let mut row = projected_row(PYTHON_REDUCTION);
    row.base_commit = "not-a-revision".to_string();
    let record = derive_historical_v2_frame_record(row, &"1".repeat(40));
    assert_eq!(
        record.disposition,
        HistoricalV2FrameDisposition::Excluded {
            reason: HistoricalV2FrameExclusionReason::InvalidBaseRevision
        }
    );
}

#[test]
fn ranking_digest_matches_the_frozen_delimiter_contract() {
    assert_eq!(
        historical_v2_rank_sha256(
            &"1".repeat(40),
            "owner/repo",
            42,
            &"a".repeat(40),
            &"b".repeat(64),
        ),
        "33f0d21fe3d46416764559936b3731059a6f53bf1f258fea09b67acb1f010056"
    );
}
