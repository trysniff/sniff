use super::*;
use crate::benchmark::{SourceSnapshot, write_test_source_seal};
use std::fs;

fn fixture() -> (tempfile::TempDir, BenchmarkSourceSeal, String) {
    let root = tempfile::tempdir().unwrap();
    let source = "pub fn first() -> i32 { 1 }\npub fn second() -> i32 { 2 }\n";
    fs::write(root.path().join("blind.rs"), source).unwrap();
    let snapshots = vec![SourceSnapshot {
        repository: "https://github.com/example/blind".to_string(),
        revision: "1".repeat(40),
        repository_path: "src/blind.rs".to_string(),
        artifact_path: "blind.rs".to_string(),
        sha256: format!("{:x}", Sha256::digest(source.as_bytes())),
    }];
    let (seal_path, seal_hash, _) = write_test_source_seal(root.path(), &snapshots);
    let seal = serde_json::from_slice(&fs::read(root.path().join(seal_path)).unwrap()).unwrap();
    (root, seal, seal_hash)
}

fn submission(
    expected: &LabelReviewWorksheet,
    reviewer_id: &str,
    run_id: &str,
) -> ModelJudgedSubmission {
    let mut review = ModelJudgedSubmission {
        schema_version: MODEL_JUDGED_REVIEW_SCHEMA_VERSION,
        source_seal_artifact_sha256: expected.source_seal_artifact_sha256.clone(),
        source_seal_commitment_sha256: expected.source_seal_commitment_sha256.clone(),
        task_commitment_sha256: expected.task_commitment_sha256.clone(),
        reviewer: ModelJudgedReviewer {
            reviewer_id: reviewer_id.to_string(),
            provider: "example-provider".to_string(),
            model: "example-model".to_string(),
            model_version: "2026-09-26".to_string(),
            run_id: run_id.to_string(),
            prompt_sha256: "a".repeat(64),
            fresh_context: true,
            sniff_output_hidden: true,
            other_reviews_hidden: true,
            source_context_inspected: true,
        },
        decisions: expected
            .methods
            .iter()
            .map(|method| ModelJudgedDecision {
                method_id: method.method_id.clone(),
                tier: FindingTier::Clean,
                mechanism: "Direct implementation".to_string(),
                evidence_artifact_path: method.artifact_path.clone(),
                exact_source_quote: method.source.clone(),
                rationale: "No unnecessary machinery is visible in source.".to_string(),
                missing_evidence: Vec::new(),
            })
            .collect(),
        submission_sha256: String::new(),
    };
    review.submission_sha256 = review.computed_sha256().unwrap();
    review
}

#[test]
fn model_reviews_are_source_bound_and_not_human_labels() {
    let (root, seal, seal_hash) = fixture();
    let expected = prepare_label_review(&seal, root.path(), &seal_hash).unwrap();
    let first = submission(&expected, "agent-a", "run-a");
    let mut second = submission(&expected, "agent-b", "run-b");
    second.decisions[0].tier = FindingTier::KindaSlop;
    second.submission_sha256 = second.computed_sha256().unwrap();
    validate_model_judged_submission(&seal, root.path(), &seal_hash, &first).unwrap();
    let audit =
        audit_model_judged_reviews(&seal, root.path(), &seal_hash, &first, &second).unwrap();
    assert_eq!(audit.agreement_count, 1);
    assert_eq!(audit.disputed_count, 1);
    assert_eq!(audit.audit_sha256, audit.computed_sha256().unwrap());
    validate_model_judged_audit(&seal, root.path(), &seal_hash, &first, &second, &audit).unwrap();
    let mut changed = audit;
    changed.methods[0].agreed = !changed.methods[0].agreed;
    changed.audit_sha256 = changed.computed_sha256().unwrap();
    assert!(
        validate_model_judged_audit(&seal, root.path(), &seal_hash, &first, &second, &changed)
            .unwrap_err()
            .contains("does not replay")
    );
}

#[test]
fn model_review_rejects_unblinded_or_forged_evidence() {
    let (root, seal, seal_hash) = fixture();
    let expected = prepare_label_review(&seal, root.path(), &seal_hash).unwrap();
    let mut review = submission(&expected, "agent-a", "run-a");
    review.reviewer.sniff_output_hidden = false;
    review.submission_sha256 = review.computed_sha256().unwrap();
    assert!(
        validate_model_judged_submission(&seal, root.path(), &seal_hash, &review)
            .unwrap_err()
            .contains("source-only isolation")
    );

    review.reviewer.sniff_output_hidden = true;
    review.decisions[0].exact_source_quote = "fabricated quote".to_string();
    review.submission_sha256 = review.computed_sha256().unwrap();
    assert!(
        validate_model_judged_submission(&seal, root.path(), &seal_hash, &review)
            .unwrap_err()
            .contains("no exact source quote")
    );
}

#[test]
fn model_audit_rejects_repeated_runs_and_unequal_coverage() {
    let (root, seal, seal_hash) = fixture();
    let expected = prepare_label_review(&seal, root.path(), &seal_hash).unwrap();
    let first = submission(&expected, "agent-a", "run-a");
    let mut second = submission(&expected, "agent-b", "run-a");
    assert!(
        audit_model_judged_reviews(&seal, root.path(), &seal_hash, &first, &second)
            .unwrap_err()
            .contains("two distinct agent runs")
    );
    second.reviewer.run_id = "run-b".to_string();
    second.decisions.pop();
    second.submission_sha256 = second.computed_sha256().unwrap();
    assert!(
        audit_model_judged_reviews(&seal, root.path(), &seal_hash, &first, &second)
            .unwrap_err()
            .contains("different method sets")
    );
}
