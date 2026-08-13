use super::{
    BenchmarkSourceSeal, LabelAgreementStatus, LabelReviewWorksheet, LabelReviewer,
    audit_label_reviews, prepare_label_review, sha256,
};
use crate::benchmark::{SourceSnapshot, write_test_source_seal};
use crate::types::FindingTier;
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
        sha256: sha256(source.as_bytes()),
    }];
    let (seal_path, seal_hash, _) = write_test_source_seal(root.path(), &snapshots);
    let seal = serde_json::from_slice(&fs::read(root.path().join(seal_path)).unwrap()).unwrap();
    (root, seal, seal_hash)
}

fn completed(mut worksheet: LabelReviewWorksheet, reviewer_id: &str) -> LabelReviewWorksheet {
    worksheet.reviewer = Some(LabelReviewer {
        reviewer_id: reviewer_id.to_string(),
        years_experience: 7,
        affiliation: "Independent reviewer".to_string(),
        independent_from_sniff: true,
        sniff_output_hidden: true,
        repository_context_inspected: true,
        maintainer: false,
        attestation: "I reviewed only the sealed source worksheet.".to_string(),
    });
    for method in &mut worksheet.methods {
        method.decision.tier = Some(FindingTier::Clean);
        method.decision.pattern = "none".to_string();
        method.decision.intentional_boundary = Some(false);
        method.decision.rationale =
            "The method directly implements its stated operation.".to_string();
    }
    worksheet
}

#[test]
fn prepared_label_review_contains_every_exact_sealed_method_without_labels() {
    let (root, seal, seal_hash) = fixture();

    let worksheet = prepare_label_review(&seal, root.path(), &seal_hash).unwrap();

    assert_eq!(worksheet.methods.len(), 2);
    assert!(worksheet.reviewer.is_none());
    assert_eq!(worksheet.context_sources.len(), 1);
    assert!(worksheet.methods.iter().all(|method| {
        method.decision.tier.is_none()
            && method.decision.pattern.is_empty()
            && !method.source.is_empty()
            && sha256(method.source.as_bytes()) == method.source_sha256
    }));
}

#[test]
fn label_audit_requires_complete_independent_reviews_and_preserves_disputes() {
    let (root, seal, seal_hash) = fixture();
    let template = prepare_label_review(&seal, root.path(), &seal_hash).unwrap();
    let first = completed(template.clone(), "reviewer-a");
    let mut second = completed(template, "reviewer-b");
    second.methods[0].decision.tier = Some(FindingTier::KindaSlop);
    second.methods[0].decision.pattern = "ceremonial_logic".to_string();
    second.methods[0].decision.rationale = "The wrapper adds no contract.".to_string();
    second.methods[0].decision.simplification = "Inline the constant return.".to_string();
    second.methods[0].decision.behavioral_evidence =
        vec!["The return value remains unchanged.".to_string()];

    let audit = audit_label_reviews(&seal, root.path(), &seal_hash, &[first, second]).unwrap();

    assert_eq!(audit.agreement_count, 1);
    assert_eq!(audit.disputed_count, 1);
    assert_eq!(audit.methods[0].status, LabelAgreementStatus::Disputed);
    assert_eq!(audit.methods[0].labels.len(), 2);
    assert_eq!(audit.audit_sha256, audit.computed_audit_sha256().unwrap());
}

#[test]
fn intentional_boundary_disagreement_remains_an_explicit_dispute() {
    let (root, seal, seal_hash) = fixture();
    let template = prepare_label_review(&seal, root.path(), &seal_hash).unwrap();
    let first = completed(template.clone(), "reviewer-a");
    let mut second = completed(template, "reviewer-b");
    second.methods[0].decision.intentional_boundary = Some(true);
    second.methods[0].decision.rationale =
        "The clean method is an intentional public boundary.".to_string();

    let audit = audit_label_reviews(&seal, root.path(), &seal_hash, &[first, second]).unwrap();

    let disputed = audit
        .methods
        .iter()
        .find(|method| method.method_id == seal.methods[0].method_id)
        .unwrap();
    assert_eq!(disputed.status, LabelAgreementStatus::Disputed);
}

#[test]
fn label_audit_rejects_tampering_omissions_and_reused_reviewer_identity() {
    let (root, seal, seal_hash) = fixture();
    let template = prepare_label_review(&seal, root.path(), &seal_hash).unwrap();
    let first = completed(template.clone(), "reviewer-a");
    let mut tampered = completed(template.clone(), "reviewer-b");
    tampered.methods[0].source.push_str("// changed\n");
    let error = audit_label_reviews(&seal, root.path(), &seal_hash, &[first.clone(), tampered])
        .unwrap_err();
    assert!(error.contains("changed immutable source facts"));

    let mut omitted = completed(template.clone(), "reviewer-b");
    omitted.methods.pop();
    let error =
        audit_label_reviews(&seal, root.path(), &seal_hash, &[first.clone(), omitted]).unwrap_err();
    assert!(error.contains("complete sealed method census"));

    let duplicate = completed(template, "reviewer-a");
    let error =
        audit_label_reviews(&seal, root.path(), &seal_hash, &[first, duplicate]).unwrap_err();
    assert!(error.contains("repeats reviewer"));
}

#[test]
fn label_audit_rejects_unblinded_or_incomplete_decisions() {
    let (root, seal, seal_hash) = fixture();
    let template = prepare_label_review(&seal, root.path(), &seal_hash).unwrap();
    let first = completed(template.clone(), "reviewer-a");
    let mut unblinded = completed(template.clone(), "reviewer-b");
    unblinded.reviewer.as_mut().unwrap().sniff_output_hidden = false;
    let error = audit_label_reviews(&seal, root.path(), &seal_hash, &[first.clone(), unblinded])
        .unwrap_err();
    assert!(error.contains("blind to Sniff output"));

    let mut incomplete = completed(template, "reviewer-b");
    incomplete.methods[0].decision.tier = None;
    let error =
        audit_label_reviews(&seal, root.path(), &seal_hash, &[first, incomplete]).unwrap_err();
    assert!(error.contains("has not been labeled"));
}

#[test]
fn label_audit_rejects_one_sided_cross_method_cases() {
    let (root, seal, seal_hash) = fixture();
    let template = prepare_label_review(&seal, root.path(), &seal_hash).unwrap();
    let first = completed(template.clone(), "reviewer-a");
    let mut malformed = completed(template, "reviewer-b");
    let related = malformed.methods[1].method_id.clone();
    malformed.methods[0].decision.tier = Some(FindingTier::KindaSlop);
    malformed.methods[0].decision.pattern = "duplicated_semantics".to_string();
    malformed.methods[0].decision.rationale = "The two methods duplicate one concept.".to_string();
    malformed.methods[0].decision.simplification = "Keep one implementation.".to_string();
    malformed.methods[0].decision.behavioral_evidence =
        vec!["Both return the same contract.".to_string()];
    malformed.methods[0].decision.related_method_ids = vec![related];

    let error =
        audit_label_reviews(&seal, root.path(), &seal_hash, &[first, malformed]).unwrap_err();

    assert!(error.contains("without a reciprocal relationship"));
}
