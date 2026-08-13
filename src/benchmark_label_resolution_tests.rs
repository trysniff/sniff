use super::{
    LABEL_RESOLUTION_SCHEMA_VERSION, LabelResolutionManifest, LabelResolver, ResolvedLabelCase,
    build_blind_case_bundle, prepare_label_resolution, sha256,
};
use crate::benchmark::{
    LabelReviewWorksheet, LabelReviewer, SourceSnapshot, audit_label_reviews, prepare_label_review,
    write_test_source_seal,
};
use crate::types::FindingTier;
use std::fs;

fn fixture() -> (
    tempfile::TempDir,
    crate::benchmark::BenchmarkSourceSeal,
    String,
    LabelReviewWorksheet,
) {
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
    let worksheet = prepare_label_review(&seal, root.path(), &seal_hash).unwrap();
    (root, seal, seal_hash, worksheet)
}

fn reviewer(mut worksheet: LabelReviewWorksheet, id: &str) -> LabelReviewWorksheet {
    worksheet.reviewer = Some(LabelReviewer {
        reviewer_id: id.to_string(),
        years_experience: 8,
        affiliation: "Independent reviewer".to_string(),
        independent_from_sniff: true,
        sniff_output_hidden: true,
        repository_context_inspected: true,
        maintainer: false,
        attestation: "I reviewed only the sealed source and context.".to_string(),
    });
    worksheet
}

fn clean(worksheet: &mut LabelReviewWorksheet) {
    for method in &mut worksheet.methods {
        method.decision.tier = Some(FindingTier::Clean);
        method.decision.pattern = "none".to_string();
        method.decision.intentional_boundary = Some(false);
        method.decision.rationale = "The method directly implements its contract.".to_string();
    }
}

fn finding(worksheet: &mut LabelReviewWorksheet) {
    let ids = worksheet
        .methods
        .iter()
        .map(|method| method.method_id.clone())
        .collect::<Vec<_>>();
    for (index, method) in worksheet.methods.iter_mut().enumerate() {
        method.decision.tier = Some(FindingTier::KindaSlop);
        method.decision.pattern = "duplicated_semantics".to_string();
        method.decision.intentional_boundary = Some(false);
        method.decision.rationale =
            "The pair implements one unnecessary duplicated concept.".to_string();
        method.decision.simplification = "Keep one implementation.".to_string();
        method.decision.behavioral_evidence =
            vec!["The public result remains unchanged.".to_string()];
        method.decision.related_method_ids = vec![ids[1 - index].clone()];
    }
}

fn resolver() -> LabelResolver {
    LabelResolver {
        resolver_id: "resolver-c".to_string(),
        years_experience: 10,
        affiliation: "Independent adjudicator".to_string(),
        maintainer: false,
        attestation: "I resolved only from the sealed audit evidence.".to_string(),
    }
}

fn after(root: &std::path::Path) -> SourceSnapshot {
    let text = "pub fn first() -> i32 { 1 }\n";
    fs::create_dir_all(root.join("after")).unwrap();
    fs::write(root.join("after/blind.rs"), text).unwrap();
    SourceSnapshot {
        repository: "https://github.com/example/blind".to_string(),
        revision: "2".repeat(40),
        repository_path: "src/blind.rs".to_string(),
        artifact_path: "after/blind.rs".to_string(),
        sha256: sha256(text.as_bytes()),
    }
}

#[test]
fn agreed_cross_method_finding_becomes_one_hash_bound_blind_case() {
    let (root, seal, seal_hash, template) = fixture();
    let mut first = reviewer(template.clone(), "reviewer-a");
    let mut second = reviewer(template, "reviewer-b");
    finding(&mut first);
    finding(&mut second);
    let audit = audit_label_reviews(&seal, root.path(), &seal_hash, &[first, second]).unwrap();
    let method_ids = seal
        .methods
        .iter()
        .map(|method| method.method_id.clone())
        .collect();
    let resolution = LabelResolutionManifest {
        schema_version: LABEL_RESOLUTION_SCHEMA_VERSION,
        source_seal_artifact_sha256: seal_hash.clone(),
        source_seal_commitment_sha256: seal.seal_sha256.clone(),
        label_audit_sha256: audit.audit_sha256.clone(),
        resolver: resolver(),
        cases: vec![ResolvedLabelCase {
            case_id: "blind-duplicate-pair".to_string(),
            method_ids,
            tier: Some(FindingTier::KindaSlop),
            pattern: "duplicated_semantics".to_string(),
            intentional_boundary: Some(false),
            human_explanation: "Both methods encode the same unnecessary behavior.".to_string(),
            behavioral_evidence: vec!["The reduced source preserves the result.".to_string()],
            expected_proof_level: 1,
            after: vec![after(root.path())],
            dispute_resolution: None,
        }],
    };

    let bundle =
        build_blind_case_bundle(&seal, &seal_hash, &audit, &resolution, root.path()).unwrap();

    assert_eq!(bundle.cases.len(), 1);
    assert_eq!(bundle.cases[0].covered_method_ids.len(), 2);
    assert_eq!(bundle.cases[0].before, seal.sources);
    assert!(!bundle.cases[0].disputed);
    assert_eq!(
        bundle.bundle_sha256,
        bundle.computed_bundle_sha256().unwrap()
    );
}

#[test]
fn undisputed_labels_and_relationship_components_cannot_be_changed() {
    let (root, seal, seal_hash, template) = fixture();
    let mut first = reviewer(template.clone(), "reviewer-a");
    let mut second = reviewer(template, "reviewer-b");
    finding(&mut first);
    finding(&mut second);
    let audit = audit_label_reviews(&seal, root.path(), &seal_hash, &[first, second]).unwrap();
    let cases = seal
        .methods
        .iter()
        .enumerate()
        .map(|(index, method)| ResolvedLabelCase {
            case_id: format!("split-{index}"),
            method_ids: vec![method.method_id.clone()],
            tier: Some(FindingTier::KindaSlop),
            pattern: "duplicated_semantics".to_string(),
            intentional_boundary: Some(false),
            human_explanation: "Attempted split.".to_string(),
            behavioral_evidence: vec!["Behavior preserved.".to_string()],
            expected_proof_level: 1,
            after: vec![after(root.path())],
            dispute_resolution: None,
        })
        .collect();
    let resolution = LabelResolutionManifest {
        schema_version: LABEL_RESOLUTION_SCHEMA_VERSION,
        source_seal_artifact_sha256: seal_hash.clone(),
        source_seal_commitment_sha256: seal.seal_sha256.clone(),
        label_audit_sha256: audit.audit_sha256.clone(),
        resolver: resolver(),
        cases,
    };

    let error =
        build_blind_case_bundle(&seal, &seal_hash, &audit, &resolution, root.path()).unwrap_err();

    assert!(error.contains("changes an undisputed relationship component"));
}

#[test]
fn disputed_label_requires_a_distinct_resolver_and_resolution_rationale() {
    let (root, seal, seal_hash, template) = fixture();
    let mut first = reviewer(template.clone(), "reviewer-a");
    let mut second = reviewer(template, "reviewer-b");
    clean(&mut first);
    clean(&mut second);
    second.methods[0].decision.tier = Some(FindingTier::KindaSlop);
    second.methods[0].decision.pattern = "ceremonial_logic".to_string();
    second.methods[0].decision.rationale = "The method is unnecessary ceremony.".to_string();
    second.methods[0].decision.simplification = "Remove the method.".to_string();
    second.methods[0].decision.behavioral_evidence = vec!["No behavior changes.".to_string()];
    let audit = audit_label_reviews(&seal, root.path(), &seal_hash, &[first, second]).unwrap();
    let cases = seal
        .methods
        .iter()
        .enumerate()
        .map(|(index, method)| ResolvedLabelCase {
            case_id: format!("resolved-{index}"),
            method_ids: vec![method.method_id.clone()],
            tier: Some(FindingTier::Clean),
            pattern: "none".to_string(),
            intentional_boundary: Some(false),
            human_explanation: "The repository contract justifies the method.".to_string(),
            behavioral_evidence: Vec::new(),
            expected_proof_level: 0,
            after: Vec::new(),
            dispute_resolution: (index == 0)
                .then(|| "A third reviewer confirmed the contract.".to_string()),
        })
        .collect();
    let mut resolution = LabelResolutionManifest {
        schema_version: LABEL_RESOLUTION_SCHEMA_VERSION,
        source_seal_artifact_sha256: seal_hash.clone(),
        source_seal_commitment_sha256: seal.seal_sha256.clone(),
        label_audit_sha256: audit.audit_sha256.clone(),
        resolver: resolver(),
        cases,
    };
    resolution.resolver.resolver_id = "reviewer-a".to_string();

    let error =
        build_blind_case_bundle(&seal, &seal_hash, &audit, &resolution, root.path()).unwrap_err();
    assert!(error.contains("resolver distinct"));

    resolution.resolver = resolver();
    resolution.cases[0].dispute_resolution = None;
    let error =
        build_blind_case_bundle(&seal, &seal_hash, &audit, &resolution, root.path()).unwrap_err();
    assert!(error.contains("dispute resolution"));
}

#[test]
fn resolution_rejects_omitted_methods() {
    let (root, seal, seal_hash, template) = fixture();
    let mut first = reviewer(template.clone(), "reviewer-a");
    let mut second = reviewer(template, "reviewer-b");
    clean(&mut first);
    clean(&mut second);
    let audit = audit_label_reviews(&seal, root.path(), &seal_hash, &[first, second]).unwrap();
    let resolution = LabelResolutionManifest {
        schema_version: LABEL_RESOLUTION_SCHEMA_VERSION,
        source_seal_artifact_sha256: seal_hash.clone(),
        source_seal_commitment_sha256: seal.seal_sha256.clone(),
        label_audit_sha256: audit.audit_sha256.clone(),
        resolver: resolver(),
        cases: vec![ResolvedLabelCase {
            case_id: "only-one".to_string(),
            method_ids: vec![seal.methods[0].method_id.clone()],
            tier: Some(FindingTier::Clean),
            pattern: "none".to_string(),
            intentional_boundary: Some(false),
            human_explanation: "The method is intentional.".to_string(),
            behavioral_evidence: Vec::new(),
            expected_proof_level: 0,
            after: Vec::new(),
            dispute_resolution: None,
        }],
    };

    let error =
        build_blind_case_bundle(&seal, &seal_hash, &audit, &resolution, root.path()).unwrap_err();

    assert!(error.contains("omits sealed methods"));
}

#[test]
fn resolution_rejects_tampered_after_artifacts() {
    let (root, seal, seal_hash, template) = fixture();
    let mut first = reviewer(template.clone(), "reviewer-a");
    let mut second = reviewer(template, "reviewer-b");
    finding(&mut first);
    finding(&mut second);
    let audit = audit_label_reviews(&seal, root.path(), &seal_hash, &[first, second]).unwrap();
    let method_ids = seal
        .methods
        .iter()
        .map(|method| method.method_id.clone())
        .collect();
    let after = after(root.path());
    fs::write(root.path().join(&after.artifact_path), "tampered\n").unwrap();
    let resolution = LabelResolutionManifest {
        schema_version: LABEL_RESOLUTION_SCHEMA_VERSION,
        source_seal_artifact_sha256: seal_hash.clone(),
        source_seal_commitment_sha256: seal.seal_sha256.clone(),
        label_audit_sha256: audit.audit_sha256.clone(),
        resolver: resolver(),
        cases: vec![ResolvedLabelCase {
            case_id: "tampered-after".to_string(),
            method_ids,
            tier: Some(FindingTier::KindaSlop),
            pattern: "duplicated_semantics".to_string(),
            intentional_boundary: Some(false),
            human_explanation: "Both methods encode unnecessary duplication.".to_string(),
            behavioral_evidence: vec!["The reduced source preserves the result.".to_string()],
            expected_proof_level: 1,
            after: vec![after],
            dispute_resolution: None,
        }],
    };

    let error =
        build_blind_case_bundle(&seal, &seal_hash, &audit, &resolution, root.path()).unwrap_err();

    assert!(error.contains("after hash mismatch"));
}

#[test]
fn resolution_draft_prefills_agreements_but_leaves_disputes_unresolved() {
    let (root, seal, seal_hash, template) = fixture();
    let mut first = reviewer(template.clone(), "reviewer-a");
    let mut second = reviewer(template, "reviewer-b");
    clean(&mut first);
    clean(&mut second);
    second.methods[0].decision.tier = Some(FindingTier::KindaSlop);
    second.methods[0].decision.pattern = "ceremonial_logic".to_string();
    second.methods[0].decision.rationale = "The method is unnecessary ceremony.".to_string();
    second.methods[0].decision.simplification = "Remove the method.".to_string();
    second.methods[0].decision.behavioral_evidence = vec!["No behavior changes.".to_string()];
    let audit = audit_label_reviews(&seal, root.path(), &seal_hash, &[first, second]).unwrap();

    let draft = prepare_label_resolution(&seal, &seal_hash, &audit).unwrap();

    assert!(draft.resolver.resolver_id.is_empty());
    assert_eq!(draft.cases.len(), 2);
    assert!(draft.cases.iter().any(|case| case.tier.is_none()));
    assert!(
        draft
            .cases
            .iter()
            .any(|case| case.tier == Some(FindingTier::Clean))
    );
}

#[test]
fn agreed_intentional_boundary_survives_resolution_into_the_blind_case() {
    let (root, seal, seal_hash, template) = fixture();
    let mut first = reviewer(template.clone(), "reviewer-a");
    let mut second = reviewer(template, "reviewer-b");
    clean(&mut first);
    clean(&mut second);
    first.methods[0].decision.intentional_boundary = Some(true);
    second.methods[0].decision.intentional_boundary = Some(true);
    first.methods[0].decision.rationale = "This is a deliberate public seam.".to_string();
    second.methods[0].decision.rationale = "This is a deliberate public seam.".to_string();
    let audit = audit_label_reviews(&seal, root.path(), &seal_hash, &[first, second]).unwrap();
    let mut resolution = prepare_label_resolution(&seal, &seal_hash, &audit).unwrap();
    resolution.resolver = resolver();

    let bundle =
        build_blind_case_bundle(&seal, &seal_hash, &audit, &resolution, root.path()).unwrap();

    let boundary = bundle
        .cases
        .iter()
        .find(|case| case.covered_method_ids == [seal.methods[0].method_id.clone()])
        .unwrap();
    assert_eq!(boundary.label.expected_tier, FindingTier::Clean);
    assert!(boundary.label.intentional_boundary);
}
