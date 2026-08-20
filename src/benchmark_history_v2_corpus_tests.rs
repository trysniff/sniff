use super::super::history_v2_label_review::tests::ReviewFixture;
use super::super::history_v2_release_gate::tests::GateFixture;
use super::*;
use crate::product_contract::SlopPattern;
use std::fs;
use std::path::Path;

#[test]
fn accepted_review_becomes_an_exact_replayable_corpus_case() {
    let fixture = ReviewFixture::new();
    let corpus = tempfile::tempdir().unwrap();
    let bundle_root = corpus.path().join("review-bundle");
    copy_tree(fixture.root.path(), &bundle_root);
    let worksheets = vec![
        fixture.accepted("reviewer-a", SlopPattern::NeedlessIndirection, ""),
        fixture.accepted("reviewer-b", SlopPattern::NeedlessIndirection, ""),
    ];
    let audit = fixture.audit(&worksheets);
    let resolution = prepare_historical_v2_label_resolution(
        &fixture.protocol,
        &bundle_root,
        &fixture.bundle,
        &worksheets,
        &audit,
    )
    .unwrap();
    let final_label = resolve_historical_v2_label(
        &fixture.protocol,
        &bundle_root,
        &fixture.bundle,
        &worksheets,
        &audit,
        &resolution,
    )
    .unwrap();
    let reviewed = HistoricalV2ReviewedSlotArtifacts {
        language: "rust",
        slot_number: 7,
        bundle_root: &bundle_root,
        bundle: &fixture.bundle,
        worksheets: &worksheets,
        audit: &audit,
        resolution: &resolution,
        final_label: &final_label,
    };
    let accepted = accepted_outcome(&fixture.bundle, &audit, &final_label);
    let binding =
        build_historical_v2_corpus_binding(&fixture.protocol, corpus.path(), &reviewed, &accepted)
            .unwrap();

    assert_eq!(binding.case.label.language, "rust");
    assert_eq!(binding.case.expected_proof_level, 3);
    assert_eq!(binding.case.adjudications.len(), 2);
    assert_eq!(binding.case.before.len(), 1);
    assert_eq!(binding.case.after.len(), 1);
    validation::validate_binding(&fixture.protocol, corpus.path(), &binding, &accepted).unwrap();

    let mut changed = binding.clone();
    changed.case.human_explanation.push_str(" invented");
    let error = validation::validate_binding(&fixture.protocol, corpus.path(), &changed, &accepted)
        .unwrap_err();
    assert!(
        error.contains("changed from its reviewed source"),
        "{error}"
    );

    let mut changed = binding.clone();
    changed.audit.labels[0]
        .decision
        .rationale
        .push_str(" invented");
    let error = validation::validate_binding(&fixture.protocol, corpus.path(), &changed, &accepted)
        .unwrap_err();
    assert!(
        error.contains("audit") || error.contains("label"),
        "{error}"
    );

    fs::write(
        corpus.path().join(&binding.case.before[0].artifact_path),
        b"fn simplify() {}\n",
    )
    .unwrap();
    let error = validation::validate_binding(&fixture.protocol, corpus.path(), &binding, &accepted)
        .unwrap_err();
    assert!(error.contains("review object changed"), "{error}");
}

#[test]
fn corpus_binding_rejects_source_bundle_outside_corpus() {
    let fixture = ReviewFixture::new();
    let corpus = tempfile::tempdir().unwrap();
    let worksheets = vec![
        fixture.accepted("reviewer-a", SlopPattern::NeedlessIndirection, ""),
        fixture.accepted("reviewer-b", SlopPattern::NeedlessIndirection, ""),
    ];
    let audit = fixture.audit(&worksheets);
    let resolution = prepare_historical_v2_label_resolution(
        &fixture.protocol,
        fixture.root.path(),
        &fixture.bundle,
        &worksheets,
        &audit,
    )
    .unwrap();
    let final_label = resolve_historical_v2_label(
        &fixture.protocol,
        fixture.root.path(),
        &fixture.bundle,
        &worksheets,
        &audit,
        &resolution,
    )
    .unwrap();
    let reviewed = HistoricalV2ReviewedSlotArtifacts {
        language: "rust",
        slot_number: 7,
        bundle_root: fixture.root.path(),
        bundle: &fixture.bundle,
        worksheets: &worksheets,
        audit: &audit,
        resolution: &resolution,
        final_label: &final_label,
    };
    let accepted = accepted_outcome(&fixture.bundle, &audit, &final_label);
    let error =
        build_historical_v2_corpus_binding(&fixture.protocol, corpus.path(), &reviewed, &accepted)
            .unwrap_err();
    assert!(error.contains("outside the corpus root"), "{error}");
}

#[test]
fn underfilled_release_cannot_create_a_corpus_bundle() {
    let fixture = GateFixture::new(Vec::new());
    let evidence = fixture.build(&[]).unwrap();
    let corpus = tempfile::tempdir().unwrap();
    let evidence_path = corpus.path().join("release-evidence.json");
    let gate_inputs = fixture.inputs(&[]);
    write_historical_v2_release_evidence(&gate_inputs, &evidence, &evidence_path).unwrap();
    let inputs = HistoricalV2CorpusBundleInputs {
        gate_inputs: &gate_inputs,
        release_evidence: &evidence,
        corpus_root: corpus.path(),
        release_evidence_path: &evidence_path,
    };
    let error = create_historical_v2_corpus_bundle(
        &inputs,
        &corpus.path().join("historical-v2-corpus.json"),
    )
    .unwrap_err();
    assert!(error.contains("underfilled"), "{error}");
}

#[test]
fn corpus_persistence_is_create_new_and_bounded() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("bundle.json");
    let bundle = HistoricalV2CorpusBundle {
        schema_version: HISTORICAL_V2_CORPUS_BUNDLE_SCHEMA_VERSION,
        corpus_contract: CORPUS_CONTRACT.to_string(),
        protocol_sha256: "a".repeat(64),
        selection_sha256: "b".repeat(64),
        release_evidence_artifact_path: "release.json".to_string(),
        release_evidence_artifact_sha256: "c".repeat(64),
        release_evidence_sha256: "d".repeat(64),
        accepted_count: 0,
        cases: Vec::new(),
        bundle_sha256: "e".repeat(64),
    };
    persist_corpus_bundle(&output, &bundle).unwrap();
    let error = persist_corpus_bundle(&output, &bundle).unwrap_err();
    assert!(error.contains("failed to create"), "{error}");
}

#[test]
fn new_corpus_artifact_must_stay_inside_its_plain_root() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    require_new_file_under_root(root.path(), &root.path().join("bundle.json")).unwrap();
    let error =
        require_new_file_under_root(root.path(), &outside.path().join("bundle.json")).unwrap_err();
    assert!(error.contains("outside its corpus root"), "{error}");
}

fn accepted_outcome(
    bundle: &HistoricalV2SourceReviewBundle,
    audit: &HistoricalV2LabelAudit,
    label: &HistoricalV2FinalLabel,
) -> HistoricalV2ReleaseSlotOutcome {
    let HistoricalV2FinalLabelOutcome::Accepted {
        basis,
        pattern,
        other_pattern,
    } = &label.outcome
    else {
        panic!("fixture final label must be accepted");
    };
    HistoricalV2ReleaseSlotOutcome::Accepted {
        terminal_checkpoint_sha256: bundle.terminal_checkpoint_sha256.clone(),
        review_item_id: bundle.review_item_id.clone(),
        source_bundle_sha256: bundle.bundle_sha256.clone(),
        label_audit_sha256: audit.audit_sha256.clone(),
        final_label_sha256: label.final_sha256.clone(),
        basis: *basis,
        pattern: *pattern,
        other_pattern: other_pattern.clone(),
    }
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}
