use super::super::history_v3_label_review::tests::{ReviewFixture, review_fixture};
use super::super::{
    HistoricalV3FinalLabelBasis, HistoricalV3FinalLabelOutcome, HistoricalV3LabelResolver,
    HistoricalV3LabelStatus, HistoricalV3ReviewerVerdict, audit_historical_v3_label_reviews,
    read_historical_v3_label_audit, read_historical_v3_resolution_worksheet,
    validate_historical_v3_label_audit, write_historical_v3_label_audit_new,
    write_historical_v3_resolution_worksheet_new,
};

#[tokio::test]
async fn persists_audit_and_resolution_create_new_for_replay() {
    let fixture = review_fixture().await;
    let worksheets = worksheets(&fixture, HistoricalV3ReviewerVerdict::Slop);
    let inputs = fixture.inputs();
    let audit = audit_historical_v3_label_reviews(&inputs, &fixture.bundle, &worksheets).unwrap();
    let resolution =
        prepare_historical_v3_label_resolution(&inputs, &fixture.bundle, &worksheets, &audit)
            .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let audit_path = directory.path().join("audit.json");
    let resolution_path = directory.path().join("resolution.json");
    write_historical_v3_label_audit_new(&audit_path, &audit).unwrap();
    write_historical_v3_resolution_worksheet_new(&resolution_path, &resolution).unwrap();
    assert!(write_historical_v3_label_audit_new(&audit_path, &audit).is_err());
    assert!(write_historical_v3_resolution_worksheet_new(&resolution_path, &resolution).is_err());
    let stored_audit = read_historical_v3_label_audit(&audit_path).unwrap();
    let stored_resolution = read_historical_v3_resolution_worksheet(&resolution_path).unwrap();
    validate_historical_v3_label_audit(&inputs, &fixture.bundle, &worksheets, &stored_audit)
        .unwrap();
    validate_historical_v3_label_resolution(
        &inputs,
        &fixture.bundle,
        &worksheets,
        &stored_audit,
        &stored_resolution,
    )
    .unwrap();
    let mut altered_audit = stored_audit;
    altered_audit.audit_sha256 = "0".repeat(64);
    let altered_path = directory.path().join("altered-audit.json");
    write_historical_v3_label_audit_new(&altered_path, &altered_audit).unwrap();
    assert!(
        validate_historical_v3_label_audit(
            &inputs,
            &fixture.bundle,
            &worksheets,
            &read_historical_v3_label_audit(&altered_path).unwrap(),
        )
        .is_err()
    );
}
use super::{
    prepare_historical_v3_label_resolution, resolve_historical_v3_label,
    validate_historical_v3_final_label, validate_historical_v3_label_resolution,
};

#[tokio::test]
async fn freezes_positive_and_typed_non_slop_consensus_without_a_resolver() {
    let fixture = review_fixture().await;
    let positive = worksheets(&fixture, HistoricalV3ReviewerVerdict::Slop);
    let accepted_audit =
        audit_historical_v3_label_reviews(&fixture.inputs(), &fixture.bundle, &positive).unwrap();
    let accepted_resolution = prepare_historical_v3_label_resolution(
        &fixture.inputs(),
        &fixture.bundle,
        &positive,
        &accepted_audit,
    )
    .unwrap();
    assert!(accepted_resolution.resolver.is_none());
    assert!(accepted_resolution.item.decision.is_none());
    let accepted = resolve_historical_v3_label(
        &fixture.inputs(),
        &fixture.bundle,
        &positive,
        &accepted_audit,
        &accepted_resolution,
    )
    .unwrap();
    assert!(matches!(
        accepted.outcome,
        HistoricalV3FinalLabelOutcome::Accepted {
            basis: HistoricalV3FinalLabelBasis::ReviewerConsensus,
            ..
        }
    ));

    let clean = worksheets(&fixture, HistoricalV3ReviewerVerdict::Clean);
    let clean_audit =
        audit_historical_v3_label_reviews(&fixture.inputs(), &fixture.bundle, &clean).unwrap();
    let clean_resolution = prepare_historical_v3_label_resolution(
        &fixture.inputs(),
        &fixture.bundle,
        &clean,
        &clean_audit,
    )
    .unwrap();
    let closed = resolve_historical_v3_label(
        &fixture.inputs(),
        &fixture.bundle,
        &clean,
        &clean_audit,
        &clean_resolution,
    )
    .unwrap();
    assert_eq!(
        closed.outcome,
        HistoricalV3FinalLabelOutcome::Closed {
            basis: HistoricalV3FinalLabelBasis::ConsensusNonSlop,
            verdict: HistoricalV3ReviewerVerdict::Clean,
        }
    );

    let mut rewrite = clean_resolution;
    rewrite.resolver = Some(resolver("resolver-c"));
    assert!(
        validate_historical_v3_label_resolution(
            &fixture.inputs(),
            &fixture.bundle,
            &clean,
            &clean_audit,
            &rewrite,
        )
        .unwrap_err()
        .contains("cannot rewrite reviewer consensus")
    );
}

#[tokio::test]
async fn disputed_review_requires_a_distinct_human_resolver_and_exact_decision() {
    let fixture = review_fixture().await;
    let disputed = vec![
        fixture.worksheet("reviewer-a", HistoricalV3ReviewerVerdict::Clean),
        fixture.worksheet(
            "reviewer-b",
            HistoricalV3ReviewerVerdict::IntentionalBoundary,
        ),
    ];
    let audit =
        audit_historical_v3_label_reviews(&fixture.inputs(), &fixture.bundle, &disputed).unwrap();
    assert_eq!(audit.status, HistoricalV3LabelStatus::Disputed);
    let mut resolution = prepare_historical_v3_label_resolution(
        &fixture.inputs(),
        &fixture.bundle,
        &disputed,
        &audit,
    )
    .unwrap();
    assert!(
        validate_historical_v3_label_resolution(
            &fixture.inputs(),
            &fixture.bundle,
            &disputed,
            &audit,
            &resolution,
        )
        .unwrap_err()
        .contains("distinct resolver")
    );

    resolution.resolver = Some(resolver(" REVIEWER-A "));
    resolution.item.decision = Some(
        fixture
            .worksheet("unused", HistoricalV3ReviewerVerdict::Slop)
            .task
            .decision,
    );
    assert!(
        validate_historical_v3_label_resolution(
            &fixture.inputs(),
            &fixture.bundle,
            &disputed,
            &audit,
            &resolution,
        )
        .unwrap_err()
        .contains("third party")
    );

    resolution.resolver = Some(resolver("resolver-c"));
    validate_historical_v3_label_resolution(
        &fixture.inputs(),
        &fixture.bundle,
        &disputed,
        &audit,
        &resolution,
    )
    .unwrap();
    let final_label = resolve_historical_v3_label(
        &fixture.inputs(),
        &fixture.bundle,
        &disputed,
        &audit,
        &resolution,
    )
    .unwrap();
    assert!(matches!(
        final_label.outcome,
        HistoricalV3FinalLabelOutcome::Accepted {
            basis: HistoricalV3FinalLabelBasis::DisputeResolution,
            ..
        }
    ));
    validate_historical_v3_final_label(
        &fixture.inputs(),
        &fixture.bundle,
        &disputed,
        &audit,
        &resolution,
        &final_label,
    )
    .unwrap();
    let mut tampered = final_label;
    tampered.language = "forged".to_string();
    assert!(
        validate_historical_v3_final_label(
            &fixture.inputs(),
            &fixture.bundle,
            &disputed,
            &audit,
            &resolution,
            &tampered,
        )
        .unwrap_err()
        .contains("final label changed")
    );
}

fn worksheets(
    fixture: &ReviewFixture,
    verdict: HistoricalV3ReviewerVerdict,
) -> Vec<super::super::HistoricalV3LabelWorksheet> {
    vec![
        fixture.worksheet("reviewer-a", verdict),
        fixture.worksheet("reviewer-b", verdict),
    ]
}

fn resolver(resolver_id: &str) -> HistoricalV3LabelResolver {
    HistoricalV3LabelResolver {
        resolver_id: resolver_id.to_string(),
        years_experience: 8,
        affiliation: "independent".to_string(),
        independent_from_sniff: true,
        sniff_output_hidden: true,
        repository_identity_hidden: true,
        change_metadata_hidden: true,
        complete_source_context_inspected: true,
        behavior_evidence_inspected: true,
        model_assistance_used: false,
        attestation: "I independently resolved the dispute from exact blinded evidence."
            .to_string(),
    }
}
