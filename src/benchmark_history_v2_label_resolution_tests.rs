use super::super::history_v2_label_review::tests::ReviewFixture;
use super::*;

#[test]
fn consensus_acceptance_cannot_be_rewritten() {
    let fixture = ReviewFixture::new();
    let worksheets = vec![
        fixture.accepted("reviewer-a", SlopPattern::NeedlessIndirection, ""),
        fixture.accepted("reviewer-b", SlopPattern::NeedlessIndirection, ""),
    ];
    let audit = fixture.audit(&worksheets);
    let resolution = prepare(&fixture, &worksheets, &audit);
    assert!(resolution.resolver.is_none());
    assert!(resolution.item.decision.is_none());
    let final_label = resolve(&fixture, &worksheets, &audit, &resolution);
    assert!(matches!(
        final_label.outcome,
        HistoricalV2FinalLabelOutcome::Accepted {
            basis: HistoricalV2FinalLabelBasis::ReviewerConsensus,
            pattern: SlopPattern::NeedlessIndirection,
            ..
        }
    ));
}

#[test]
fn consensus_rejection_permanently_closes_the_item() {
    let fixture = ReviewFixture::new();
    let worksheets = vec![
        fixture.rejected("reviewer-a"),
        fixture.rejected("reviewer-b"),
    ];
    let audit = fixture.audit(&worksheets);
    let resolution = prepare(&fixture, &worksheets, &audit);
    let final_label = resolve(&fixture, &worksheets, &audit, &resolution);
    assert!(matches!(
        final_label.outcome,
        HistoricalV2FinalLabelOutcome::Closed {
            basis: HistoricalV2FinalLabelBasis::ConsensusRejected,
            resolver_verdict: None,
        }
    ));
}

#[test]
fn a_dispute_requires_a_distinct_third_reviewer() {
    let fixture = ReviewFixture::new();
    let worksheets = disputed_worksheets(&fixture);
    let audit = fixture.audit(&worksheets);
    let resolution = prepare(&fixture, &worksheets, &audit);
    let error = validate(&fixture, &worksheets, &audit, &resolution).unwrap_err();
    assert!(error.contains("requires a distinct resolver"), "{error}");

    let mut repeated = resolution;
    repeated.resolver = Some(resolver("reviewer-a"));
    repeated.item.decision = Some(
        fixture
            .accepted("resolver", SlopPattern::NeedlessIndirection, "")
            .task
            .decision,
    );
    let error = validate(&fixture, &worksheets, &audit, &repeated).unwrap_err();
    assert!(error.contains("third party"), "{error}");

    let mut aliased = prepare(&fixture, &worksheets, &audit);
    aliased.resolver = Some(resolver("  REVIEWER-A "));
    aliased.item.decision = Some(
        fixture
            .accepted("resolver", SlopPattern::NeedlessIndirection, "")
            .task
            .decision,
    );
    let error = validate(&fixture, &worksheets, &audit, &aliased).unwrap_err();
    assert!(error.contains("third party"), "{error}");
}

#[test]
fn a_distinct_resolver_can_accept_a_disputed_case() {
    let fixture = ReviewFixture::new();
    let worksheets = disputed_worksheets(&fixture);
    let audit = fixture.audit(&worksheets);
    let mut resolution = prepare(&fixture, &worksheets, &audit);
    resolution.resolver = Some(resolver("resolver-c"));
    resolution.item.decision = Some(
        fixture
            .accepted("unused", SlopPattern::NeedlessIndirection, "")
            .task
            .decision,
    );
    let final_label = resolve(&fixture, &worksheets, &audit, &resolution);
    assert!(matches!(
        final_label.outcome,
        HistoricalV2FinalLabelOutcome::Accepted {
            basis: HistoricalV2FinalLabelBasis::DisputeResolution,
            pattern: SlopPattern::NeedlessIndirection,
            ..
        }
    ));
    assert_eq!(
        final_label.resolver.as_ref().unwrap().resolver_id,
        "resolver-c"
    );
}

#[test]
fn a_distinct_resolver_can_close_a_disputed_case() {
    let fixture = ReviewFixture::new();
    let worksheets = disputed_worksheets(&fixture);
    let audit = fixture.audit(&worksheets);
    let mut resolution = prepare(&fixture, &worksheets, &audit);
    resolution.resolver = Some(resolver("resolver-c"));
    resolution.item.decision = Some(fixture.rejected("unused").task.decision);
    let final_label = resolve(&fixture, &worksheets, &audit, &resolution);
    assert!(matches!(
        final_label.outcome,
        HistoricalV2FinalLabelOutcome::Closed {
            basis: HistoricalV2FinalLabelBasis::DisputeResolvedRejected,
            resolver_verdict: Some(HistoricalV2ReviewerVerdict::Reject),
        }
    ));
}

#[test]
fn rejects_attempts_to_add_a_resolver_to_consensus() {
    let fixture = ReviewFixture::new();
    let worksheets = vec![
        fixture.rejected("reviewer-a"),
        fixture.rejected("reviewer-b"),
    ];
    let audit = fixture.audit(&worksheets);
    let mut resolution = prepare(&fixture, &worksheets, &audit);
    resolution.resolver = Some(resolver("resolver-c"));
    let error = validate(&fixture, &worksheets, &audit, &resolution).unwrap_err();
    assert!(
        error.contains("cannot rewrite reviewer consensus"),
        "{error}"
    );
}

#[test]
fn final_label_validation_rejects_tampering() {
    let fixture = ReviewFixture::new();
    let worksheets = vec![
        fixture.accepted("reviewer-a", SlopPattern::NeedlessIndirection, ""),
        fixture.accepted("reviewer-b", SlopPattern::NeedlessIndirection, ""),
    ];
    let audit = fixture.audit(&worksheets);
    let resolution = prepare(&fixture, &worksheets, &audit);
    let mut final_label = resolve(&fixture, &worksheets, &audit, &resolution);
    final_label.language = "python".to_string();
    let error = validate_historical_v2_final_label(
        &fixture.protocol,
        fixture.root.path(),
        &fixture.bundle,
        &worksheets,
        &audit,
        &resolution,
        &final_label,
    )
    .unwrap_err();
    assert!(error.contains("final label changed"), "{error}");
}

fn disputed_worksheets(fixture: &ReviewFixture) -> Vec<HistoricalV2LabelWorksheet> {
    vec![
        fixture.accepted("reviewer-a", SlopPattern::NeedlessIndirection, ""),
        fixture.rejected("reviewer-b"),
    ]
}

fn resolver(resolver_id: &str) -> HistoricalV2LabelResolver {
    HistoricalV2LabelResolver {
        resolver_id: resolver_id.to_string(),
        years_experience: 10,
        affiliation: "independent".to_string(),
        independent_from_sniff: true,
        complete_source_context_inspected: true,
        behavior_evidence_inspected: true,
        model_assistance_used: false,
        attestation: "I resolved this dispute independently from exact source.".to_string(),
    }
}

fn prepare(
    fixture: &ReviewFixture,
    worksheets: &[HistoricalV2LabelWorksheet],
    audit: &HistoricalV2LabelAudit,
) -> HistoricalV2ResolutionWorksheet {
    prepare_historical_v2_label_resolution(
        &fixture.protocol,
        fixture.root.path(),
        &fixture.bundle,
        worksheets,
        audit,
    )
    .unwrap()
}

fn validate(
    fixture: &ReviewFixture,
    worksheets: &[HistoricalV2LabelWorksheet],
    audit: &HistoricalV2LabelAudit,
    resolution: &HistoricalV2ResolutionWorksheet,
) -> Result<(), String> {
    validate_historical_v2_label_resolution(
        &fixture.protocol,
        fixture.root.path(),
        &fixture.bundle,
        worksheets,
        audit,
        resolution,
    )
}

fn resolve(
    fixture: &ReviewFixture,
    worksheets: &[HistoricalV2LabelWorksheet],
    audit: &HistoricalV2LabelAudit,
    resolution: &HistoricalV2ResolutionWorksheet,
) -> HistoricalV2FinalLabel {
    resolve_historical_v2_label(
        &fixture.protocol,
        fixture.root.path(),
        &fixture.bundle,
        worksheets,
        audit,
        resolution,
    )
    .unwrap()
}
