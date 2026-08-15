use super::super::intentional_boundary_label_review::tests::{completed, protocol, source_bundle};
use super::*;

fn reviews(
    root: &Path,
    bundle: &IntentionalBoundarySourceBundle,
    second_tier: FindingTier,
    second_boundary: bool,
) -> Vec<IntentionalBoundaryLabelWorksheet> {
    vec![
        completed(root, bundle, "reviewer-a", FindingTier::Clean, true),
        completed(root, bundle, "reviewer-b", second_tier, second_boundary),
    ]
}

fn resolver(id: &str) -> IntentionalBoundaryLabelResolver {
    IntentionalBoundaryLabelResolver {
        resolver_id: id.to_string(),
        years_experience: 11,
        affiliation: "Independent resolution panel".to_string(),
        independent_from_sniff: true,
        complete_source_context_inspected: true,
        attestation: "I independently resolved only the disputed fixed slot.".to_string(),
    }
}

fn resolution_decision(
    tier: FindingTier,
    intentional_boundary: bool,
) -> IntentionalBoundaryLabelDecision {
    IntentionalBoundaryLabelDecision {
        tier: Some(tier),
        intentional_boundary: Some(intentional_boundary),
        rationale: "The committed runtime source establishes the boundary.".to_string(),
        citations: vec![IntentionalBoundarySourceCitation {
            repository_path: "src/main.rs".to_string(),
            start_line: 1,
            end_line: 3,
            quote: "pub fn launch() -> u8 {\n    7\n}".to_string(),
        }],
    }
}

#[test]
fn accepted_consensus_is_frozen_without_an_unneeded_resolver() {
    let (root, bundle) = source_bundle();
    let reviews = reviews(root.path(), &bundle, FindingTier::Clean, true);
    let audit =
        audit_intentional_boundary_label_reviews(&protocol(), root.path(), &bundle, &reviews)
            .unwrap();
    let resolution = prepare_intentional_boundary_label_resolution(
        &protocol(),
        root.path(),
        &bundle,
        &reviews,
        &audit,
    )
    .unwrap();

    assert!(resolution.resolver.is_none());
    assert!(resolution.items[0].decision.is_none());
    let final_bundle = resolve_intentional_boundary_labels(
        &protocol(),
        root.path(),
        &bundle,
        &reviews,
        &audit,
        &resolution,
    )
    .unwrap();
    assert_eq!(final_bundle.accepted_count, 1);
    assert_eq!(final_bundle.closed_count, 0);
    assert_eq!(final_bundle.unfilled_slot_count, 15);
    assert_eq!(
        final_bundle.labels[0].outcome,
        IntentionalBoundaryFinalOutcome::Accepted {
            basis: IntentionalBoundaryFinalBasis::ReviewerConsensus
        }
    );
}

#[test]
fn a_distinct_resolver_can_accept_a_disputed_fixed_slot() {
    let (root, bundle) = source_bundle();
    let reviews = reviews(root.path(), &bundle, FindingTier::Clean, false);
    let audit =
        audit_intentional_boundary_label_reviews(&protocol(), root.path(), &bundle, &reviews)
            .unwrap();
    let mut resolution = prepare_intentional_boundary_label_resolution(
        &protocol(),
        root.path(),
        &bundle,
        &reviews,
        &audit,
    )
    .unwrap();
    resolution.resolver = Some(resolver("resolver-c"));
    resolution.items[0].decision = Some(resolution_decision(FindingTier::Clean, true));

    validate_intentional_boundary_label_resolution(
        &protocol(),
        root.path(),
        &bundle,
        &reviews,
        &audit,
        &resolution,
    )
    .unwrap();
    let final_bundle = resolve_intentional_boundary_labels(
        &protocol(),
        root.path(),
        &bundle,
        &reviews,
        &audit,
        &resolution,
    )
    .unwrap();
    assert_eq!(
        final_bundle.labels[0].outcome,
        IntentionalBoundaryFinalOutcome::Accepted {
            basis: IntentionalBoundaryFinalBasis::DisputeResolution
        }
    );
    validate_intentional_boundary_final_labels(
        &protocol(),
        root.path(),
        &bundle,
        &reviews,
        &audit,
        &resolution,
        &final_bundle,
    )
    .unwrap();
}

#[test]
fn rejected_and_resolved_negative_labels_close_slots_without_backfill() {
    let (root, bundle) = source_bundle();
    let rejected_reviews = vec![
        completed(
            root.path(),
            &bundle,
            "reviewer-a",
            FindingTier::Clean,
            false,
        ),
        completed(
            root.path(),
            &bundle,
            "reviewer-b",
            FindingTier::Clean,
            false,
        ),
    ];
    let rejected_audit = audit_intentional_boundary_label_reviews(
        &protocol(),
        root.path(),
        &bundle,
        &rejected_reviews,
    )
    .unwrap();
    let rejected_resolution = prepare_intentional_boundary_label_resolution(
        &protocol(),
        root.path(),
        &bundle,
        &rejected_reviews,
        &rejected_audit,
    )
    .unwrap();
    let rejected = resolve_intentional_boundary_labels(
        &protocol(),
        root.path(),
        &bundle,
        &rejected_reviews,
        &rejected_audit,
        &rejected_resolution,
    )
    .unwrap();
    assert_eq!(rejected.accepted_count, 0);
    assert_eq!(rejected.closed_count, 1);
    assert_eq!(rejected.labels.len(), 1);

    let disputed_reviews = reviews(root.path(), &bundle, FindingTier::Slop, false);
    let disputed_audit = audit_intentional_boundary_label_reviews(
        &protocol(),
        root.path(),
        &bundle,
        &disputed_reviews,
    )
    .unwrap();
    let mut disputed_resolution = prepare_intentional_boundary_label_resolution(
        &protocol(),
        root.path(),
        &bundle,
        &disputed_reviews,
        &disputed_audit,
    )
    .unwrap();
    disputed_resolution.resolver = Some(resolver("resolver-c"));
    disputed_resolution.items[0].decision = Some(resolution_decision(FindingTier::Slop, false));
    let resolved = resolve_intentional_boundary_labels(
        &protocol(),
        root.path(),
        &bundle,
        &disputed_reviews,
        &disputed_audit,
        &disputed_resolution,
    )
    .unwrap();
    assert_eq!(resolved.closed_count, 1);
    assert_eq!(resolved.unfilled_slot_count, 15);
    assert_eq!(resolved.labels.len(), 1);
}

#[test]
fn resolution_rejects_reviewer_resolvers_consensus_rewrites_and_final_tampering() {
    let (root, bundle) = source_bundle();
    let reviews = reviews(root.path(), &bundle, FindingTier::Clean, false);
    let audit =
        audit_intentional_boundary_label_reviews(&protocol(), root.path(), &bundle, &reviews)
            .unwrap();
    let mut resolution = prepare_intentional_boundary_label_resolution(
        &protocol(),
        root.path(),
        &bundle,
        &reviews,
        &audit,
    )
    .unwrap();
    resolution.resolver = Some(resolver("reviewer-a"));
    resolution.items[0].decision = Some(resolution_decision(FindingTier::Clean, true));
    assert!(
        validate_intentional_boundary_label_resolution(
            &protocol(),
            root.path(),
            &bundle,
            &reviews,
            &audit,
            &resolution,
        )
        .unwrap_err()
        .contains("distinct")
    );

    let accepted_reviews = vec![
        completed(root.path(), &bundle, "reviewer-a", FindingTier::Clean, true),
        completed(root.path(), &bundle, "reviewer-b", FindingTier::Clean, true),
    ];
    let accepted_audit = audit_intentional_boundary_label_reviews(
        &protocol(),
        root.path(),
        &bundle,
        &accepted_reviews,
    )
    .unwrap();
    let mut accepted_resolution = prepare_intentional_boundary_label_resolution(
        &protocol(),
        root.path(),
        &bundle,
        &accepted_reviews,
        &accepted_audit,
    )
    .unwrap();
    accepted_resolution.items[0].decision = Some(resolution_decision(FindingTier::Clean, false));
    assert!(
        validate_intentional_boundary_label_resolution(
            &protocol(),
            root.path(),
            &bundle,
            &accepted_reviews,
            &accepted_audit,
            &accepted_resolution,
        )
        .unwrap_err()
        .contains("rewrites consensus")
    );

    accepted_resolution.items[0].decision = None;
    let mut final_bundle = resolve_intentional_boundary_labels(
        &protocol(),
        root.path(),
        &bundle,
        &accepted_reviews,
        &accepted_audit,
        &accepted_resolution,
    )
    .unwrap();
    final_bundle.closed_count = 1;
    assert!(
        validate_intentional_boundary_final_labels(
            &protocol(),
            root.path(),
            &bundle,
            &accepted_reviews,
            &accepted_audit,
            &accepted_resolution,
            &final_bundle,
        )
        .unwrap_err()
        .contains("changed")
    );
}
