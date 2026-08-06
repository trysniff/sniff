use super::{
    IntentMethodReview, SemanticMethodReview, append_intent_challenge,
    enforce_boundary_requirements, enforce_dead_code_proof, missing_evidence_needs_history,
    needs_private_unused_refinement, numbered_method_source,
    private_unused_requires_signature_change, proven_private_unused_review,
    render_adjudication_prompt,
};
use crate::types::MethodRecord;

#[test]
fn history_expansion_requires_history_relevant_missing_evidence() {
    assert!(missing_evidence_needs_history(&[
        "commit history for the compatibility boundary".to_string()
    ]));
    assert!(missing_evidence_needs_history(&[
        "previous version behavior".to_string()
    ]));
    assert!(!missing_evidence_needs_history(&[
        "external framework registration".to_string()
    ]));
    assert!(!missing_evidence_needs_history(&[
        "runtime callback consumer".to_string()
    ]));
}

#[test]
fn private_unused_proof_replaces_invented_model_actions_with_graph_facts() {
    let method = MethodRecord {
        name: "_run".to_string(),
        file_path: "src/demo.py".to_string(),
        source: "def _run():\n    return process_data([])\n".to_string(),
        loc: 2,
        param_count: 0,
        start_line: 4,
        end_line: 5,
        is_exported: false,
        language: "python".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let scoped = SemanticMethodReview {
        tier: crate::types::FindingTier::Slop,
        pattern: crate::product_contract::SlopPattern::NeedlessIndirection,
        intent: "Run processing.".to_string(),
        reason: "Inline the call elsewhere.".to_string(),
        evidence: Vec::new(),
        necessity_check: "The method is unused.".to_string(),
        contract_status: "unnecessary".to_string(),
        contract_impact: "No contract impact.".to_string(),
        dependency_impact: "The call is inlined.".to_string(),
        simplification: "Delete the method.".to_string(),
        change_scope: "whole_method".to_string(),
        behavior_status: "preserved".to_string(),
        missing_evidence: Vec::new(),
    };

    let coordinated = proven_private_unused_review(&method, scoped.clone(), true);
    assert_eq!(coordinated.change_scope, "signature");
    assert!(
        coordinated
            .simplification
            .contains("private contract surface")
    );
    assert!(private_unused_requires_signature_change(
        "private returned-object surface entries requiring coordinated removal: src/runtime.ts:6: snapshot,"
    ));

    let proven = proven_private_unused_review(&method, scoped, false);

    assert_eq!(proven.simplification, "Delete the entire method.");
    assert!(!proven.dependency_impact.contains("inlined"));
    assert!(proven.dependency_impact.contains("closed repository graph"));
    assert_eq!(proven.evidence[0].quote, method.source);
    assert_eq!(proven.evidence[0].start_line, 4);
    assert_eq!(proven.evidence[0].end_line, 5);
}

#[test]
fn proven_private_unused_clean_or_unresolved_reviews_require_severity_refinement() {
    let mut review = SemanticMethodReview {
        tier: crate::types::FindingTier::Clean,
        pattern: crate::product_contract::SlopPattern::None,
        intent: "Provide a private helper.".to_string(),
        reason: "The method appears coherent.".to_string(),
        evidence: Vec::new(),
        necessity_check: "The dossier establishes no consumer.".to_string(),
        contract_status: "required".to_string(),
        contract_impact: "No public contract exists.".to_string(),
        dependency_impact: "No dependency exists.".to_string(),
        simplification: "none".to_string(),
        change_scope: "none".to_string(),
        behavior_status: "preserved".to_string(),
        missing_evidence: Vec::new(),
    };

    assert!(needs_private_unused_refinement(&review, true));
    assert!(!needs_private_unused_refinement(&review, false));
    review.tier = crate::types::FindingTier::Unresolved;
    assert!(needs_private_unused_refinement(&review, true));
    review.tier = crate::types::FindingTier::Slop;
    assert!(!needs_private_unused_refinement(&review, true));
}

#[test]
fn adjudicator_prompt_protects_intentional_boundaries() {
    let method = MethodRecord {
        name: "request_headers".to_string(),
        file_path: "src/orchestrator/court.py".to_string(),
        source:
            "def request_headers(token, endpoint):\n    return _request_headers(token, endpoint)\n"
                .to_string(),
        loc: 2,
        param_count: 2,
        start_line: 1,
        end_line: 2,
        is_exported: false,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 1,
    };
    let intent = IntentMethodReview {
        intent: "Expose a stable public boundary.".to_string(),
        necessity_check: "The boundary is intentional.".to_string(),
        contract_status: "required".to_string(),
        missing_evidence: vec![],
    };
    let review = SemanticMethodReview {
        tier: crate::types::FindingTier::Clean,
        pattern: crate::product_contract::SlopPattern::None,
        intent: "Expose a stable public boundary.".to_string(),
        reason: "clean".to_string(),
        evidence: vec![],
        necessity_check: "The boundary is intentional.".to_string(),
        contract_status: "required".to_string(),
        contract_impact: "The stable boundary requires this signature.".to_string(),
        dependency_impact: "Known callers depend on the boundary.".to_string(),
        simplification: "none".to_string(),
        change_scope: "none".to_string(),
        behavior_status: "preserved".to_string(),
        missing_evidence: vec![],
    };

    let prompt = render_adjudication_prompt(&method, "", &[], &[], &intent, &review);
    assert!(prompt.contains("dependency-injection seams"));
    assert!(prompt.contains("never `slop`"));
    assert!(prompt.contains("Scope a finding to the exact cited machinery"));
    assert!(prompt.contains("the signature can remain unchanged"));
    for pattern in crate::product_contract::SlopPattern::FINDING_PATTERNS {
        assert!(prompt.contains(pattern.as_str()));
    }
    assert!(!prompt.contains("intent_hidden"));
    assert!(!prompt.contains("duplicated_decision_paths"));
    assert!(!prompt.contains("unnecessarily_complicated"));
}

#[test]
fn adjudicator_source_does_not_carry_the_retired_wire_ontology() {
    let source = include_str!("../analyzer_method.rs");
    for retired in [
        "intent_hidden",
        "duplicated_decision_paths",
        "difficult_state_transition",
        "semantic_mismatch",
        "unnecessarily_complicated",
    ] {
        assert!(
            !source.contains(retired),
            "retired pattern remains: {retired}"
        );
    }
}

#[test]
fn adversarial_prompt_receives_the_intent_and_its_missing_evidence() {
    let intent = IntentMethodReview {
        intent: "Preserve a stable callback seam.".to_string(),
        necessity_check: "The callback consumer is not yet established.".to_string(),
        contract_status: "unknown".to_string(),
        missing_evidence: vec!["callback registration site".to_string()],
    };

    let prompt = append_intent_challenge("challenge this method".to_string(), &intent);

    assert!(prompt.contains("Preserve a stable callback seam."));
    assert!(prompt.contains("callback registration site"));
    assert!(prompt.contains("Investigate every listed missing-evidence item"));
    assert!(prompt.contains("never hedge with Kinda Slop"));
}

#[test]
fn method_dossier_numbers_source_with_absolute_lines() {
    let method = MethodRecord {
        name: "demo".to_string(),
        file_path: "src/demo.py".to_string(),
        source: "def demo():\n    return 1\n".to_string(),
        loc: 2,
        param_count: 0,
        start_line: 41,
        end_line: 42,
        is_exported: true,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };

    let source = numbered_method_source(&method);
    assert!(source.contains("    41 | def demo():"));
    assert!(source.contains("    42 |     return 1"));
}

#[test]
fn reference_context_keeps_every_resolved_call_site() {
    let references = (0..10)
        .map(|index| crate::types::Reference {
            file_path: format!("src/caller_{index}.py"),
            line: index + 1,
            snippet: "x".repeat(5_000),
        })
        .collect::<Vec<_>>();

    let rendered = super::render_reference_context(&references);
    assert!(rendered.contains("src/caller_0.py:1"));
    assert!(rendered.contains("src/caller_9.py:10"));
}

#[test]
fn high_fanout_reference_context_keeps_every_call_without_repeating_surrounding_noise() {
    let references = (0..30)
            .map(|index| {
                let line = 100 + index;
                crate::types::Reference {
                    file_path: format!("src/caller_{index}.kt"),
                    line,
                    snippet: format!(
                        "Caller Method: caller_{index} (lines 1-200)\nCall site at line {line}:\n    99 | {}\n{:>6} | target_{index}()\n{:>6} | {}",
                        "before".repeat(100),
                        line,
                        line + 1,
                        "after".repeat(100),
                    ),
                }
            })
            .collect::<Vec<_>>();

    let rendered = super::render_reference_context(&references);

    for index in 0..30 {
        assert!(rendered.contains(&format!("FILE: src/caller_{index}.kt")));
        assert!(rendered.contains(&format!("line {}", 100 + index)));
        assert!(rendered.contains(&format!("target_{index}()")));
    }
    assert!(rendered.contains("Representative surrounding caller contexts"));
    assert!(rendered.matches(&"before".repeat(100)).count() <= 8);
    assert!(rendered.len() < 20_000);
}

#[test]
fn unresolved_boundary_requirements_override_a_clean_model_verdict() {
    let review = SemanticMethodReview {
        tier: crate::types::FindingTier::Clean,
        pattern: crate::product_contract::SlopPattern::None,
        intent: "Expose an exported alias.".to_string(),
        reason: "clean".to_string(),
        evidence: vec![],
        necessity_check: "No repository caller is known.".to_string(),
        contract_status: "required".to_string(),
        contract_impact: "The exported alias may be externally stable.".to_string(),
        dependency_impact: "External callers cannot be resolved.".to_string(),
        simplification: "none".to_string(),
        change_scope: "none".to_string(),
        behavior_status: "preserved".to_string(),
        missing_evidence: vec![],
    };

    let review = enforce_boundary_requirements(review, &["external consumers".to_string()]);
    assert_eq!(review.tier, crate::types::FindingTier::Unresolved);
    assert_eq!(review.missing_evidence, vec!["external consumers"]);
    assert_eq!(review.contract_status, "unknown");
}

#[test]
fn exported_whole_method_removal_becomes_unresolved() {
    let method = MethodRecord {
        name: "public_helper".to_string(),
        file_path: "src/api.py".to_string(),
        source: "def public_helper():\n    return 1\n".to_string(),
        loc: 2,
        param_count: 0,
        start_line: 1,
        end_line: 2,
        is_exported: true,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };
    let review = SemanticMethodReview {
        tier: crate::types::FindingTier::Slop,
        pattern: crate::product_contract::SlopPattern::CeremonialLogic,
        intent: "Expose a helper.".to_string(),
        reason: "The helper appears unused.".to_string(),
        evidence: vec![],
        necessity_check: "No repository callers were found.".to_string(),
        contract_status: "unnecessary".to_string(),
        contract_impact: "Delete it.".to_string(),
        dependency_impact: "No repository callers.".to_string(),
        simplification: "Delete the method.".to_string(),
        change_scope: "whole_method".to_string(),
        behavior_status: "preserved".to_string(),
        missing_evidence: vec![],
    };

    let private_review = super::enforce_exported_change_scope(review.clone(), &method, true);
    assert_eq!(private_review.tier, crate::types::FindingTier::Slop);
    assert_eq!(private_review.change_scope, "whole_method");

    let public_review = super::enforce_exported_change_scope(review, &method, false);
    assert_eq!(public_review.tier, crate::types::FindingTier::Unresolved);
    assert_eq!(public_review.change_scope, "none");
    assert!(public_review.missing_evidence[0].contains("external consumers"));
}

#[test]
fn dead_code_requires_the_closed_world_private_unused_proof() {
    let mut method = MethodRecord {
        name: "helper".to_string(),
        file_path: "src/helper.kt".to_string(),
        source: "private fun helper() = Unit".to_string(),
        loc: 1,
        param_count: 0,
        start_line: 1,
        end_line: 1,
        is_exported: false,
        language: "kotlin".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 2,
    };
    let dead_review = SemanticMethodReview {
        tier: crate::types::FindingTier::Slop,
        pattern: crate::product_contract::SlopPattern::ResidualMachinery,
        intent: "Provide a helper.".to_string(),
        reason: "No callers exist.".to_string(),
        evidence: vec![],
        necessity_check: "No consumer exists.".to_string(),
        contract_status: "unnecessary".to_string(),
        contract_impact: "Delete the helper.".to_string(),
        dependency_impact: "No dependencies exist.".to_string(),
        simplification: "Delete the method.".to_string(),
        change_scope: "whole_method".to_string(),
        behavior_status: "preserved".to_string(),
        missing_evidence: vec![],
    };

    let called = enforce_dead_code_proof(dead_review.clone(), &method, false);
    assert_eq!(called.tier, crate::types::FindingTier::Clean);
    assert!(called.reason.contains("2 caller(s)"));

    method.real_ref_count = 0;
    method.is_exported = true;
    let public = enforce_dead_code_proof(dead_review.clone(), &method, false);
    assert_eq!(public.tier, crate::types::FindingTier::Clean);
    assert!(public.reason.contains("externally visible"));

    let proven = enforce_dead_code_proof(dead_review, &method, true);
    assert_eq!(proven.tier, crate::types::FindingTier::Slop);
}

#[test]
fn local_residual_machinery_does_not_require_whole_method_dead_code_proof() {
    let method = MethodRecord {
        name: "sample".to_string(),
        file_path: "src/sample.py".to_string(),
        source: "def sample():\n    noop()\n    return 1\n".to_string(),
        loc: 3,
        param_count: 0,
        start_line: 1,
        end_line: 3,
        is_exported: false,
        language: "python".to_string(),
        nesting_depth: 0,
        references: vec![],
        real_ref_count: 0,
    };
    let review = SemanticMethodReview {
        tier: crate::types::FindingTier::KindaSlop,
        pattern: crate::product_contract::SlopPattern::ResidualMachinery,
        intent: "Return one.".to_string(),
        reason: "The no-op call adds residual machinery.".to_string(),
        evidence: vec![],
        necessity_check: "The no-op has no contract purpose.".to_string(),
        contract_status: "unnecessary".to_string(),
        contract_impact: "Removing the no-op preserves the callable contract.".to_string(),
        dependency_impact: "No dependency observes the no-op.".to_string(),
        simplification: "Remove noop().".to_string(),
        change_scope: "local".to_string(),
        behavior_status: "preserved".to_string(),
        missing_evidence: vec![],
    };

    assert_eq!(
        enforce_dead_code_proof(review.clone(), &method, false),
        review
    );
}
