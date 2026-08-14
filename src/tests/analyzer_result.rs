use super::{
    IntentMethodReview, SemanticEvidence, SemanticMethodReview, build_method_review_record,
    build_semantic_method_verdict, evidence_matches_source, parse_adversarial_method_review,
    parse_semantic_method_review, validate_file_review,
};
use crate::product_contract::SlopPattern;
use crate::types::{FindingTier, MethodRecord};

fn established_intent() -> IntentMethodReview {
    IntentMethodReview {
        intent: "Return the normalized value.".to_string(),
        contract_status: "required".to_string(),
        necessity_check: "A resolved caller consumes the normalized value.".to_string(),
        missing_evidence: Vec::new(),
    }
}

#[test]
fn method_review_record_persists_the_full_semantic_review() {
    let method = MethodRecord {
        name: "normalize".to_string(),
        file_path: "src/demo.py".to_string(),
        source: "def normalize(value):\n    return value.strip()\n".to_string(),
        loc: 2,
        param_count: 1,
        start_line: 1,
        end_line: 2,
        is_exported: false,
        language: "python".to_string(),
        nesting_depth: 0,
        references: Vec::new(),
        real_ref_count: 0,
    };
    let review = SemanticMethodReview {
        tier: FindingTier::Slop,
        pattern: SlopPattern::CeremonialLogic,
        intent: "Normalize the value before returning it.".to_string(),
        reason: "The temporary layer adds no distinct behavior.".to_string(),
        evidence: vec![SemanticEvidence {
            start_line: 2,
            end_line: 2,
            quote: "return value.strip()".to_string(),
        }],
        necessity_check: "The method can return the expression directly.".to_string(),
        contract_status: "unnecessary".to_string(),
        contract_impact: "The return contract is preserved.".to_string(),
        dependency_impact: "No caller depends on the temporary layer.".to_string(),
        simplification: "Return value.strip() directly.".to_string(),
        change_scope: "local".to_string(),
        behavior_status: "preserved".to_string(),
        missing_evidence: Vec::new(),
    };

    let record = build_method_review_record(&review, "method-1", "hash-1", &method);

    assert_eq!(record.unit_id, "method-1");
    assert_eq!(record.source_hash, "hash-1");
    assert_eq!(record.pattern, "ceremonial_logic");
    assert_eq!(record.intent, review.intent);
    assert_eq!(record.evidence.len(), 1);
    assert_eq!(record.evidence[0].quote, "return value.strip()");
    assert_eq!(record.verdict.tier, FindingTier::Slop);
}

#[test]
fn compact_clean_adversarial_review_reuses_the_established_intent_proof() {
    let result = serde_json::json!({
        "tier": "clean",
        "reason": "The implementation directly serves the established contract."
    });

    let review =
        parse_adversarial_method_review(&result, &established_intent(), "return value", 1, 1)
            .unwrap();

    assert_eq!(review.tier, FindingTier::Clean);
    assert_eq!(review.contract_status, "required");
    assert_eq!(review.simplification, "none");
}

#[test]
fn compact_unresolved_adversarial_review_requires_named_missing_evidence() {
    let result = serde_json::json!({
        "tier": "unresolved",
        "reason": "A dynamic registration cannot be resolved."
    });

    let error =
        parse_adversarial_method_review(&result, &established_intent(), "return value", 1, 1)
            .unwrap_err();

    assert!(error.contains("must list missing evidence"));
}

#[test]
fn adversarial_slop_still_requires_the_complete_semantic_proof() {
    let result = serde_json::json!({
        "tier": "slop",
        "reason": "The branch is redundant."
    });

    let error =
        parse_adversarial_method_review(&result, &established_intent(), "return value", 1, 1)
            .unwrap_err();

    assert!(error.contains("missing non-empty pattern"));
}

#[test]
fn evidence_match_accepts_exact_substrings() {
    assert!(evidence_matches_source(
        "def demo(value):\n    return value\n",
        "def demo(value):"
    ));
}

#[test]
fn evidence_match_accepts_whitespace_variants() {
    assert!(evidence_matches_source(
        "def extract_python_signatures(items):\n    return 1\n",
        "def  extract_python_signatures( items ) :"
    ));
}

#[test]
fn evidence_match_rejects_missing_text() {
    assert!(!evidence_matches_source(
        "def demo(value):\n    return value\n",
        "def other(value):"
    ));
}

#[test]
fn file_review_rejects_unknown_tier_instead_of_promoting_it_to_slop() {
    let result = serde_json::json!({
        "smelly": true,
        "tier": "maybe",
        "evidence": "return value",
        "reason": "unclear",
        "cohesive": true,
        "name_accurate": true
    });

    let error = validate_file_review(&result).expect_err("unknown tiers must fail closed");
    assert!(error.contains("invalid file verdict tier"));
    assert_eq!(
        super::build_file_verdict(&result, "src/demo.py").tier,
        FindingTier::Unresolved
    );
}

#[test]
fn file_review_rejects_smelly_tier_mismatch() {
    let result = serde_json::json!({
        "smelly": true,
        "tier": "clean",
        "evidence": "return value",
        "reason": "unclear",
        "cohesive": true,
        "name_accurate": true
    });

    let error = validate_file_review(&result).expect_err("inconsistent verdicts must fail");
    assert!(error.contains("smelly and tier disagree"));
}

#[test]
fn semantic_review_requires_concrete_pattern_and_exact_evidence() {
    let source = "def load(value):\n    normalized = value.strip()\n    return normalized\n";
    let result = serde_json::json!({
        "smelly": true,
        "tier": "slop",
        "pattern": "ceremonial_logic",
        "intent": "Normalize and return the value.",
        "reason": "The temporary normalization layer adds no distinct behavior.",
        "necessity_check": "The method can return the same expression directly.",
        "contract_status": "unnecessary",
        "contract_impact": "Returning the expression directly preserves the method contract.",
        "dependency_impact": "No caller depends on the temporary normalization layer.",
        "simplification": "return value.strip() directly",
        "change_scope": "local",
        "behavior_status": "preserved",
        "missing_evidence": [],
        "evidence": [{
            "start_line": 11,
            "end_line": 11,
            "quote": "normalized = value.strip()"
        }]
    });

    let review = parse_semantic_method_review(&result, source, 10, 12).unwrap();
    assert_eq!(review.tier, FindingTier::Slop);
    assert_eq!(
        review.pattern,
        crate::product_contract::SlopPattern::CeremonialLogic
    );
    assert_eq!(review.evidence.len(), 1);
}

#[test]
fn semantic_review_accepts_closed_world_residual_machinery_pattern() {
    let source = "def _stale():\n    return legacy_helper()\n";
    let result = serde_json::json!({
        "tier": "slop",
        "pattern": "residual_machinery",
        "intent": "Expose a private legacy helper.",
        "reason": "The unused helper adds misleading conceptual machinery.",
        "necessity_check": "The closed repository dossier proves the method has no consumer or boundary role.",
        "contract_status": "unnecessary",
        "contract_impact": "Deleting this private method changes no callable or protocol contract.",
        "dependency_impact": "No caller, test, registration, export, callback, re-export, compatibility path, or protocol depends on it.",
        "simplification": "Delete the entire method.",
        "change_scope": "whole_method",
        "behavior_status": "preserved",
        "missing_evidence": [],
        "evidence": [{
            "start_line": 1,
            "end_line": 2,
            "quote": source
        }]
    });

    let review = parse_semantic_method_review(&result, source, 1, 2).unwrap();

    assert_eq!(review.tier, FindingTier::Slop);
    assert_eq!(
        review.pattern,
        crate::product_contract::SlopPattern::ResidualMachinery
    );
    assert_eq!(review.change_scope, "whole_method");
}

#[test]
fn semantic_finding_rejects_placeholder_contract_and_dependency_proof() {
    let source =
        "def choose(enabled, value):\n    if enabled:\n        return value\n    return value\n";
    let result = serde_json::json!({
        "tier": "slop",
        "pattern": "duplicated_semantics",
        "intent": "Return the supplied value.",
        "reason": "Both paths return the same value.",
        "necessity_check": "The branch has no distinct behavior.",
        "contract_status": "unnecessary",
        "contract_impact": "none",
        "dependency_impact": "none",
        "simplification": "Replace the branch with one return statement.",
        "change_scope": "local",
        "behavior_status": "preserved",
        "missing_evidence": [],
        "evidence": [{
            "start_line": 2,
            "end_line": 4,
            "quote": "if enabled:\n        return value\n    return value"
        }]
    });

    let error = parse_semantic_method_review(&result, source, 1, 4)
        .expect_err("placeholder proof must never survive as a finding");
    assert!(error.contains("substantive necessity, contract, dependency"));
}

#[test]
fn whole_method_scope_rejects_a_local_body_simplification() {
    let source = "pub fn sample(value: bool) -> bool {\n    if value { value } else { value }\n}\n";
    let result = serde_json::json!({
        "tier": "slop",
        "pattern": "ceremonial_logic",
        "intent": "Return the input value.",
        "reason": "Both branches return the same value.",
        "necessity_check": "The conditional has no semantic effect.",
        "contract_status": "unnecessary",
        "contract_impact": "Replacing the body preserves the callable contract.",
        "dependency_impact": "Callers observe the same return value.",
        "simplification": "Replace the conditional with a direct return.",
        "change_scope": "whole_method",
        "behavior_status": "preserved",
        "missing_evidence": [],
        "evidence": [{
            "start_line": 2,
            "end_line": 2,
            "quote": "if value { value } else { value }"
        }]
    });

    let error = parse_semantic_method_review(&result, source, 1, 3)
        .expect_err("a body rewrite must not be classified as whole-method deletion");
    assert!(error.contains("whole_method change_scope"));
}

#[test]
fn local_scope_rejects_a_hidden_signature_change() {
    let source =
        "def choose(enabled, value):\n    if enabled:\n        return value\n    return value\n";
    let result = serde_json::json!({
        "tier": "slop",
        "pattern": "duplicated_semantics",
        "intent": "Return the supplied value.",
        "reason": "Both paths return the same value.",
        "necessity_check": "The branch has no distinct behavior.",
        "contract_status": "unnecessary",
        "contract_impact": "The returned value remains identical for every input.",
        "dependency_impact": "Callers continue receiving the same supplied value.",
        "simplification": "Replace the branch with one return and remove the enabled parameter.",
        "change_scope": "local",
        "behavior_status": "preserved",
        "missing_evidence": [],
        "evidence": [{
            "start_line": 2,
            "end_line": 4,
            "quote": "if enabled:\n        return value\n    return value"
        }]
    });

    let error = parse_semantic_method_review(&result, source, 1, 4)
        .expect_err("a local edit must not hide a signature change");
    assert!(error.contains("local change_scope"));
}

#[test]
fn semantic_review_uses_tier_as_the_sole_verdict_field() {
    let result = serde_json::json!({
        "smelly": true,
        "tier": "clean",
        "pattern": "none",
        "intent": "Return the configured value.",
        "reason": "clean",
        "necessity_check": "The implementation is direct.",
        "contract_status": "required",
        "contract_impact": "The contract requires the direct return.",
        "dependency_impact": "Callers depend on the returned value.",
        "simplification": "none",
        "change_scope": "none",
        "behavior_status": "preserved",
        "missing_evidence": [],
        "evidence": []
    });
    let review = parse_semantic_method_review(&result, "return 1\n", 1, 1)
        .expect("the redundant smelly field must not override tier");
    assert_eq!(review.tier, FindingTier::Clean);
}

#[test]
fn clean_and_unresolved_reviews_default_an_omitted_evidence_array_to_empty() {
    let clean = serde_json::json!({
        "tier": "clean",
        "pattern": "none",
        "intent": "Return the configured value.",
        "reason": "The direct implementation is coherent.",
        "necessity_check": "The implementation directly serves its contract.",
        "contract_status": "required",
        "contract_impact": "The contract requires the returned value.",
        "dependency_impact": "Known callers consume the returned value.",
        "simplification": "none",
        "change_scope": "none",
        "behavior_status": "preserved",
        "missing_evidence": []
    });
    let unresolved = serde_json::json!({
        "tier": "unresolved",
        "pattern": "none",
        "intent": "Expose a possible external boundary.",
        "reason": "The external consumer cannot be resolved.",
        "necessity_check": "The repository cannot establish the external contract.",
        "contract_status": "unknown",
        "contract_impact": "The external contract impact is unknown.",
        "dependency_impact": "External dependencies are unknown.",
        "simplification": "none",
        "change_scope": "none",
        "behavior_status": "unknown",
        "missing_evidence": ["external consumer"]
    });

    assert!(
        parse_semantic_method_review(&clean, "return value", 1, 1)
            .unwrap()
            .evidence
            .is_empty()
    );
    assert!(
        parse_semantic_method_review(&unresolved, "return value", 1, 1)
            .unwrap()
            .evidence
            .is_empty()
    );
}

#[test]
fn semantic_finding_still_requires_an_evidence_array() {
    let result = serde_json::json!({
        "tier": "slop",
        "pattern": "ceremonial_logic",
        "intent": "Return the configured value.",
        "reason": "The temporary is unnecessary.",
        "necessity_check": "The value can be returned directly.",
        "contract_status": "unnecessary",
        "contract_impact": "The returned value remains unchanged.",
        "dependency_impact": "No dependency observes the temporary.",
        "simplification": "Return the value directly.",
        "change_scope": "local",
        "behavior_status": "preserved",
        "missing_evidence": []
    });

    let error = parse_semantic_method_review(&result, "return value", 1, 1)
        .expect_err("a finding without exact evidence must remain invalid");
    assert!(error.contains("missing evidence array"));
}

#[test]
fn clean_semantic_review_accepts_known_behavior_as_preserved() {
    let result = serde_json::json!({
        "tier": "clean",
        "pattern": "none",
        "intent": "Return the configured value.",
        "reason": "The direct implementation is coherent.",
        "necessity_check": "No unnecessary machinery is present.",
        "contract_status": "required",
        "contract_impact": "The method directly fulfills its contract.",
        "dependency_impact": "Known callers consume the returned value.",
        "simplification": "none",
        "change_scope": "none",
        "behavior_status": "known",
        "missing_evidence": [],
        "evidence": []
    });

    let review = parse_semantic_method_review(&result, "return value\n", 1, 1)
        .expect("known behavior is an unambiguous Clean synonym");
    assert_eq!(review.behavior_status, "preserved");
}

#[test]
fn semantic_finding_rejects_known_as_behavior_preservation_proof() {
    let result = serde_json::json!({
        "tier": "slop",
        "pattern": "ceremonial_logic",
        "intent": "Return a value.",
        "reason": "The temporary is unnecessary.",
        "necessity_check": "The expression can be returned directly.",
        "contract_status": "unnecessary",
        "contract_impact": "The contract remains unchanged.",
        "dependency_impact": "No dependency uses the temporary.",
        "simplification": "Return the expression directly.",
        "change_scope": "local",
        "behavior_status": "known",
        "missing_evidence": [],
        "evidence": [{"start_line": 1, "end_line": 1, "quote": "return value"}]
    });

    let error = parse_semantic_method_review(&result, "return value\n", 1, 1)
        .expect_err("a finding still requires explicit preservation proof");
    assert!(error.contains("invalid behavior_status: known"));
}

#[test]
fn semantic_review_canonicalizes_unique_whitespace_variant_evidence() {
    let source = "def load(value):\n    normalized = value.strip()\n    return normalized\n";
    let result = serde_json::json!({
        "smelly": true,
        "tier": "kinda_slop",
        "pattern": "ceremonial_logic",
        "intent": "Normalize and return the value.",
        "reason": "The temporary normalization layer adds no distinct behavior.",
        "necessity_check": "The method can return the same expression directly.",
        "contract_status": "unnecessary",
        "contract_impact": "Returning the expression directly preserves the method contract.",
        "dependency_impact": "No caller depends on the temporary normalization layer.",
        "simplification": "return value.strip() directly",
        "change_scope": "local",
        "behavior_status": "preserved",
        "missing_evidence": [],
        "evidence": [{
            "start_line": 10,
            "end_line": 10,
            "quote": "normalized = value . strip ( )"
        }]
    });

    let review = parse_semantic_method_review(&result, source, 10, 12).unwrap();
    assert_eq!(review.evidence[0].start_line, 11);
    assert_eq!(review.evidence[0].end_line, 11);
}

#[test]
fn semantic_review_rejects_evidence_that_is_not_in_the_method() {
    let result = serde_json::json!({
        "smelly": true,
        "tier": "slop",
        "pattern": "contract_fog",
        "intent": "Return the value.",
        "reason": "The implementation hides a direct operation.",
        "necessity_check": "No extra machinery is required.",
        "contract_status": "unnecessary",
        "contract_impact": "The direct return preserves the method contract.",
        "dependency_impact": "No dependency requires the hidden operation.",
        "simplification": "return value directly",
        "change_scope": "local",
        "behavior_status": "preserved",
        "missing_evidence": [],
        "evidence": [{
            "start_line": 1,
            "end_line": 1,
            "quote": "not in source"
        }]
    });

    let error = parse_semantic_method_review(&result, "return value", 1, 1).unwrap_err();
    assert!(error.contains("does not belong to its declared line range"));
}

#[test]
fn semantic_review_canonicalizes_a_unique_quote_with_wrong_line_numbers() {
    let result = serde_json::json!({
        "smelly": true,
        "tier": "slop",
        "pattern": "ceremonial_logic",
        "intent": "Return the normalized value.",
        "reason": "The temporary is unnecessary.",
        "necessity_check": "The expression can be returned directly.",
        "contract_status": "unnecessary",
        "contract_impact": "Returning the expression directly preserves the method contract.",
        "dependency_impact": "No caller depends on the temporary.",
        "simplification": "return value.strip() directly",
        "change_scope": "local",
        "behavior_status": "preserved",
        "missing_evidence": [],
        "evidence": [{
            "start_line": 90,
            "end_line": 90,
            "quote": "normalized = value.strip()"
        }]
    });

    let review = parse_semantic_method_review(
        &result,
        "def load(value):\n    normalized = value.strip()\n    return normalized\n",
        10,
        12,
    )
    .unwrap();
    assert_eq!(review.evidence[0].start_line, 11);
    assert_eq!(review.evidence[0].end_line, 11);
}

#[test]
fn clean_semantic_review_discards_non_finding_evidence() {
    let result = serde_json::json!({
        "smelly": false,
        "tier": "clean",
        "pattern": "none",
        "intent": "Return the value.",
        "reason": "The method directly performs its stated job.",
        "necessity_check": "There is no unnecessary machinery.",
        "contract_status": "required",
        "contract_impact": "The current method directly fulfills its contract.",
        "dependency_impact": "Callers depend on the direct behavior.",
        "simplification": "none",
        "change_scope": "none",
        "behavior_status": "preserved",
        "missing_evidence": [],
        "evidence": [{
            "start_line": 1,
            "end_line": 1,
            "quote": "return value"
        }]
    });

    let review = parse_semantic_method_review(&result, "return value", 1, 1).unwrap();
    assert!(review.evidence.is_empty());
}

#[test]
fn clean_semantic_review_requires_proven_contract_and_complete_evidence() {
    let result = serde_json::json!({
        "smelly": false,
        "tier": "clean",
        "pattern": "none",
        "intent": "Expose a boundary.",
        "reason": "The method may be a stable seam.",
        "necessity_check": "External usage is not fully visible.",
        "contract_status": "unnecessary",
        "contract_impact": "The public contract cannot be established.",
        "dependency_impact": "External dependencies are missing.",
        "simplification": "none",
        "change_scope": "none",
        "behavior_status": "preserved",
        "missing_evidence": ["external consumers"],
        "evidence": []
    });

    let error = parse_semantic_method_review(&result, "return value", 1, 1)
        .expect_err("a clean verdict cannot contain unresolved contract evidence");
    assert!(error.contains("must prove a required contract"));
}

#[test]
fn clean_semantic_review_rejects_uncertainty_hidden_behind_required_status() {
    let result = serde_json::json!({
        "tier": "clean",
        "pattern": "none",
        "intent": "Expose a boundary.",
        "reason": "The method may be a stable seam.",
        "necessity_check": "The external usage cannot be established from repository evidence.",
        "contract_status": "required",
        "contract_impact": "The contract is unknown despite the selected status.",
        "dependency_impact": "Callers are unknown.",
        "simplification": "none",
        "change_scope": "none",
        "behavior_status": "preserved",
        "missing_evidence": [],
        "evidence": []
    });

    let error = parse_semantic_method_review(&result, "return value", 1, 1)
        .expect_err("uncertainty cannot be serialized as Clean");
    assert!(error.contains("no unresolved evidence"));
}

#[test]
fn semantic_finding_cannot_claim_missing_evidence() {
    let result = serde_json::json!({
        "smelly": true,
        "tier": "slop",
        "pattern": "ceremonial_logic",
        "intent": "Return the normalized value.",
        "reason": "The temporary adds no distinct behavior.",
        "necessity_check": "The expression can be returned directly.",
        "contract_status": "unnecessary",
        "contract_impact": "Returning the expression directly preserves the method contract.",
        "dependency_impact": "No caller depends on the temporary.",
        "simplification": "return value.strip() directly",
        "change_scope": "local",
        "behavior_status": "preserved",
        "missing_evidence": ["external callers"],
        "evidence": [{"start_line": 1, "end_line": 1, "quote": "return value"}]
    });

    let error = parse_semantic_method_review(&result, "return value", 1, 1)
        .expect_err("a finding with missing evidence must remain unresolved");
    assert!(error.contains("cannot retain unresolved missing evidence"));
}

#[test]
fn semantic_slop_requires_a_simplification_proof() {
    let result = serde_json::json!({
        "smelly": true,
        "tier": "slop",
        "pattern": "needless_indirection",
        "intent": "Expose a stable boundary.",
        "reason": "The delegate appears unnecessary.",
        "necessity_check": "The direct operation would be shorter.",
        "contract_status": "unknown",
        "contract_impact": "The public contract is unknown.",
        "dependency_impact": "External dependencies are unknown.",
        "simplification": "return the delegated value directly",
        "change_scope": "local",
        "behavior_status": "preserved",
        "missing_evidence": [],
        "evidence": [{"start_line": 1, "end_line": 1, "quote": "return value"}]
    });

    let error = parse_semantic_method_review(&result, "return value", 1, 1)
        .expect_err("unknown contract purpose must not become a finding");
    assert!(error.contains("prove an unnecessary contract"));
}

#[test]
fn semantic_slop_rejects_uncertain_dependency_proof() {
    let result = serde_json::json!({
        "tier": "slop",
        "pattern": "needless_indirection",
        "intent": "Expose a stable boundary.",
        "reason": "The delegate appears unnecessary.",
        "necessity_check": "The direct operation is equivalent.",
        "contract_status": "unnecessary",
        "contract_impact": "The signature remains unchanged.",
        "dependency_impact": "External callers are unknown.",
        "simplification": "return the delegated value directly",
        "change_scope": "local",
        "behavior_status": "preserved",
        "missing_evidence": [],
        "evidence": [{"start_line": 1, "end_line": 1, "quote": "return value"}]
    });

    let error = parse_semantic_method_review(&result, "return value", 1, 1)
        .expect_err("uncertain dependency impact cannot become Slop");
    assert!(error.contains("cannot contain uncertain contract or dependency proof"));
}

#[test]
fn unresolved_semantic_review_requires_exact_unknown_invariants() {
    let result = serde_json::json!({
        "tier": "unresolved",
        "pattern": "none",
        "intent": "Expose a stable boundary.",
        "reason": "External consumers are unavailable.",
        "necessity_check": "The contract cannot be established.",
        "contract_status": "required",
        "contract_impact": "The impact cannot be established.",
        "dependency_impact": "External callers are missing.",
        "simplification": "remove the wrapper",
        "change_scope": "local",
        "behavior_status": "preserved",
        "missing_evidence": ["external consumers"],
        "evidence": []
    });

    let error = parse_semantic_method_review(&result, "return value", 1, 1)
        .expect_err("Unresolved must not carry a conclusive contract or edit");
    assert!(error.contains("must use an unknown contract and behavior"));
}

#[test]
fn unresolved_semantic_review_is_explicit_and_not_smelly() {
    let result = serde_json::json!({
        "smelly": false,
        "tier": "unresolved",
        "pattern": "none",
        "intent": "Expose a stable boundary.",
        "reason": "The available dossier cannot distinguish a public contract from needless indirection.",
        "necessity_check": "Caller and protocol evidence is incomplete.",
        "contract_status": "unknown",
        "contract_impact": "The boundary contract cannot be established.",
        "dependency_impact": "External callers and implementations are missing.",
        "simplification": "none",
        "change_scope": "none",
        "behavior_status": "unknown",
        "missing_evidence": ["interface implementations and external callers"],
        "evidence": []
    });

    let review = parse_semantic_method_review(&result, "return value", 1, 1).unwrap();
    let verdict = build_semantic_method_verdict(&review, "src/lib.py", "boundary", 1, 1, 1);
    assert_eq!(verdict.tier, FindingTier::Unresolved);
    assert!(!verdict.smelly);
    assert!(verdict.reason.contains("Missing evidence"));
}
