use super::ResponseSchema;
use crate::product_contract::{SLOP_PATTERN_PROMPT_LIST, SlopPattern};

pub(super) fn schema_description(schema: ResponseSchema) -> String {
    match schema {
        ResponseSchema::MethodReview => {
            "Required fields: smelly (bool), tier (string), evidence (string), reason (string)."
                .to_string()
        }
        ResponseSchema::MethodIntentReview => {
            "Required fields: intent (string), contract_status (string), necessity_check (string), missing_evidence (array of strings). This pass describes intent and contract only; it must not assign a slop tier."
                .to_string()
        }
        ResponseSchema::MethodIntentBatchReview => {
            "Required root field: reviews (array). Every review requires method_key (string), intent (string), contract_status (string), necessity_check (string), and missing_evidence (array of strings). Return exactly one review for every requested method key."
                .to_string()
        }
        ResponseSchema::SemanticMethodReview => {
            format!(
                "Required fields: tier (string), pattern (string), intent (string), reason (string), necessity_check (string), contract_status (string), contract_impact (string), dependency_impact (string), simplification (string), change_scope (string), behavior_status (string), missing_evidence (array of strings), evidence (array of objects with start_line (number), end_line (number), quote (string)). Allowed tiers are slop, kinda_slop, clean, unresolved. Allowed finding patterns are {SLOP_PATTERN_PROMPT_LIST}; use none for clean or unresolved. Tier is the sole verdict field. change_scope must be none for clean/unresolved and local, signature, or whole_method for slop/kinda_slop. Slop and kinda_slop must prove contract_status=unnecessary, behavior_status=preserved, unchanged contract impact, absent dependency impact, and provide a concrete simplification plus evidence. Unresolved must list missing_evidence."
            )
        }
        ResponseSchema::SemanticMethodBatchReview => {
            format!(
                "Required root field: reviews (array). Every review requires method_key (string), tier, pattern, intent, reason, necessity_check, contract_status, contract_impact, dependency_impact, simplification, change_scope, behavior_status, missing_evidence, and semantic evidence. Allowed finding patterns are {SLOP_PATTERN_PROMPT_LIST}; use none for clean or unresolved. Return exactly one independent review for every requested method key."
            )
        }
        ResponseSchema::ScopedTierReview => {
            "Required fields: tier (string) and reason (string). Allowed tiers are slop, kinda_slop, clean, or unresolved."
                .to_string()
        }
        ResponseSchema::CaseSynthesis => {
            "Required root field: cases (array). Each case must contain tier, pattern, mechanism, intent, affected_units (array of strings), evidence (array), contract_boundary, counterfactual, and unresolved_assumptions (array of strings)."
                .to_string()
        }
        ResponseSchema::CaseAdjudication => {
            "Required root field: decisions (array). Each decision must contain case_id (string), decision (keep, discard, unresolved, or merge), and reason (string). A merge decision must also contain merge_into_case_id naming a different existing case; use merge only when the mechanism, contract boundary, and counterfactual are the same."
                .to_string()
        }
        ResponseSchema::CaseProof => {
            "Required root field: proofs (array). Return exactly one proof for every case. Each proof must contain case_id (string), decision (validated or unresolved), reason (string), and edits (array). Validated proofs require at least one edit with file_path (string), start_line (positive integer), end_line (positive integer), and replacement (string); unresolved proofs must contain no edits."
                .to_string()
        }
        ResponseSchema::FileReview => {
            "Required fields: smelly (bool), tier (string), evidence (string), cohesive (bool), name_accurate (bool), reason (string). Allowed tiers are slop, kinda_slop, clean, unresolved; unresolved means the file-level evidence is insufficient and must use smelly=false."
                .to_string()
        }
        ResponseSchema::RoleClassification => {
            "Required fields: role (string), reason (string).".to_string()
        }
    }
}

pub(super) fn validate_schema(
    value: &serde_json::Value,
    schema: ResponseSchema,
) -> Result<(), String> {
    let Some(obj) = value.as_object() else {
        return Err("response was not a JSON object".to_string());
    };

    let mut missing = Vec::new();
    let mut wrong_type = Vec::new();

    fn check_bool(
        obj: &serde_json::Map<String, serde_json::Value>,
        name: &str,
        missing: &mut Vec<String>,
        wrong_type: &mut Vec<String>,
    ) {
        match obj.get(name) {
            Some(v) if v.is_boolean() => {}
            Some(_) => wrong_type.push(name.to_string()),
            None => missing.push(name.to_string()),
        }
    }

    fn check_string(
        obj: &serde_json::Map<String, serde_json::Value>,
        name: &str,
        missing: &mut Vec<String>,
        wrong_type: &mut Vec<String>,
    ) {
        match obj.get(name) {
            Some(v) if v.is_string() => {}
            Some(_) => wrong_type.push(name.to_string()),
            None => missing.push(name.to_string()),
        }
    }

    fn check_number(
        obj: &serde_json::Map<String, serde_json::Value>,
        name: &str,
        missing: &mut Vec<String>,
        wrong_type: &mut Vec<String>,
    ) {
        match obj.get(name) {
            Some(v) if v.is_u64() || v.is_i64() => {}
            Some(_) => wrong_type.push(name.to_string()),
            None => missing.push(name.to_string()),
        }
    }

    fn check_semantic_evidence(
        obj: &serde_json::Map<String, serde_json::Value>,
        missing: &mut Vec<String>,
        wrong_type: &mut Vec<String>,
    ) {
        let Some(value) = obj.get("evidence") else {
            missing.push("evidence".to_string());
            return;
        };
        let Some(entries) = value.as_array() else {
            wrong_type.push("evidence".to_string());
            return;
        };
        for (index, entry) in entries.iter().enumerate() {
            let Some(entry) = entry.as_object() else {
                wrong_type.push(format!("evidence[{index}]"));
                continue;
            };
            check_number(entry, "start_line", missing, wrong_type);
            check_number(entry, "end_line", missing, wrong_type);
            check_string(entry, "quote", missing, wrong_type);
        }
    }

    fn check_string_array(
        obj: &serde_json::Map<String, serde_json::Value>,
        name: &str,
        missing: &mut Vec<String>,
        wrong_type: &mut Vec<String>,
    ) {
        let Some(value) = obj.get(name) else {
            missing.push(name.to_string());
            return;
        };
        let Some(entries) = value.as_array() else {
            wrong_type.push(name.to_string());
            return;
        };
        for (index, entry) in entries.iter().enumerate() {
            if !entry.is_string() {
                wrong_type.push(format!("{name}[{index}]"));
            }
        }
    }

    fn check_intent_review(
        obj: &serde_json::Map<String, serde_json::Value>,
        missing: &mut Vec<String>,
        wrong_type: &mut Vec<String>,
    ) {
        check_string(obj, "intent", missing, wrong_type);
        check_string(obj, "contract_status", missing, wrong_type);
        check_string(obj, "necessity_check", missing, wrong_type);
        check_string_array(obj, "missing_evidence", missing, wrong_type);
    }

    fn check_semantic_review(
        obj: &serde_json::Map<String, serde_json::Value>,
        missing: &mut Vec<String>,
        wrong_type: &mut Vec<String>,
    ) {
        check_string(obj, "tier", missing, wrong_type);
        check_string(obj, "pattern", missing, wrong_type);
        if let Some(pattern) = obj.get("pattern").and_then(serde_json::Value::as_str)
            && SlopPattern::parse(pattern).is_none()
        {
            wrong_type.push("pattern (unknown value)".to_string());
        }
        check_string(obj, "intent", missing, wrong_type);
        check_string(obj, "reason", missing, wrong_type);
        check_string(obj, "necessity_check", missing, wrong_type);
        check_string(obj, "contract_status", missing, wrong_type);
        check_string(obj, "contract_impact", missing, wrong_type);
        check_string(obj, "dependency_impact", missing, wrong_type);
        check_string(obj, "simplification", missing, wrong_type);
        check_string(obj, "change_scope", missing, wrong_type);
        check_string(obj, "behavior_status", missing, wrong_type);
        check_string_array(obj, "missing_evidence", missing, wrong_type);
        check_semantic_evidence(obj, missing, wrong_type);
    }

    fn check_review_array_envelope(
        obj: &serde_json::Map<String, serde_json::Value>,
        missing: &mut Vec<String>,
        wrong_type: &mut Vec<String>,
    ) {
        match obj.get("reviews") {
            Some(value) if value.is_array() => {}
            Some(_) => wrong_type.push("reviews".to_string()),
            None => missing.push("reviews".to_string()),
        }
    }

    fn check_case_array_envelope(
        obj: &serde_json::Map<String, serde_json::Value>,
        missing: &mut Vec<String>,
        wrong_type: &mut Vec<String>,
    ) {
        match obj.get("cases") {
            Some(value) if value.is_array() => {}
            Some(_) => wrong_type.push("cases".to_string()),
            None => missing.push("cases".to_string()),
        }
    }

    fn check_decision_array_envelope(
        obj: &serde_json::Map<String, serde_json::Value>,
        missing: &mut Vec<String>,
        wrong_type: &mut Vec<String>,
    ) {
        match obj.get("decisions") {
            Some(value) if value.is_array() => {}
            Some(_) => wrong_type.push("decisions".to_string()),
            None => missing.push("decisions".to_string()),
        }
    }

    match schema {
        ResponseSchema::MethodReview => {
            check_bool(obj, "smelly", &mut missing, &mut wrong_type);
            check_string(obj, "tier", &mut missing, &mut wrong_type);
            check_string(obj, "evidence", &mut missing, &mut wrong_type);
            check_string(obj, "reason", &mut missing, &mut wrong_type);
        }
        ResponseSchema::MethodIntentReview => {
            check_intent_review(obj, &mut missing, &mut wrong_type);
        }
        ResponseSchema::MethodIntentBatchReview => {
            // Per-method fields and keys are validated by the batch analyzer,
            // which can preserve valid siblings and repair only invalid keys.
            check_review_array_envelope(obj, &mut missing, &mut wrong_type);
        }
        ResponseSchema::SemanticMethodReview => {
            check_semantic_review(obj, &mut missing, &mut wrong_type);
        }
        ResponseSchema::SemanticMethodBatchReview => {
            // Detailed fields, keys, and exact evidence are validated per
            // method by the targeted batch repair layer.
            check_review_array_envelope(obj, &mut missing, &mut wrong_type);
        }
        ResponseSchema::ScopedTierReview => {
            check_string(obj, "tier", &mut missing, &mut wrong_type);
            check_string(obj, "reason", &mut missing, &mut wrong_type);
        }
        ResponseSchema::CaseSynthesis => {
            check_case_array_envelope(obj, &mut missing, &mut wrong_type);
        }
        ResponseSchema::CaseAdjudication => {
            check_decision_array_envelope(obj, &mut missing, &mut wrong_type);
        }
        ResponseSchema::CaseProof => match obj.get("proofs") {
            Some(value) if value.is_array() => {}
            Some(_) => wrong_type.push("proofs".to_string()),
            None => missing.push("proofs".to_string()),
        },
        ResponseSchema::FileReview => {
            check_bool(obj, "smelly", &mut missing, &mut wrong_type);
            check_string(obj, "tier", &mut missing, &mut wrong_type);
            check_string(obj, "evidence", &mut missing, &mut wrong_type);
            check_string(obj, "reason", &mut missing, &mut wrong_type);
            check_bool(obj, "cohesive", &mut missing, &mut wrong_type);
            check_bool(obj, "name_accurate", &mut missing, &mut wrong_type);
        }
        ResponseSchema::RoleClassification => {
            check_string(obj, "role", &mut missing, &mut wrong_type);
            check_string(obj, "reason", &mut missing, &mut wrong_type);
        }
    }

    if missing.is_empty() && wrong_type.is_empty() {
        Ok(())
    } else {
        let mut parts = Vec::new();
        if !missing.is_empty() {
            parts.push(format!("missing fields: {}", missing.join(", ")));
        }
        if !wrong_type.is_empty() {
            parts.push(format!("wrong field types: {}", wrong_type.join(", ")));
        }
        Err(parts.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::{ResponseSchema, schema_description, validate_schema};

    #[test]
    fn clean_semantic_review_may_omit_its_explanation() {
        let value = serde_json::json!({
            "smelly": false,
            "tier": "clean",
            "pattern": "none",
            "intent": "Return a configured value.",
            "reason": "The method is coherent.",
            "necessity_check": "The implementation is direct.",
            "contract_status": "required",
            "contract_impact": "The method contract requires the direct operation.",
            "dependency_impact": "Callers depend on the returned configured value.",
            "simplification": "none",
            "change_scope": "none",
            "behavior_status": "preserved",
            "missing_evidence": [],
            "evidence": []
        });

        assert!(validate_schema(&value, ResponseSchema::SemanticMethodReview).is_ok());
    }

    #[test]
    fn semantic_batch_requires_typed_reviews() {
        let review = serde_json::json!({
            "method_key": "m0",
            "tier": "clean",
            "pattern": "none",
            "intent": "Return a configured value.",
            "reason": "The method is coherent.",
            "necessity_check": "The implementation is direct.",
            "contract_status": "required",
            "contract_impact": "The method contract requires the operation.",
            "dependency_impact": "Callers consume the value.",
            "simplification": "none",
            "change_scope": "none",
            "behavior_status": "preserved",
            "missing_evidence": [],
            "evidence": []
        });
        let value = serde_json::json!({"reviews": [review]});

        assert!(validate_schema(&value, ResponseSchema::SemanticMethodBatchReview).is_ok());
    }

    #[test]
    fn intent_batch_rejects_non_array_reviews() {
        let value = serde_json::json!({"reviews": {}});
        let error = validate_schema(&value, ResponseSchema::MethodIntentBatchReview).unwrap_err();
        assert!(error.contains("wrong field types: reviews"));
    }

    #[test]
    fn semantic_batch_defers_method_fields_to_the_semantic_validator() {
        let value = serde_json::json!({
            "reviews": [{
                "method_key": "m0",
                "evidence": [{"start_line": 1, "end_line": 1}]
            }]
        });

        assert!(validate_schema(&value, ResponseSchema::SemanticMethodBatchReview).is_ok());
    }

    #[test]
    fn semantic_schema_rejects_untyped_pattern_values() {
        let value = serde_json::json!({
            "tier": "slop",
            "pattern": "vague_vibes",
            "intent": "Return a configured value.",
            "reason": "The implementation adds unsupported ceremony.",
            "necessity_check": "The ceremony has no contract purpose.",
            "contract_status": "unnecessary",
            "contract_impact": "The contract remains unchanged.",
            "dependency_impact": "No dependency uses the ceremony.",
            "simplification": "Remove the ceremony.",
            "change_scope": "local",
            "behavior_status": "preserved",
            "missing_evidence": [],
            "evidence": [{"start_line": 1, "end_line": 1, "quote": "noop();"}]
        });

        let error = validate_schema(&value, ResponseSchema::SemanticMethodReview).unwrap_err();
        assert!(error.contains("pattern (unknown value)"));
    }

    #[test]
    fn semantic_schema_description_uses_the_canonical_ontology() {
        let description = schema_description(ResponseSchema::SemanticMethodReview);
        for pattern in crate::product_contract::SlopPattern::FINDING_PATTERNS {
            assert!(description.contains(pattern.as_str()));
        }
        assert!(!description.contains("intent_hidden"));
        assert!(!description.contains("dead_code"));
    }

    #[test]
    fn synthesis_schema_requires_cases_instead_of_reviews() {
        let valid = serde_json::json!({"cases": []});
        assert!(validate_schema(&valid, ResponseSchema::CaseSynthesis).is_ok());

        let invalid = serde_json::json!({"reviews": []});
        let error = validate_schema(&invalid, ResponseSchema::CaseSynthesis).unwrap_err();
        assert!(error.contains("missing fields: cases"));
    }

    #[test]
    fn proof_schema_requires_proofs_instead_of_cases() {
        let valid = serde_json::json!({"proofs": []});
        assert!(validate_schema(&valid, ResponseSchema::CaseProof).is_ok());

        let invalid = serde_json::json!({"cases": []});
        let error = validate_schema(&invalid, ResponseSchema::CaseProof).unwrap_err();
        assert!(error.contains("missing fields: proofs"));
    }
}
