use crate::product_contract::SlopPattern;
use crate::report_types::{MethodEvidenceRecord, MethodReviewRecord};
use crate::types::FindingTier;
use serde::{Deserialize, Serialize};

/// The strongest proof currently available before counterfactual execution.
///
/// Keeping this explicit prevents a semantic review from being presented as
/// compiler or behavioral proof merely because it contains a confident prose
/// verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProofLevel {
    P0SourceReasoning,
    P1CompilerValidated,
    P2TestsValidated,
    P3SurfaceValidated,
    P4DifferentialValidated,
    P5ClosedWorldValidated,
}

impl ProofLevel {
    pub fn label(self) -> &'static str {
        match self {
            Self::P0SourceReasoning => "P0 source reasoning",
            Self::P1CompilerValidated => "P1 compiler validated",
            Self::P2TestsValidated => "P2 tests validated",
            Self::P3SurfaceValidated => "P3 surface validated",
            Self::P4DifferentialValidated => "P4 differential validated",
            Self::P5ClosedWorldValidated => "P5 closed-world validated",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseEvidence {
    pub unit_id: String,
    pub file_path: String,
    pub method_name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub quote: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterfactualEdit {
    pub file_path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub replacement: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CounterfactualDecision {
    Validated,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseProof {
    pub case_id: String,
    pub decision: CounterfactualDecision,
    pub reason: String,
    pub edits: Vec<CounterfactualEdit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlopCase {
    pub case_id: String,
    pub tier: FindingTier,
    pub pattern: SlopPattern,
    pub mechanism: String,
    pub intent: String,
    pub evidence: Vec<CaseEvidence>,
    pub affected_units: Vec<String>,
    pub contract_boundary: String,
    pub counterfactual: String,
    #[serde(default)]
    pub counterfactual_edits: Vec<CounterfactualEdit>,
    pub proof_level: ProofLevel,
    pub unresolved_assumptions: Vec<String>,
    pub provenance: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaseDecision {
    Keep,
    Discard,
    Unresolved,
    Merge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseAdjudication {
    pub case_id: String,
    pub decision: CaseDecision,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_into_case_id: Option<String>,
}

/// Merge only byte-for-byte equivalent cases produced by overlapping
/// synthesis units. Similar-looking cases are intentionally left separate;
/// semantic merging belongs to an explicit model judgment, not a heuristic.
pub fn deduplicate_cases(cases: Vec<SlopCase>) -> Result<Vec<SlopCase>, String> {
    let mut positions = std::collections::HashMap::<String, usize>::new();
    let mut unique = Vec::with_capacity(cases.len());
    for case in cases {
        let Some(&position) = positions.get(&case.case_id) else {
            positions.insert(case.case_id.clone(), unique.len());
            unique.push(case);
            continue;
        };
        let existing = &mut unique[position];
        if !same_case_content(existing, &case) {
            return Err(format!(
                "case {} was produced more than once with conflicting evidence or reasoning",
                case.case_id
            ));
        }
        existing.provenance.extend(case.provenance);
        existing.provenance.sort();
        existing.provenance.dedup();
    }
    Ok(unique)
}

fn same_case_content(left: &SlopCase, right: &SlopCase) -> bool {
    left.case_id == right.case_id
        && left.tier == right.tier
        && left.pattern == right.pattern
        && left.mechanism == right.mechanism
        && left.intent == right.intent
        && left.evidence == right.evidence
        && left.affected_units == right.affected_units
        && left.contract_boundary == right.contract_boundary
        && left.counterfactual == right.counterfactual
        && left.counterfactual_edits == right.counterfactual_edits
        && left.proof_level == right.proof_level
        && left.unresolved_assumptions == right.unresolved_assumptions
}

/// Parse the verifier response as a complete, fail-closed decision ledger.
pub fn parse_case_adjudications(
    value: &serde_json::Value,
    cases: &[SlopCase],
) -> Result<Vec<CaseAdjudication>, String> {
    let decisions = value
        .get("decisions")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "case adjudication is missing decisions array".to_string())?;
    let known = cases
        .iter()
        .map(|case| case.case_id.as_str())
        .collect::<std::collections::HashSet<_>>();
    let mut parsed = Vec::with_capacity(decisions.len());
    let mut seen = std::collections::HashSet::new();
    for (index, value) in decisions.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| format!("case adjudication {index} is not an object"))?;
        let case_id = object
            .get("case_id")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("case adjudication {index} is missing case_id"))?;
        if !known.contains(case_id) {
            return Err(format!(
                "case adjudication {index} references unknown case {case_id}"
            ));
        }
        if !seen.insert(case_id) {
            return Err(format!("case adjudication repeats case {case_id}"));
        }
        let decision = match object
            .get("decision")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
        {
            Some("keep") => CaseDecision::Keep,
            Some("discard") => CaseDecision::Discard,
            Some("unresolved") => CaseDecision::Unresolved,
            Some("merge") => CaseDecision::Merge,
            Some(other) => {
                return Err(format!(
                    "case adjudication {index} has invalid decision {other}"
                ));
            }
            None => return Err(format!("case adjudication {index} is missing decision")),
        };
        let reason = object
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .ok_or_else(|| format!("case adjudication {index} is missing reason"))?;
        let merge_into_case_id = object
            .get("merge_into_case_id")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        match decision {
            CaseDecision::Merge => {
                let Some(target) = merge_into_case_id.as_ref() else {
                    return Err(format!(
                        "case adjudication {index} marked merge without merge_into_case_id"
                    ));
                };
                if target == case_id {
                    return Err(format!(
                        "case adjudication {index} cannot merge case {case_id} into itself"
                    ));
                }
                if !known.contains(target.as_str()) {
                    return Err(format!(
                        "case adjudication {index} merge target {target} is unknown"
                    ));
                }
            }
            _ if merge_into_case_id.is_some() => {
                return Err(format!(
                    "case adjudication {index} supplies merge_into_case_id for a non-merge decision"
                ));
            }
            _ => {}
        }
        parsed.push(CaseAdjudication {
            case_id: case_id.to_string(),
            decision,
            reason,
            merge_into_case_id,
        });
    }
    if seen.len() != known.len() {
        let missing = known
            .iter()
            .filter(|case_id| !seen.contains(**case_id))
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!("case adjudication omitted cases: {missing}"));
    }
    Ok(parsed)
}

/// Parse the complete counterfactual ledger. A proof response is not allowed
/// to silently omit a case or invent a case identifier; later validation owns
/// the source-range and compiler checks.
pub fn parse_case_proofs(
    value: &serde_json::Value,
    cases: &[SlopCase],
) -> Result<Vec<CaseProof>, String> {
    let proofs = value
        .get("proofs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "case proof is missing proofs array".to_string())?;
    let known = cases
        .iter()
        .map(|case| case.case_id.as_str())
        .collect::<std::collections::HashSet<_>>();
    let mut parsed = Vec::with_capacity(proofs.len());
    let mut seen = std::collections::HashSet::new();
    for (index, value) in proofs.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| format!("case proof {index} is not an object"))?;
        let case_id = required_string(object, "case_id", index)?;
        if !known.contains(case_id.as_str()) {
            return Err(format!(
                "case proof {index} references unknown case {case_id}"
            ));
        }
        if !seen.insert(case_id.clone()) {
            return Err(format!("case proof repeats case {case_id}"));
        }
        let decision = match required_string(object, "decision", index)?.as_str() {
            "validated" => CounterfactualDecision::Validated,
            "unresolved" => CounterfactualDecision::Unresolved,
            other => {
                return Err(format!("case proof {index} has invalid decision {other}"));
            }
        };
        let reason = required_string(object, "reason", index)?;
        let edits = parse_counterfactual_edits(object, index)?;
        if matches!(decision, CounterfactualDecision::Validated) && edits.is_empty() {
            return Err(format!(
                "case proof {index} marked validated without exact edits"
            ));
        }
        if matches!(decision, CounterfactualDecision::Unresolved) && !edits.is_empty() {
            return Err(format!(
                "case proof {index} is unresolved but contains edits"
            ));
        }
        parsed.push(CaseProof {
            case_id,
            decision,
            reason,
            edits,
        });
    }
    if seen.len() != known.len() {
        let missing = known
            .iter()
            .filter(|case_id| !seen.contains(**case_id))
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!("case proof omitted cases: {missing}"));
    }
    Ok(parsed)
}

fn required_string(
    object: &serde_json::Map<String, serde_json::Value>,
    name: &str,
    index: usize,
) -> Result<String, String> {
    object
        .get(name)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("case proof {index} is missing non-empty {name}"))
}

fn parse_counterfactual_edits(
    object: &serde_json::Map<String, serde_json::Value>,
    index: usize,
) -> Result<Vec<CounterfactualEdit>, String> {
    let edits = object
        .get("edits")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("case proof {index} is missing edits array"))?;
    edits
        .iter()
        .enumerate()
        .map(|(edit_index, value)| {
            let edit = value.as_object().ok_or_else(|| {
                format!("case proof {index} edits[{edit_index}] is not an object")
            })?;
            let file_path = required_string(edit, "file_path", index)?;
            let start_line = edit
                .get("start_line")
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .filter(|value| *value > 0)
                .ok_or_else(|| {
                    format!("case proof {index} edits[{edit_index}] has invalid start_line")
                })?;
            let end_line = edit
                .get("end_line")
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .filter(|value| *value >= start_line)
                .ok_or_else(|| {
                    format!("case proof {index} edits[{edit_index}] has invalid end_line")
                })?;
            let replacement = edit
                .get("replacement")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| {
                    format!("case proof {index} edits[{edit_index}] is missing replacement")
                })?;
            if replacement.contains('\0') {
                return Err(format!(
                    "case proof {index} edits[{edit_index}] replacement contains NUL"
                ));
            }
            Ok(CounterfactualEdit {
                file_path,
                start_line,
                end_line,
                replacement,
            })
        })
        .collect()
}

/// Seed repository cases from the exhaustive method census.
///
/// This is deliberately conservative: it does not merge similarly worded
/// findings across methods. Cross-method merging requires a later synthesis
/// judgment with relationship evidence, otherwise unrelated methods can be
/// incorrectly turned into one architectural finding.
pub fn seed_method_cases(records: &[MethodReviewRecord]) -> Vec<SlopCase> {
    records
        .iter()
        .filter(|record| {
            matches!(
                record.verdict.tier,
                FindingTier::Slop | FindingTier::KindaSlop
            )
        })
        .map(case_from_method_record)
        .collect()
}

fn case_from_method_record(record: &MethodReviewRecord) -> SlopCase {
    SlopCase {
        case_id: record.unit_id.clone(),
        tier: record.verdict.tier,
        pattern: SlopPattern::parse(&record.pattern).unwrap_or(SlopPattern::Other),
        mechanism: record.verdict.reason.clone(),
        intent: record.intent.clone(),
        evidence: record
            .evidence
            .iter()
            .map(|evidence| CaseEvidence {
                unit_id: record.unit_id.clone(),
                file_path: record.file_path.clone(),
                method_name: record.method_name.clone(),
                start_line: evidence.start_line,
                end_line: evidence.end_line,
                quote: evidence.quote.clone(),
            })
            .collect(),
        affected_units: vec![record.unit_id.clone()],
        contract_boundary: record.contract_impact.clone(),
        counterfactual: record.simplification.clone(),
        counterfactual_edits: Vec::new(),
        proof_level: ProofLevel::P0SourceReasoning,
        unresolved_assumptions: record.missing_evidence.clone(),
        provenance: vec![format!(
            "method:{}:{}:{}-{}",
            record.file_path, record.method_name, record.start_line, record.end_line
        )],
    }
}

pub fn case_evidence_matches_record(case: &SlopCase, record: &MethodReviewRecord) -> bool {
    case.affected_units.len() == 1
        && case.affected_units[0] == record.unit_id
        && case.evidence.iter().all(|evidence| {
            evidence.unit_id == record.unit_id
                && evidence.file_path == record.file_path
                && evidence.method_name == record.method_name
                && record.evidence.iter().any(|source_evidence| {
                    source_evidence
                        == &MethodEvidenceRecord {
                            start_line: evidence.start_line,
                            end_line: evidence.end_line,
                            quote: evidence.quote.clone(),
                        }
                })
        })
}

#[cfg(test)]
mod tests {
    use super::{
        CaseDecision, CounterfactualDecision, ProofLevel, case_evidence_matches_record,
        deduplicate_cases, parse_case_adjudications, parse_case_proofs, seed_method_cases,
    };
    use crate::product_contract::SlopPattern;
    use crate::report_types::{LLMVerdict, MethodEvidenceRecord, MethodReviewRecord};
    use crate::types::FindingTier;

    fn record(tier: FindingTier, pattern: &str) -> MethodReviewRecord {
        MethodReviewRecord {
            unit_id: "unit-1".to_string(),
            source_hash: "hash".to_string(),
            file_path: "src/demo.py".to_string(),
            method_name: "demo".to_string(),
            start_line: 4,
            end_line: 8,
            loc: 5,
            verdict: LLMVerdict {
                verdict_type: "method".to_string(),
                file_path: "src/demo.py".to_string(),
                method_name: Some("demo".to_string()),
                check_type: "method".to_string(),
                smelly: tier != FindingTier::Clean,
                tier,
                cohesive: None,
                name_accurate: None,
                evidence: "return value".to_string(),
                reason: "The temporary branch adds no behavior.".to_string(),
                loc: 5,
                start_line: 4,
                end_line: 8,
            },
            pattern: pattern.to_string(),
            intent: "Return the value.".to_string(),
            necessity_check: "The branch has no distinct contract.".to_string(),
            contract_status: "unnecessary".to_string(),
            contract_impact: "The return contract is unchanged.".to_string(),
            dependency_impact: "No dependency uses the branch.".to_string(),
            simplification: "Return value directly.".to_string(),
            change_scope: "local".to_string(),
            behavior_status: "preserved".to_string(),
            missing_evidence: Vec::new(),
            evidence: vec![MethodEvidenceRecord {
                start_line: 5,
                end_line: 5,
                quote: "return value".to_string(),
            }],
        }
    }

    #[test]
    fn proof_parser_requires_a_complete_exact_edit_ledger() {
        let cases = seed_method_cases(&[record(
            FindingTier::Slop,
            SlopPattern::CeremonialLogic.as_str(),
        )]);
        let value = serde_json::json!({
            "proofs": [{
                "case_id": cases[0].case_id,
                "decision": "validated",
                "reason": "The replacement is concrete and preserves the stated contract.",
                "edits": [{
                    "file_path": "src/demo.py",
                    "start_line": 4,
                    "end_line": 8,
                    "replacement": "return value"
                }]
            }]
        });
        let parsed = parse_case_proofs(&value, &cases).unwrap();
        assert_eq!(parsed[0].decision, CounterfactualDecision::Validated);
        assert_eq!(parsed[0].edits[0].replacement, "return value");
    }

    #[test]
    fn proof_parser_rejects_vague_validated_cases() {
        let cases = seed_method_cases(&[record(
            FindingTier::Slop,
            SlopPattern::CeremonialLogic.as_str(),
        )]);
        let value = serde_json::json!({
            "proofs": [{
                "case_id": cases[0].case_id,
                "decision": "validated",
                "reason": "Simplify it.",
                "edits": []
            }]
        });
        let error = parse_case_proofs(&value, &cases).unwrap_err();
        assert!(error.contains("without exact edits"));
    }

    #[test]
    fn only_proven_method_findings_seed_cases() {
        let records = vec![
            record(FindingTier::Slop, "ceremonial_logic"),
            record(FindingTier::Clean, "none"),
            record(FindingTier::Unresolved, "none"),
        ];

        let cases = seed_method_cases(&records);

        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0].pattern, SlopPattern::CeremonialLogic);
        assert_eq!(cases[0].proof_level, ProofLevel::P0SourceReasoning);
        assert_eq!(cases[0].counterfactual, "Return value directly.");
        assert!(case_evidence_matches_record(&cases[0], &records[0]));
    }

    #[test]
    fn unknown_pattern_is_preserved_as_other_not_dropped() {
        let cases = seed_method_cases(&[record(FindingTier::KindaSlop, "future_pattern")]);

        assert_eq!(cases[0].pattern, SlopPattern::Other);
        assert_eq!(cases[0].affected_units, vec!["unit-1"]);
    }

    #[test]
    fn duplicate_case_ids_merge_only_when_the_payload_agrees() {
        let original =
            seed_method_cases(&[record(FindingTier::Slop, "ceremonial_logic")])[0].clone();
        let mut duplicate = original.clone();
        duplicate.provenance = vec!["overlapping-synthesis-unit".to_string()];

        let merged = deduplicate_cases(vec![original.clone(), duplicate]).unwrap();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].provenance.len(), 2);

        let mut conflicting = original;
        conflicting.mechanism = "A different mechanism".to_string();
        let error = deduplicate_cases(vec![merged[0].clone(), conflicting]).unwrap_err();
        assert!(error.contains("conflicting evidence or reasoning"));
    }

    #[test]
    fn case_adjudication_requires_one_decision_for_every_case() {
        let cases = seed_method_cases(&[record(FindingTier::Slop, "ceremonial_logic")]);
        let value = serde_json::json!({
            "decisions": [{
                "case_id": "unit-1",
                "decision": "keep",
                "reason": "The challenge found no contract or behavior dependency."
            }]
        });

        let parsed = parse_case_adjudications(&value, &cases).unwrap();

        assert_eq!(parsed[0].decision, CaseDecision::Keep);
    }

    #[test]
    fn case_adjudication_rejects_unknown_or_missing_cases() {
        let cases = seed_method_cases(&[record(FindingTier::Slop, "ceremonial_logic")]);
        let value = serde_json::json!({
            "decisions": [{
                "case_id": "unit-1",
                "decision": "discard",
                "reason": "The apparent machinery is a public contract."
            }, {
                "case_id": "invented",
                "decision": "keep",
                "reason": "invented"
            }]
        });

        let error = parse_case_adjudications(&value, &cases).unwrap_err();

        assert!(error.contains("unknown case invented"));
    }

    #[test]
    fn case_adjudication_accepts_only_a_known_merge_target() {
        let original =
            seed_method_cases(&[record(FindingTier::Slop, "ceremonial_logic")])[0].clone();
        let mut second = original.clone();
        second.case_id = "unit-2".to_string();
        let cases = vec![original, second];
        let value = serde_json::json!({
            "decisions": [{
                "case_id": "unit-1",
                "decision": "keep",
                "reason": "Canonical case."
            }, {
                "case_id": "unit-2",
                "decision": "merge",
                "merge_into_case_id": "unit-1",
                "reason": "Same mechanism and counterfactual."
            }]
        });

        let parsed = parse_case_adjudications(&value, &cases).unwrap();

        assert_eq!(parsed[1].decision, CaseDecision::Merge);
        assert_eq!(parsed[1].merge_into_case_id.as_deref(), Some("unit-1"));
    }
}
