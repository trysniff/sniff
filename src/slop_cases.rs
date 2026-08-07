use crate::product_contract::SlopPattern;
use crate::report_types::{MethodEvidenceRecord, MethodReviewRecord};
use crate::types::FindingTier;
use serde::{Deserialize, Serialize};

/// The strongest proof currently available before counterfactual execution.
///
/// Keeping this explicit prevents a semantic review from being presented as
/// compiler or behavioral proof merely because it contains a confident prose
/// verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofLevel {
    P0SourceReasoning,
    P1CompilerValidated,
    P2TestsValidated,
    P3SurfaceValidated,
    P4DifferentialValidated,
    P5ClosedWorldValidated,
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
    pub proof_level: ProofLevel,
    pub unresolved_assumptions: Vec<String>,
    pub provenance: Vec<String>,
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
    use super::{ProofLevel, case_evidence_matches_record, seed_method_cases};
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
}
