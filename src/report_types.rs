use serde::{Deserialize, Serialize};

use crate::slop_cases::SlopCase;
use crate::types::{FindingTier, MethodRecord};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticFlag {
    #[serde(rename = "type")]
    pub flag_type: String,
    pub file_path: String,
    pub method_name: Option<String>,
    pub reasons: Vec<String>,
    pub tier: FindingTier,
    pub gate: String,
    pub loc: usize,
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileVerdict {
    pub file_path: String,
    pub role: String,
    pub verdict: FindingTier,
    pub top_reasons: Vec<String>,
    pub flagged_methods: Vec<String>,
    pub recommended_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LLMVerdict {
    #[serde(rename = "type")]
    pub verdict_type: String,
    pub file_path: String,
    pub method_name: Option<String>,
    pub check_type: String,
    pub smelly: bool,
    pub tier: FindingTier,
    pub cohesive: Option<bool>,
    pub name_accurate: Option<bool>,
    pub evidence: String,
    pub reason: String,
    pub loc: usize,
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MethodEvidenceRecord {
    pub start_line: usize,
    pub end_line: usize,
    pub quote: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MethodSemanticFields {
    pub pattern: String,
    pub intent: String,
    pub necessity_check: String,
    pub contract_status: String,
    pub contract_impact: String,
    pub dependency_impact: String,
    pub simplification: String,
    pub change_scope: String,
    pub behavior_status: String,
    pub missing_evidence: Vec<String>,
    pub evidence: Vec<MethodEvidenceRecord>,
}

/// The durable, identity-bearing result of reviewing one eligible method.
///
/// `LLMVerdict` is the presentation-facing verdict. This record keeps the
/// source identity alongside it so coverage and resume logic cannot confuse
/// two same-named methods or count an unrelated verdict as completed work.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MethodReviewRecord {
    pub unit_id: String,
    pub source_hash: String,
    pub file_path: String,
    pub method_name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub loc: usize,
    pub verdict: LLMVerdict,
    pub pattern: String,
    pub intent: String,
    pub necessity_check: String,
    pub contract_status: String,
    pub contract_impact: String,
    pub dependency_impact: String,
    pub simplification: String,
    pub change_scope: String,
    pub behavior_status: String,
    pub missing_evidence: Vec<String>,
    pub evidence: Vec<MethodEvidenceRecord>,
}

impl MethodReviewRecord {
    pub fn from_method(
        unit_id: impl Into<String>,
        source_hash: impl Into<String>,
        method: &MethodRecord,
        verdict: LLMVerdict,
    ) -> Self {
        Self {
            unit_id: unit_id.into(),
            source_hash: source_hash.into(),
            file_path: method.file_path.clone(),
            method_name: method.name.clone(),
            start_line: method.start_line,
            end_line: method.end_line,
            loc: method.loc,
            verdict,
            pattern: "none".to_string(),
            intent: String::new(),
            necessity_check: String::new(),
            contract_status: String::new(),
            contract_impact: String::new(),
            dependency_impact: String::new(),
            simplification: String::new(),
            change_scope: String::new(),
            behavior_status: String::new(),
            missing_evidence: Vec::new(),
            evidence: Vec::new(),
        }
    }

    pub fn with_semantic_fields(mut self, fields: MethodSemanticFields) -> Self {
        self.pattern = fields.pattern;
        self.intent = fields.intent;
        self.necessity_check = fields.necessity_check;
        self.contract_status = fields.contract_status;
        self.contract_impact = fields.contract_impact;
        self.dependency_impact = fields.dependency_impact;
        self.simplification = fields.simplification;
        self.change_scope = fields.change_scope;
        self.behavior_status = fields.behavior_status;
        self.missing_evidence = fields.missing_evidence;
        self.evidence = fields.evidence;
        self
    }

    pub fn matches_method(&self, unit_id: &str, source_hash: &str, method: &MethodRecord) -> bool {
        self.unit_id == unit_id
            && self.source_hash == source_hash
            && self.file_path == method.file_path
            && self.method_name == method.name
            && self.start_line == method.start_line
            && self.end_line == method.end_line
            && self.loc == method.loc
            && self.verdict.check_type == "method"
            && self.verdict.file_path == method.file_path
            && self.verdict.method_name.as_deref() == Some(method.name.as_str())
            && self.verdict.loc == method.loc
            && self.verdict.start_line == method.start_line
            && self.verdict.end_line == method.end_line
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunStats {
    pub files_scanned: usize,
    pub methods_analyzed: usize,
    pub flagged_by_ref_count: usize,
    pub flagged_by_scorer: usize,
    pub duplication_static: usize,
    pub churn_static: usize,
    pub architecture_static: usize,
    pub test_coupling_static: usize,
    pub provenance_static: usize,
    pub slop_static: usize,
    pub kinda_slop_static: usize,
    pub slop_ai: usize,
    pub kinda_slop_ai: usize,
    pub unresolved_ai: usize,
    pub ai_reviews: usize,
    pub ai_expected_reviews: usize,
    pub ai_failed_reviews: usize,
    pub method_reviews_completed: usize,
    pub method_reviews_expected: usize,
    pub method_review_failures: usize,
    pub unresolved_methods: usize,
    #[serde(default)]
    pub compiler_methods_covered: usize,
    #[serde(default)]
    pub compiler_methods_expected: usize,
    pub dead_methods: usize,
    pub inline_candidates: usize,
    pub input_tokens: usize,
    #[serde(default)]
    pub cached_input_tokens: usize,
    pub output_tokens: usize,
    pub estimated_cost_usd: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunReport {
    pub file_verdicts: Vec<FileVerdict>,
    pub static_flags: Vec<StaticFlag>,
    pub llm_verdicts: Vec<LLMVerdict>,
    /// The complete identity-bearing method census consumed by later synthesis.
    pub method_review_records: Vec<MethodReviewRecord>,
    /// Typed cases seeded from proven method findings; later synthesis may merge them.
    pub slop_cases: Vec<SlopCase>,
    pub stats: RunStats,
}
