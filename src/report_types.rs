use serde::{Deserialize, Serialize};

use crate::types::FindingTier;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub ai_reviews: usize,
    pub ai_expected_reviews: usize,
    pub ai_failed_reviews: usize,
    pub dead_methods: usize,
    pub inline_candidates: usize,
    pub input_tokens: usize,
    pub output_tokens: usize,
    pub estimated_cost_usd: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunReport {
    pub file_verdicts: Vec<FileVerdict>,
    pub static_flags: Vec<StaticFlag>,
    pub llm_verdicts: Vec<LLMVerdict>,
    pub stats: RunStats,
}
