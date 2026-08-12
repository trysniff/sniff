use crate::benchmark::{BenchmarkEvidence, BlindReviewer, ReviewerDisposition};
use crate::types::FindingTier;
use serde::{Deserialize, Serialize};

pub const BENCHMARK_REVIEW_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindCaseSource {
    pub repository: String,
    pub revision: String,
    pub repository_path: String,
    pub artifact_path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindBenchmarkCase {
    pub case_id: String,
    pub language: String,
    pub sources: Vec<BlindCaseSource>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PreparedOutcome {
    pub outcome_id: String,
    pub finding_fingerprint: Option<String>,
    pub tier: FindingTier,
    pub pattern: String,
    pub mechanism: String,
    pub evidence: Vec<BenchmarkEvidence>,
    pub proof_level: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedRunIdentity {
    pub tool_version: String,
    pub source_revision: String,
    pub provider: String,
    pub model: String,
    pub prompt_contract_version: String,
    pub completed_artifact_ids: Vec<String>,
    pub execution_commitments_sha256: Vec<String>,
    pub cross_scan_reused_units: usize,
    pub analyzed_method_count: usize,
    pub input_tokens: u64,
    pub cached_input_tokens: u64,
    pub output_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutcomeReview {
    pub outcome_id: String,
    pub matched_case_id: Option<String>,
    pub reviewer_disposition: ReviewerDisposition,
    pub reviewer_minutes: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkRunReview {
    pub schema_version: u32,
    pub corpus_id: String,
    pub source_commitment_sha256: String,
    pub label_commitment_sha256: String,
    pub completed_artifact_paths: Vec<String>,
    pub prepared: PreparedRunIdentity,
    pub blind_cases: Vec<BlindBenchmarkCase>,
    pub outcomes: Vec<PreparedOutcome>,
    pub reviews: Vec<OutcomeReview>,
    pub actual_cost_microusd: Option<u64>,
    pub actual_cost_provenance: String,
    pub actual_cost_artifact_path: String,
    pub actual_cost_artifact_sha256: String,
    pub blind_reviewer: Option<BlindReviewer>,
    pub wall_clock_seconds: Option<f64>,
}
