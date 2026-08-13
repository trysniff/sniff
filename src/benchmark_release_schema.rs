use super::{BenchmarkCase, BenchmarkMetrics};
use crate::types::FindingTier;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkPartition {
    SyntheticGold,
    HistoricalSimplification,
    ResearchTrajectory,
    IntentionalBoundary,
    BlindOss,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceSnapshot {
    pub repository: String,
    pub revision: String,
    pub repository_path: String,
    pub artifact_path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkEvidence {
    pub artifact_path: String,
    pub source_sha256: String,
    pub start_line: usize,
    pub end_line: usize,
    pub quote: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkAdjudication {
    pub reviewer_id: String,
    pub years_experience: u16,
    pub tier: FindingTier,
    pub pattern: String,
    pub rationale: String,
    #[serde(default)]
    pub maintainer: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseBenchmarkCase {
    #[serde(flatten)]
    pub label: BenchmarkCase,
    pub partition: BenchmarkPartition,
    pub before: Vec<SourceSnapshot>,
    #[serde(default)]
    pub after: Vec<SourceSnapshot>,
    pub human_explanation: String,
    pub behavioral_evidence: Vec<String>,
    pub expected_proof_level: u8,
    #[serde(default)]
    pub covered_method_ids: Vec<String>,
    pub adjudications: Vec<BenchmarkAdjudication>,
    #[serde(default)]
    pub disputed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispute_resolution: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkCorpus {
    pub schema_version: u32,
    pub corpus_id: String,
    pub frozen_at: String,
    pub source_commitment_sha256: String,
    pub label_commitment_sha256: String,
    pub source_seal_artifact_path: String,
    pub source_seal_sha256: String,
    pub blind_case_bundle_artifact_path: String,
    pub blind_case_bundle_sha256: String,
    pub analysis_sources: Vec<SourceSnapshot>,
    pub cases: Vec<ReleaseBenchmarkCase>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewerDisposition {
    Accepted,
    Rejected,
    Unreviewed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkRunPrediction {
    pub prediction_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_case_id: Option<String>,
    pub tier: FindingTier,
    pub pattern: String,
    #[serde(default)]
    pub evidence: Vec<BenchmarkEvidence>,
    pub proof_level: u8,
    pub reviewer_disposition: ReviewerDisposition,
    pub reviewer_minutes: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkUsage {
    pub input_tokens: u64,
    pub cached_input_tokens: u64,
    pub output_tokens: u64,
    pub actual_cost_microusd: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActualCostReceipt {
    pub schema_version: u32,
    pub provider: String,
    pub model: String,
    pub currency: String,
    pub actual_cost_microusd: u64,
    pub provenance: String,
    pub raw_evidence_artifact_path: String,
    pub raw_evidence_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindReviewer {
    pub reviewer_id: String,
    pub years_experience: u16,
    pub affiliation: String,
    pub independent_from_sniff: bool,
    pub labels_hidden_during_review: bool,
    pub attestation: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkRun {
    pub run_id: String,
    pub tool_version: String,
    pub source_revision: String,
    pub provider: String,
    pub model: String,
    pub prompt_contract_version: String,
    pub source_commitment_sha256: String,
    pub label_commitment_sha256: String,
    pub completed_artifact_ids: Vec<String>,
    pub execution_commitments_sha256: Vec<String>,
    pub cross_scan_reused_units: usize,
    pub analyzed_method_count: usize,
    pub covered_case_ids: Vec<String>,
    pub predictions: Vec<BenchmarkRunPrediction>,
    pub usage: BenchmarkUsage,
    pub actual_cost_provenance: String,
    pub actual_cost_artifact_path: String,
    pub actual_cost_artifact_sha256: String,
    pub blind_reviewer: BlindReviewer,
    pub wall_clock_seconds: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkBaseline {
    pub tool_id: String,
    pub tool_version: String,
    pub run_id: String,
    pub corpus_id: String,
    pub source_commitment_sha256: String,
    pub label_commitment_sha256: String,
    pub raw_output_artifact_path: String,
    pub raw_output_sha256: String,
    pub covered_case_ids: Vec<String>,
    pub findings: Vec<BenchmarkBaselineFinding>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkBaselineFinding {
    pub finding_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_case_id: Option<String>,
    pub reviewer_disposition: ReviewerDisposition,
    pub reviewer_minutes: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkSubmission {
    pub schema_version: u32,
    pub corpus_id: String,
    pub runs: Vec<BenchmarkRun>,
    pub baselines: Vec<BenchmarkBaseline>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReleaseBenchmarkMetrics {
    pub primary: BenchmarkMetrics,
    pub real_world: BenchmarkMetrics,
    pub per_run: BTreeMap<String, BenchmarkMetrics>,
    pub real_world_per_run: BTreeMap<String, BenchmarkMetrics>,
    pub blind_oss_per_run: BTreeMap<String, BenchmarkMetrics>,
    pub run_count: usize,
    pub verdict_repeatability: f64,
    pub duplicate_case_rate: f64,
    pub unresolved_rate: f64,
    pub proof_level_accuracy: f64,
    pub overall_evidence_validity: f64,
    pub maintainer_acceptance: f64,
    pub accepted_findings: usize,
    pub reviewer_minutes: f64,
    pub accepted_findings_per_reviewer_minute: f64,
    pub cost_usd_per_1000_methods: f64,
    pub unmatched_findings: usize,
    pub unmatched_slop: usize,
    pub by_partition: BTreeMap<String, BenchmarkMetrics>,
    pub release_gate_errors: Vec<String>,
}
