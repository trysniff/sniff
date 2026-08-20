use super::{
    BenchmarkAdjudication, BenchmarkCase, BenchmarkScope, HistoricalV2FinalLabel,
    HistoricalV2LabelAudit, HistoricalV2LabelWorksheet, HistoricalV2ResolutionWorksheet,
    SourceSnapshot,
};
use serde::{Deserialize, Serialize};

pub const HISTORICAL_V2_CORPUS_BUNDLE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2CorpusCase {
    pub label: BenchmarkCase,
    pub before: Vec<SourceSnapshot>,
    pub after: Vec<SourceSnapshot>,
    pub human_explanation: String,
    pub behavioral_evidence: Vec<String>,
    pub scope: BenchmarkScope,
    pub expected_proof_level: u8,
    pub provenance_id: String,
    pub adjudications: Vec<BenchmarkAdjudication>,
    pub disputed: bool,
    pub dispute_resolution: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2CorpusCaseBinding {
    pub language: String,
    pub slot_number: usize,
    pub terminal_checkpoint_sha256: String,
    pub review_item_id: String,
    pub source_bundle_artifact_path: String,
    pub source_bundle_sha256: String,
    pub label_audit_sha256: String,
    pub final_label_sha256: String,
    pub worksheets: Vec<HistoricalV2LabelWorksheet>,
    pub audit: HistoricalV2LabelAudit,
    pub resolution: HistoricalV2ResolutionWorksheet,
    pub final_label: HistoricalV2FinalLabel,
    pub case: HistoricalV2CorpusCase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2CorpusBundle {
    pub schema_version: u32,
    pub corpus_contract: String,
    pub protocol_sha256: String,
    pub selection_sha256: String,
    pub release_evidence_artifact_path: String,
    pub release_evidence_artifact_sha256: String,
    pub release_evidence_sha256: String,
    pub accepted_count: usize,
    pub cases: Vec<HistoricalV2CorpusCaseBinding>,
    pub bundle_sha256: String,
}
