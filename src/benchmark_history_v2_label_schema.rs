use super::{HistoricalV2ReviewChangedMethod, HistoricalV2ReviewSnapshotSide};
use crate::product_contract::SlopPattern;
use serde::{Deserialize, Serialize};

pub const HISTORICAL_V2_LABEL_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SourceCitation {
    pub side: HistoricalV2ReviewSnapshotSide,
    pub repository_path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub quote: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2ReviewerVerdict {
    Accept,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2ReviewDecision {
    pub verdict: Option<HistoricalV2ReviewerVerdict>,
    pub pattern: Option<SlopPattern>,
    pub other_pattern: String,
    pub mechanism: String,
    pub exact_before_slop_mechanism: Option<bool>,
    pub exact_after_removal: Option<bool>,
    pub simpler_counterfactual_matches: Option<bool>,
    pub public_surface_preserved: Option<bool>,
    pub behavior_preserved: Option<bool>,
    pub simpler_counterfactual: String,
    pub rationale: String,
    pub citations: Vec<HistoricalV2SourceCitation>,
}

impl HistoricalV2ReviewDecision {
    pub(super) fn blank() -> Self {
        Self {
            verdict: None,
            pattern: None,
            other_pattern: String::new(),
            mechanism: String::new(),
            exact_before_slop_mechanism: None,
            exact_after_removal: None,
            simpler_counterfactual_matches: None,
            public_surface_preserved: None,
            behavior_preserved: None,
            simpler_counterfactual: String::new(),
            rationale: String::new(),
            citations: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2Reviewer {
    pub reviewer_id: String,
    pub years_experience: u16,
    pub affiliation: String,
    pub independent_from_sniff: bool,
    pub sniff_output_hidden: bool,
    pub dataset_judgments_hidden: bool,
    pub other_reviewer_labels_hidden: bool,
    pub complete_source_context_inspected: bool,
    pub behavior_evidence_inspected: bool,
    pub model_assistance_used: bool,
    pub attestation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2ReviewMethodSource {
    pub method: HistoricalV2ReviewChangedMethod,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2LabelTask {
    pub review_item_id: String,
    pub language: String,
    pub changed_methods: Vec<HistoricalV2ReviewMethodSource>,
    pub decision: HistoricalV2ReviewDecision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2LabelWorksheet {
    pub schema_version: u32,
    pub protocol_sha256: String,
    pub source_bundle_sha256: String,
    pub task_sha256: String,
    pub reviewer: Option<HistoricalV2Reviewer>,
    pub task: HistoricalV2LabelTask,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2LabelStatus {
    Accepted,
    Rejected,
    Disputed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2ReviewerLabel {
    pub reviewer_id: String,
    pub decision: HistoricalV2ReviewDecision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2LabelAudit {
    pub schema_version: u32,
    pub protocol_sha256: String,
    pub source_bundle_sha256: String,
    pub task_sha256: String,
    pub worksheet_sha256s: Vec<String>,
    pub reviewers: Vec<HistoricalV2Reviewer>,
    pub review_item_id: String,
    pub status: HistoricalV2LabelStatus,
    pub labels: Vec<HistoricalV2ReviewerLabel>,
    pub audit_sha256: String,
}
