use super::super::{
    HistoricalV3ReviewBehaviorEvidence, HistoricalV3ReviewMethod, HistoricalV3SimplificationKind,
    HistoricalV3SourceSide,
};
use crate::product_contract::SlopPattern;
use serde::{Deserialize, Serialize};

pub const HISTORICAL_V3_LABEL_REVIEW_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV3ReviewerVerdict {
    Slop,
    Clean,
    IntentionalBoundary,
    Ambiguous,
    InsufficientContext,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3SourceCitation {
    pub side: HistoricalV3SourceSide,
    pub repository_path: String,
    pub parser_unit_id: String,
    pub start_line: usize,
    pub end_line: usize,
    pub quote: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3ReviewDecision {
    pub verdict: Option<HistoricalV3ReviewerVerdict>,
    pub pattern: Option<SlopPattern>,
    pub other_pattern: String,
    pub mechanism: String,
    pub before_contains_unnecessary_machinery: Option<bool>,
    pub after_removes_that_machinery: Option<bool>,
    pub removal_not_relocated: Option<bool>,
    pub simpler_counterfactual_matches: Option<bool>,
    pub public_surface_preserved: Option<bool>,
    pub behavior_preserved: Option<bool>,
    pub simpler_counterfactual: String,
    pub boundary_justification: String,
    pub rationale: String,
    pub missing_evidence: Vec<String>,
    pub citations: Vec<HistoricalV3SourceCitation>,
}

impl HistoricalV3ReviewDecision {
    pub fn blank() -> Self {
        Self {
            verdict: None,
            pattern: None,
            other_pattern: String::new(),
            mechanism: String::new(),
            before_contains_unnecessary_machinery: None,
            after_removes_that_machinery: None,
            removal_not_relocated: None,
            simpler_counterfactual_matches: None,
            public_surface_preserved: None,
            behavior_preserved: None,
            simpler_counterfactual: String::new(),
            boundary_justification: String::new(),
            rationale: String::new(),
            missing_evidence: Vec::new(),
            citations: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3Reviewer {
    pub reviewer_id: String,
    pub years_experience: u16,
    pub affiliation: String,
    pub independent_from_sniff: bool,
    pub sniff_output_hidden: bool,
    pub repository_identity_hidden: bool,
    pub change_metadata_hidden: bool,
    pub other_reviewer_labels_hidden: bool,
    pub complete_source_context_inspected: bool,
    pub behavior_evidence_inspected: bool,
    pub model_assistance_used: bool,
    pub attestation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3LabelTask {
    pub review_item_id: String,
    pub language: String,
    pub public_surface_preserved: bool,
    pub public_surface_delta_sha256: String,
    pub simplifications: Vec<HistoricalV3SimplificationKind>,
    pub methods: Vec<HistoricalV3ReviewMethod>,
    pub behavior: HistoricalV3ReviewBehaviorEvidence,
    pub decision: HistoricalV3ReviewDecision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3LabelWorksheet {
    pub schema_version: u32,
    pub protocol_sha256: String,
    pub source_bundle_sha256: String,
    pub task_sha256: String,
    pub reviewer: Option<HistoricalV3Reviewer>,
    pub task: HistoricalV3LabelTask,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV3LabelStatus {
    Accepted,
    Rejected,
    Disputed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3ReviewerLabel {
    pub reviewer_id: String,
    pub decision: HistoricalV3ReviewDecision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3LabelAudit {
    pub schema_version: u32,
    pub protocol_sha256: String,
    pub source_bundle_sha256: String,
    pub task_sha256: String,
    pub worksheet_sha256s: Vec<String>,
    pub reviewers: Vec<HistoricalV3Reviewer>,
    pub review_item_id: String,
    pub status: HistoricalV3LabelStatus,
    pub labels: Vec<HistoricalV3ReviewerLabel>,
    pub audit_sha256: String,
}
