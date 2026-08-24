use super::IntentionalBoundarySourceReviewItem;
use crate::types::FindingTier;
use serde::{Deserialize, Serialize};

pub const INTENTIONAL_BOUNDARY_LABEL_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySourceCitation {
    pub repository_path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub quote: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryLabelDecision {
    pub tier: Option<FindingTier>,
    pub intentional_boundary: Option<bool>,
    pub rationale: String,
    pub citations: Vec<IntentionalBoundarySourceCitation>,
}

impl IntentionalBoundaryLabelDecision {
    pub(super) fn blank() -> Self {
        Self {
            tier: None,
            intentional_boundary: None,
            rationale: String::new(),
            citations: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryLabelReviewer {
    pub reviewer_id: String,
    pub years_experience: u16,
    pub affiliation: String,
    pub independent_from_sniff: bool,
    pub sniff_output_hidden: bool,
    pub other_reviewer_labels_hidden: bool,
    pub complete_source_context_inspected: bool,
    pub attestation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryLabelTask {
    pub source: IntentionalBoundarySourceReviewItem,
    pub method_source: String,
    pub decision: IntentionalBoundaryLabelDecision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryLabelWorksheet {
    pub schema_version: u32,
    pub source_bundle_sha256: String,
    pub task_sha256: String,
    pub reviewer: Option<IntentionalBoundaryLabelReviewer>,
    pub items: Vec<IntentionalBoundaryLabelTask>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryLabelProgress {
    pub total_items: usize,
    pub completed_items: usize,
    pub pending_items: usize,
    pub reviewer_complete: bool,
    pub complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryLabelStatus {
    Accepted,
    Rejected,
    Disputed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryReviewerLabel {
    pub reviewer_id: String,
    pub decision: IntentionalBoundaryLabelDecision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryLabelAuditItem {
    pub review_item_id: String,
    pub status: IntentionalBoundaryLabelStatus,
    pub labels: Vec<IntentionalBoundaryReviewerLabel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryLabelAudit {
    pub schema_version: u32,
    pub protocol_sha256: String,
    pub source_bundle_sha256: String,
    pub task_sha256: String,
    pub worksheet_sha256s: Vec<String>,
    pub reviewers: Vec<IntentionalBoundaryLabelReviewer>,
    pub items: Vec<IntentionalBoundaryLabelAuditItem>,
    pub accepted_count: usize,
    pub rejected_count: usize,
    pub disputed_count: usize,
    pub audit_sha256: String,
}
