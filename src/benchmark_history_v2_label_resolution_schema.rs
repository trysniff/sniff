use super::{HistoricalV2LabelStatus, HistoricalV2ReviewDecision, HistoricalV2ReviewerVerdict};
use crate::product_contract::SlopPattern;
use serde::{Deserialize, Serialize};

pub const HISTORICAL_V2_LABEL_RESOLUTION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2LabelResolver {
    pub resolver_id: String,
    pub years_experience: u16,
    pub affiliation: String,
    pub independent_from_sniff: bool,
    pub complete_source_context_inspected: bool,
    pub behavior_evidence_inspected: bool,
    pub model_assistance_used: bool,
    pub attestation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2ResolutionItem {
    pub review_item_id: String,
    pub audit_status: HistoricalV2LabelStatus,
    pub decision: Option<HistoricalV2ReviewDecision>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2ResolutionWorksheet {
    pub schema_version: u32,
    pub protocol_sha256: String,
    pub source_bundle_sha256: String,
    pub label_audit_sha256: String,
    pub resolution_task_sha256: String,
    pub resolver: Option<HistoricalV2LabelResolver>,
    pub item: HistoricalV2ResolutionItem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2FinalLabelBasis {
    ReviewerConsensus,
    ConsensusRejected,
    DisputeResolution,
    DisputeResolvedRejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV2FinalLabelOutcome {
    Accepted {
        basis: HistoricalV2FinalLabelBasis,
        pattern: SlopPattern,
        other_pattern: String,
    },
    Closed {
        basis: HistoricalV2FinalLabelBasis,
        resolver_verdict: Option<HistoricalV2ReviewerVerdict>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2FinalLabel {
    pub schema_version: u32,
    pub final_contract: String,
    pub protocol_sha256: String,
    pub selection_sha256: String,
    pub source_bundle_sha256: String,
    pub assessment_identity_sha256: String,
    pub terminal_checkpoint_sha256: String,
    pub review_item_id: String,
    pub language: String,
    pub label_audit_sha256: String,
    pub resolution_task_sha256: String,
    pub resolver: Option<HistoricalV2LabelResolver>,
    pub outcome: HistoricalV2FinalLabelOutcome,
    pub final_sha256: String,
}
