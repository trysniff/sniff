use super::super::{
    HistoricalV3LabelStatus, HistoricalV3ReviewDecision, HistoricalV3ReviewerVerdict,
};
use crate::product_contract::SlopPattern;
use serde::{Deserialize, Serialize};

pub const HISTORICAL_V3_LABEL_RESOLUTION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3LabelResolver {
    pub resolver_id: String,
    pub years_experience: u16,
    pub affiliation: String,
    pub independent_from_sniff: bool,
    pub sniff_output_hidden: bool,
    pub repository_identity_hidden: bool,
    pub change_metadata_hidden: bool,
    pub complete_source_context_inspected: bool,
    pub behavior_evidence_inspected: bool,
    pub model_assistance_used: bool,
    pub attestation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3ResolutionItem {
    pub review_item_id: String,
    pub audit_status: HistoricalV3LabelStatus,
    pub decision: Option<HistoricalV3ReviewDecision>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3ResolutionWorksheet {
    pub schema_version: u32,
    pub protocol_sha256: String,
    pub source_bundle_sha256: String,
    pub label_audit_sha256: String,
    pub resolution_task_sha256: String,
    pub resolver: Option<HistoricalV3LabelResolver>,
    pub item: HistoricalV3ResolutionItem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV3FinalLabelBasis {
    ReviewerConsensus,
    ConsensusNonSlop,
    DisputeResolution,
    DisputeResolvedNonSlop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV3FinalLabelOutcome {
    Accepted {
        basis: HistoricalV3FinalLabelBasis,
        pattern: SlopPattern,
        other_pattern: String,
    },
    Closed {
        basis: HistoricalV3FinalLabelBasis,
        verdict: HistoricalV3ReviewerVerdict,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3FinalLabel {
    pub schema_version: u32,
    pub final_contract: String,
    pub protocol_sha256: String,
    pub source_bundle_sha256: String,
    pub review_item_id: String,
    pub language: String,
    pub label_audit_sha256: String,
    pub resolution_task_sha256: String,
    pub resolver: Option<HistoricalV3LabelResolver>,
    pub outcome: HistoricalV3FinalLabelOutcome,
    pub final_sha256: String,
}
