use super::{
    HistoricalV2FinalLabelBasis, HistoricalV2SlotStage, HistoricalV2TerminalExclusionReason,
};
use crate::product_contract::SlopPattern;
use serde::{Deserialize, Serialize};

pub const HISTORICAL_V2_RELEASE_EVIDENCE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2ReleaseGateStatus {
    Passed,
    Underfilled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV2ReleaseSlotOutcome {
    Unfilled,
    Excluded {
        terminal_checkpoint_sha256: String,
        stage: HistoricalV2SlotStage,
        reason: HistoricalV2TerminalExclusionReason,
    },
    Accepted {
        terminal_checkpoint_sha256: String,
        review_item_id: String,
        source_bundle_sha256: String,
        label_audit_sha256: String,
        final_label_sha256: String,
        basis: HistoricalV2FinalLabelBasis,
        pattern: SlopPattern,
        other_pattern: String,
    },
    ReviewClosed {
        terminal_checkpoint_sha256: String,
        review_item_id: String,
        source_bundle_sha256: String,
        label_audit_sha256: String,
        final_label_sha256: String,
        basis: HistoricalV2FinalLabelBasis,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2ReleaseSlotEvidence {
    pub language: String,
    pub slot_number: usize,
    pub outcome: HistoricalV2ReleaseSlotOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2ReleaseLanguageEvidence {
    pub language: String,
    pub fixed_slot_count: usize,
    pub selected_slot_count: usize,
    pub unfilled_slot_count: usize,
    pub execution_excluded_count: usize,
    pub review_closed_count: usize,
    pub accepted_count: usize,
    pub minimum_accepted: usize,
    pub passes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2ReleaseEvidence {
    pub schema_version: u32,
    pub release_contract: String,
    pub protocol_sha256: String,
    pub selection_sha256: String,
    pub fixed_slot_count: usize,
    pub selected_slot_count: usize,
    pub unfilled_slot_count: usize,
    pub execution_excluded_count: usize,
    pub review_closed_count: usize,
    pub accepted_count: usize,
    pub minimum_total_accepted: usize,
    pub languages: Vec<HistoricalV2ReleaseLanguageEvidence>,
    pub slots: Vec<HistoricalV2ReleaseSlotEvidence>,
    pub status: HistoricalV2ReleaseGateStatus,
    pub evidence_sha256: String,
}
