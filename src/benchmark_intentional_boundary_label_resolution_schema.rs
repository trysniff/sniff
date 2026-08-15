use super::{IntentionalBoundaryLabelDecision, IntentionalBoundaryLabelStatus};
use crate::types::FindingTier;
use serde::{Deserialize, Serialize};

pub const INTENTIONAL_BOUNDARY_LABEL_RESOLUTION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryLabelResolver {
    pub resolver_id: String,
    pub years_experience: u16,
    pub affiliation: String,
    pub independent_from_sniff: bool,
    pub complete_source_context_inspected: bool,
    pub attestation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryResolutionItem {
    pub review_item_id: String,
    pub audit_status: IntentionalBoundaryLabelStatus,
    pub decision: Option<IntentionalBoundaryLabelDecision>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryResolutionWorksheet {
    pub schema_version: u32,
    pub protocol_sha256: String,
    pub source_bundle_sha256: String,
    pub label_audit_sha256: String,
    pub resolution_task_sha256: String,
    pub resolver: Option<IntentionalBoundaryLabelResolver>,
    pub items: Vec<IntentionalBoundaryResolutionItem>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryFinalBasis {
    ReviewerConsensus,
    ConsensusRejected,
    DisputeResolution,
    DisputeResolvedClosed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IntentionalBoundaryFinalOutcome {
    Accepted {
        basis: IntentionalBoundaryFinalBasis,
    },
    Closed {
        basis: IntentionalBoundaryFinalBasis,
        tier: FindingTier,
        intentional_boundary: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryFinalLabel {
    pub review_item_id: String,
    pub outcome: IntentionalBoundaryFinalOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryFinalLabelBundle {
    pub schema_version: u32,
    pub final_contract: String,
    pub protocol_sha256: String,
    pub source_bundle_sha256: String,
    pub selection_sha256: String,
    pub label_audit_sha256: String,
    pub resolution_task_sha256: String,
    pub resolver: Option<IntentionalBoundaryLabelResolver>,
    pub labels: Vec<IntentionalBoundaryFinalLabel>,
    pub accepted_count: usize,
    pub closed_count: usize,
    pub unfilled_slot_count: usize,
    pub final_sha256: String,
}
