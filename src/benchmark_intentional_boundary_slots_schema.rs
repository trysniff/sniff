use super::IntentionalBoundaryCategory;
use serde::{Deserialize, Serialize};

pub const INTENTIONAL_BOUNDARY_SLOT_SELECTION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IntentionalBoundarySlotOutcome {
    Selected {
        candidate_id: String,
        candidate_rank_sha256: String,
    },
    Unfilled {
        available_candidate_count: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySlot {
    pub category: IntentionalBoundaryCategory,
    pub slot_number: usize,
    pub outcome: IntentionalBoundarySlotOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySlotSelection {
    pub schema_version: u32,
    pub selection_contract: String,
    pub frame_task_sha256: String,
    pub candidate_frame_sha256: String,
    pub protocol_sha256: String,
    pub policy_sha256: String,
    pub ranking_seed: String,
    pub ranking_contract: String,
    pub cases_per_category: usize,
    pub slots: Vec<IntentionalBoundarySlot>,
    pub selected_candidate_count: usize,
    pub unfilled_slot_count: usize,
    pub selection_sha256: String,
}
