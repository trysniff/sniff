use super::{
    IntentionalBoundaryCandidate, IntentionalBoundaryCandidateCensus, IntentionalBoundaryCategory,
    IntentionalBoundaryFrameExclusionReason, IntentionalBoundaryRepositoryTask,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const INTENTIONAL_BOUNDARY_FRAME_RANK_SCHEMA_VERSION: u32 = 1;
pub const INTENTIONAL_BOUNDARY_CANDIDATE_FRAME_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IntentionalBoundaryFrameRankOutcome {
    Analyzed {
        inventory_sha256: String,
        candidate_census: Box<IntentionalBoundaryCandidateCensus>,
    },
    Excluded {
        reason: IntentionalBoundaryFrameExclusionReason,
        evidence_sha256: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryFrameRankRecord {
    pub schema_version: u32,
    pub frame_task_sha256: String,
    pub repository_task: IntentionalBoundaryRepositoryTask,
    pub outcome: IntentionalBoundaryFrameRankOutcome,
    pub record_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryCandidateFrame {
    pub schema_version: u32,
    pub frame_contract: String,
    pub frame_task_sha256: String,
    pub protocol_sha256: String,
    pub rank_records: Vec<IntentionalBoundaryFrameRankRecord>,
    pub candidates: Vec<IntentionalBoundaryCandidate>,
    pub analyzed_repository_count: usize,
    pub excluded_repository_count: usize,
    pub candidate_count_by_category: BTreeMap<IntentionalBoundaryCategory, usize>,
    pub frame_sha256: String,
}
