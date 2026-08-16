use super::{HistoricalV2IdenticalTestExecution, HistoricalV2IdenticalTestPlan};
use serde::{Deserialize, Serialize};

pub const HISTORICAL_V2_EXECUTION_CHECKPOINT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2ExecutionCheckpointDisposition {
    IdenticalTestsExcluded,
    ReadyForReview,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2ExecutionCheckpoint {
    pub schema_version: u32,
    pub checkpoint_contract: String,
    pub selection_sha256: String,
    pub assessment_identity_sha256: String,
    pub language: String,
    pub slot_number: usize,
    pub canonical_repository: String,
    pub qualification_sha256: String,
    pub test_recipe_sha256: String,
    pub plan_sha256: String,
    pub execution_sha256: String,
    pub disposition: HistoricalV2ExecutionCheckpointDisposition,
    pub checkpoint_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalV2CheckpointedExecution {
    pub checkpoint: HistoricalV2ExecutionCheckpoint,
    pub plan: HistoricalV2IdenticalTestPlan,
    pub execution: HistoricalV2IdenticalTestExecution,
    pub resumed: bool,
}
