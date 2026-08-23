use super::IntentionalBoundaryCandidateCensus;
use serde::{Deserialize, Serialize};

pub const INTENTIONAL_BOUNDARY_CANDIDATE_STAGE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryCandidateStage {
    pub schema_version: u32,
    pub stage_contract: String,
    pub frame_task_sha256: String,
    pub population_rank: usize,
    pub materialization_sha256: String,
    pub inventory_sha256: String,
    pub source_census_stage_sha256: String,
    pub license_census_stage_sha256: String,
    pub semantic_census_stage_sha256: String,
    pub ast_census_stage_sha256: String,
    pub manifest_stage_sha256: String,
    pub base_evidence_stage_sha256: String,
    pub project_model_stage_sha256: String,
    pub generator_stage_sha256: String,
    pub behavior_stage_sha256: String,
    pub protocol_sha256: String,
    pub candidate_census: IntentionalBoundaryCandidateCensus,
    pub stage_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentionalBoundaryCandidateStageErrorKind {
    InvalidInput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentionalBoundaryCandidateStageError {
    pub kind: IntentionalBoundaryCandidateStageErrorKind,
    pub detail: String,
}
