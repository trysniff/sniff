use super::{IntentionalBoundaryBehaviorCensus, IntentionalBoundaryEvidenceCensus};
use serde::{Deserialize, Serialize};

pub const INTENTIONAL_BOUNDARY_BEHAVIOR_STAGE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryBehaviorStage {
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
    pub behavior_census: IntentionalBoundaryBehaviorCensus,
    pub evidence_census: IntentionalBoundaryEvidenceCensus,
    pub stage_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentionalBoundaryBehaviorStageErrorKind {
    InvalidInput,
    InfrastructureUnavailable,
    InfrastructureFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentionalBoundaryBehaviorStageError {
    pub kind: IntentionalBoundaryBehaviorStageErrorKind,
    pub detail: String,
}
