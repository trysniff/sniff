use super::{
    IntentionalBoundaryEvidenceCensus, IntentionalBoundaryProjectModelBindingCensus,
    IntentionalBoundaryProjectModelCensus, IntentionalBoundaryProjectModelProvider,
};
use serde::{Deserialize, Serialize};

pub const INTENTIONAL_BOUNDARY_PROJECT_MODEL_STAGE_SCHEMA_VERSION: u32 = 1;
pub const INTENTIONAL_BOUNDARY_PROJECT_MODEL_EXCLUSION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryProjectModelExclusionReason {
    UnsupportedProjectShape,
    ProviderRejectedRepository,
    ProviderOutputIncomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryProjectModelFailurePhase {
    RepositoryValidation,
    SnapshotPreparation,
    RuntimePreparation,
    Execution,
    OutputValidation,
    IntegrityVerification,
    CensusAssembly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryProjectModelProcessEvidence {
    pub status_code: Option<i32>,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub retained_stdout: String,
    pub retained_stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryProjectModelFailureEvidence {
    pub reason: IntentionalBoundaryProjectModelExclusionReason,
    pub provider: IntentionalBoundaryProjectModelProvider,
    pub phase: IntentionalBoundaryProjectModelFailurePhase,
    pub invocation_anchor_repository_path: Option<String>,
    pub detail_sha256: String,
    pub retained_detail: String,
    pub detail_truncated: bool,
    pub process: Option<IntentionalBoundaryProjectModelProcessEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryProjectModelStage {
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
    pub required_providers: Vec<IntentionalBoundaryProjectModelProvider>,
    pub project_model_census: IntentionalBoundaryProjectModelCensus,
    pub binding_census: IntentionalBoundaryProjectModelBindingCensus,
    pub evidence_census: IntentionalBoundaryEvidenceCensus,
    pub stage_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryProjectModelExclusion {
    pub schema_version: u32,
    pub exclusion_contract: String,
    pub frame_task_sha256: String,
    pub population_rank: usize,
    pub repository: String,
    pub revision: String,
    pub materialization_sha256: String,
    pub inventory_sha256: String,
    pub source_census_stage_sha256: String,
    pub license_census_stage_sha256: String,
    pub semantic_census_stage_sha256: String,
    pub ast_census_stage_sha256: String,
    pub manifest_stage_sha256: String,
    pub base_evidence_stage_sha256: String,
    pub required_providers: Vec<IntentionalBoundaryProjectModelProvider>,
    pub reasons: Vec<IntentionalBoundaryProjectModelExclusionReason>,
    pub failures: Vec<IntentionalBoundaryProjectModelFailureEvidence>,
    pub exclusion_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentionalBoundaryProjectModelStageOutcome {
    Completed(Box<IntentionalBoundaryProjectModelStage>),
    Excluded(Box<IntentionalBoundaryProjectModelExclusion>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentionalBoundaryProjectModelStageErrorKind {
    InvalidInput,
    InfrastructureUnavailable,
    InfrastructureFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentionalBoundaryProjectModelStageError {
    pub kind: IntentionalBoundaryProjectModelStageErrorKind,
    pub detail: String,
}
