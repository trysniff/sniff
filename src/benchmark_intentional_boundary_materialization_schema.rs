use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const INTENTIONAL_BOUNDARY_MATERIALIZATION_SCHEMA_VERSION: u32 = 1;
pub const INTENTIONAL_BOUNDARY_MATERIALIZATION_EXCLUSION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryMaterializationExclusionReason {
    RepositoryInaccessible,
    EmptyRepository,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IntentionalBoundaryMaterializationExclusionEvidence {
    RepositoryProbe { url: String, status: u16 },
    EmptyClone { clone_url: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryMaterializationExclusion {
    pub schema_version: u32,
    pub exclusion_contract: String,
    pub frame_task_sha256: String,
    pub population_rank: usize,
    pub population_rank_sha256: String,
    pub repository: String,
    pub reason: IntentionalBoundaryMaterializationExclusionReason,
    pub evidence: IntentionalBoundaryMaterializationExclusionEvidence,
    pub exclusion_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryMaterialization {
    pub schema_version: u32,
    pub materialization_contract: String,
    pub frame_task_sha256: String,
    pub population_rank: usize,
    pub population_rank_sha256: String,
    pub repository: String,
    pub clone_url: String,
    pub revision: String,
    pub git_object_format: String,
    pub tree_oid: String,
    pub materialization_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentionalBoundaryMaterializedRepository {
    pub artifact: IntentionalBoundaryMaterialization,
    pub checkout_root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentionalBoundaryMaterializationOutcome {
    Completed(IntentionalBoundaryMaterializedRepository),
    Excluded(IntentionalBoundaryMaterializationExclusion),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentionalBoundaryMaterializationErrorKind {
    InvalidInput,
    InfrastructureUnavailable,
    InfrastructureFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentionalBoundaryMaterializationError {
    pub kind: IntentionalBoundaryMaterializationErrorKind,
    pub detail: String,
}
