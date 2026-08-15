use super::{IntentionalBoundaryManifestDeclarationKind, IntentionalBoundaryManifestTarget};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const INTENTIONAL_BOUNDARY_PROJECT_MODEL_CENSUS_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryProjectModelProvider {
    CargoMetadata,
    GoList,
    GradleToolingApi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryProjectModelNonBoundaryReason {
    ExampleTarget,
    TestTarget,
    BenchmarkTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryProjectModelUnresolvedReason {
    ConflictingTargetKinds,
    UnknownTargetKind,
    SourceOutsideRepository,
    SourceNotTracked,
    SourceNotRegularBlob,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IntentionalBoundaryProjectModelTargetStatus {
    Boundary {
        declaration_kind: IntentionalBoundaryManifestDeclarationKind,
        target: IntentionalBoundaryManifestTarget,
    },
    NonBoundary {
        reason: IntentionalBoundaryProjectModelNonBoundaryReason,
    },
    Unresolved {
        reason: IntentionalBoundaryProjectModelUnresolvedReason,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryProjectModelTarget {
    pub target_id: String,
    pub execution_id: String,
    pub provider: IntentionalBoundaryProjectModelProvider,
    pub manifest_repository_path: String,
    pub manifest_object_id: String,
    pub package_name: String,
    pub package_version: String,
    pub target_name: String,
    pub provider_kinds: Vec<String>,
    pub provider_output_types: Vec<String>,
    pub source_repository_paths: Vec<String>,
    pub required_features: Vec<String>,
    pub target_status: IntentionalBoundaryProjectModelTargetStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryProjectModelExecution {
    pub execution_id: String,
    pub provider: IntentionalBoundaryProjectModelProvider,
    pub invocation_anchor_repository_path: String,
    pub invocation_anchor_object_id: String,
    pub toolchain_identity_sha256: String,
    pub command_contract: String,
    pub normalized_model_sha256: String,
    pub covered_manifest_repository_paths: Vec<String>,
    pub target_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryProjectModelCensus {
    pub schema_version: u32,
    pub project_model_contract: String,
    pub repository: String,
    pub revision: String,
    pub inventory_sha256: String,
    pub executions: Vec<IntentionalBoundaryProjectModelExecution>,
    pub targets: Vec<IntentionalBoundaryProjectModelTarget>,
    pub execution_count_by_provider: BTreeMap<IntentionalBoundaryProjectModelProvider, usize>,
    pub target_count_by_status: BTreeMap<String, usize>,
    pub project_model_census_sha256: String,
}
