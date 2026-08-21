use super::IntentionalBoundarySemanticRange;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const INTENTIONAL_BOUNDARY_GENERATOR_CENSUS_SCHEMA_VERSION: u32 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryGeneratorUnresolvedReason {
    MissingConfiguration,
    AmbiguousConfiguration,
    UnsupportedConfiguration,
    RuntimeUnavailable,
    SandboxUnavailable,
    ExecutionFailed,
    OutputMissing,
    OutputChanged,
    RepositoryMutation,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryGeneratorSubject {
    pub parser_unit_id: String,
    pub subject_symbol_id: String,
    pub repository_path: String,
    pub marker_location: IntentionalBoundarySemanticRange,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryGeneratorOutput {
    pub repository_path: String,
    pub object_id: String,
    pub byte_length: u64,
    pub committed_sha256: String,
    pub first_run_sha256: String,
    pub second_run_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryGeneratorExecution {
    pub run_number: u8,
    pub command: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub runtime_identity_sha256: String,
    pub status_code: i32,
    pub timed_out: bool,
    pub network_enabled: bool,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IntentionalBoundaryGeneratorReplayOutcome {
    Reproduced {
        declaration_id: String,
        declaration_location: IntentionalBoundarySemanticRange,
        preparations: Vec<IntentionalBoundaryGeneratorExecution>,
        command: Vec<String>,
        outputs: Vec<IntentionalBoundaryGeneratorOutput>,
        executions: Vec<IntentionalBoundaryGeneratorExecution>,
    },
    Unresolved {
        reason: IntentionalBoundaryGeneratorUnresolvedReason,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryGeneratorReplay {
    pub replay_id: String,
    pub configuration_declaration_id: Option<String>,
    pub candidate_declaration_ids: Vec<String>,
    pub subjects: Vec<IntentionalBoundaryGeneratorSubject>,
    pub outcome: IntentionalBoundaryGeneratorReplayOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryGeneratorCensus {
    pub schema_version: u32,
    pub generator_contract: String,
    pub repository: String,
    pub revision: String,
    pub inventory_sha256: String,
    pub source_census_sha256: String,
    pub semantic_census_sha256: String,
    pub project_model_census_sha256: String,
    pub manifest_census_sha256: String,
    pub manifest_binding_census_sha256: String,
    pub base_evidence_census_sha256: String,
    pub replays: Vec<IntentionalBoundaryGeneratorReplay>,
    pub replay_count_by_status: BTreeMap<String, usize>,
    pub generator_census_sha256: String,
}
