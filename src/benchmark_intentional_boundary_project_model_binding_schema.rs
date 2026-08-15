use super::{
    IntentionalBoundaryProjectModelNonBoundaryReason,
    IntentionalBoundaryProjectModelUnresolvedReason,
};
use serde::{Deserialize, Serialize};

pub const INTENTIONAL_BOUNDARY_PROJECT_MODEL_BINDING_CENSUS_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryProjectModelBoundSubject {
    pub parser_unit_id: String,
    pub subject_symbol_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryProjectModelNonMethodReason {
    WholeScriptEntrypoint,
    ModuleHasNoExportedMethods,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryProjectModelBindingUnresolvedReason {
    TargetNotInSourceCensus,
    AmbiguousSourceTarget,
    CompilerMethodUnavailable,
    UnsupportedSelector,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IntentionalBoundaryProjectModelBindingOutcome {
    Bound {
        subjects: Vec<IntentionalBoundaryProjectModelBoundSubject>,
    },
    NonMethodBoundary {
        reason: IntentionalBoundaryProjectModelNonMethodReason,
    },
    AwaitingGeneratorReplay,
    NonBoundary {
        reason: IntentionalBoundaryProjectModelNonBoundaryReason,
    },
    UpstreamUnresolved {
        reason: IntentionalBoundaryProjectModelUnresolvedReason,
        detail: String,
    },
    BindingUnresolved {
        reason: IntentionalBoundaryProjectModelBindingUnresolvedReason,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryProjectModelBinding {
    pub target_id: String,
    pub outcome: IntentionalBoundaryProjectModelBindingOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryProjectModelBindingCensus {
    pub schema_version: u32,
    pub binding_contract: String,
    pub repository: String,
    pub revision: String,
    pub source_census_sha256: String,
    pub semantic_census_sha256: String,
    pub project_model_census_sha256: String,
    pub bindings: Vec<IntentionalBoundaryProjectModelBinding>,
    pub bound_target_count: usize,
    pub non_method_target_count: usize,
    pub awaiting_generator_replay_count: usize,
    pub non_boundary_target_count: usize,
    pub upstream_unresolved_target_count: usize,
    pub binding_unresolved_target_count: usize,
    pub binding_census_sha256: String,
}
