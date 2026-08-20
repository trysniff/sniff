use serde::{Deserialize, Serialize};

pub const INTENTIONAL_BOUNDARY_MANIFEST_BINDING_CENSUS_SCHEMA_VERSION: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryManifestBoundSubject {
    pub parser_unit_id: String,
    pub subject_symbol_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryManifestNonMethodReason {
    WholeScriptEntrypoint,
    ModuleHasNoExportedMethods,
    ModuleLevelPythonEntrypoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentionalBoundaryManifestBindingUnresolvedReason {
    TargetNotInSourceCensus,
    AmbiguousSourceTarget,
    UnsupportedPythonQualname,
    CompilerMethodUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IntentionalBoundaryManifestBindingOutcome {
    Bound {
        subjects: Vec<IntentionalBoundaryManifestBoundSubject>,
    },
    NonMethodBoundary {
        reason: IntentionalBoundaryManifestNonMethodReason,
    },
    AwaitingGeneratorReplay,
    Unresolved {
        reason: IntentionalBoundaryManifestBindingUnresolvedReason,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryManifestBinding {
    pub declaration_id: String,
    pub outcome: IntentionalBoundaryManifestBindingOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundaryManifestBindingCensus {
    pub schema_version: u32,
    pub binding_contract: String,
    pub repository: String,
    pub revision: String,
    pub source_census_sha256: String,
    pub semantic_census_sha256: String,
    pub manifest_census_sha256: String,
    pub bindings: Vec<IntentionalBoundaryManifestBinding>,
    pub bound_declaration_count: usize,
    pub non_method_declaration_count: usize,
    pub awaiting_generator_replay_count: usize,
    pub unresolved_declaration_count: usize,
    pub binding_census_sha256: String,
}
