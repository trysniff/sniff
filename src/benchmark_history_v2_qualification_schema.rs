use super::{
    HistoricalDiffHunk, HistoricalRevisionSide, IntentionalBoundaryIndexerKind,
    IntentionalBoundarySemanticUnresolvedReason,
};
use serde::{Deserialize, Serialize};

pub const HISTORICAL_V2_QUALIFICATION_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2SourceRole {
    Production,
    Test,
    Fixture,
    Example,
    Generated,
    Vendored,
    Documentation,
    Script,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2SourceRoleBasis {
    TrackedSupportedSource,
    CompilerRuntimeSurface,
    TestPath,
    FixturePath,
    ExamplePath,
    GeneratedPath,
    GeneratedHeader,
    VendoredPath,
    DocumentationPath,
    ScriptPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SourceRoleDecision {
    pub role: HistoricalV2SourceRole,
    pub basis: HistoricalV2SourceRoleBasis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2QualifiedPath {
    pub previous_path: Option<String>,
    pub path: String,
    pub base_role: Option<HistoricalV2SourceRoleDecision>,
    pub patched_role: Option<HistoricalV2SourceRoleDecision>,
    pub production_role_stable: bool,
    pub base_non_whitespace_lines: usize,
    pub patched_non_whitespace_lines: usize,
    pub hunks: Vec<HistoricalDiffHunk>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2ChangedMethod {
    pub side: HistoricalRevisionSide,
    pub language: String,
    pub repository_path: String,
    pub parser_unit_id: String,
    pub symbol_name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub source_sha256: String,
    pub indexer: IntentionalBoundaryIndexerKind,
    pub compiler_symbol_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV2ChangedMethodResolutionFailure {
    MissingSemanticMethod,
    CompilerExcluded {
        reason: String,
    },
    Unresolved {
        reason: IntentionalBoundarySemanticUnresolvedReason,
        raw_target: Option<String>,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2UnresolvedChangedMethod {
    pub side: HistoricalRevisionSide,
    pub repository_path: String,
    pub parser_unit_id: String,
    pub symbol_name: String,
    pub failure: HistoricalV2ChangedMethodResolutionFailure,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2PublicSurfaceEntry {
    pub indexer: IntentionalBoundaryIndexerKind,
    pub surface_unit_id: String,
    pub declaration_unit_id: String,
    pub symbol_id: String,
    pub semantic_fingerprint_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2PublicSurfaceChange {
    pub indexer: IntentionalBoundaryIndexerKind,
    pub surface_unit_id: String,
    pub base_symbol_id: String,
    pub patched_symbol_id: String,
    pub base_fingerprint_sha256: String,
    pub patched_fingerprint_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2PublicSurfaceDelta {
    pub base_entries: Vec<HistoricalV2PublicSurfaceEntry>,
    pub patched_entries: Vec<HistoricalV2PublicSurfaceEntry>,
    pub removed: Vec<HistoricalV2PublicSurfaceEntry>,
    pub added: Vec<HistoricalV2PublicSurfaceEntry>,
    pub changed: Vec<HistoricalV2PublicSurfaceChange>,
    pub preserved: bool,
    pub delta_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2QualificationExclusionReason {
    PatchAndGitPathsDisagree,
    ChangedSourceMissingFromCensus,
    RepositoryMethodCountBelowMinimum,
    RepositoryMethodCountAboveMaximum,
    ProductionRoleChanged,
    NoChangedProductionPaths,
    ChangedProductionMethodUnresolved,
    NoChangedBaseProductionMethods,
    NoNetProductionReduction,
    PublicSurfaceChanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV2QualificationOutcome {
    Qualified,
    Excluded {
        reasons: Vec<HistoricalV2QualificationExclusionReason>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2Qualification {
    pub schema_version: u32,
    pub qualification_contract: String,
    pub assessment_identity_sha256: String,
    pub language: String,
    pub slot_number: usize,
    pub patch_changed_paths: Vec<String>,
    pub git_changed_paths: Vec<String>,
    pub qualified_paths: Vec<HistoricalV2QualifiedPath>,
    pub repository_production_method_count: usize,
    pub repository_method_minimum: usize,
    pub repository_method_maximum: usize,
    pub changed_methods: Vec<HistoricalV2ChangedMethod>,
    pub unresolved_changed_methods: Vec<HistoricalV2UnresolvedChangedMethod>,
    pub production_non_whitespace_lines_before: usize,
    pub production_non_whitespace_lines_after: usize,
    pub public_surface: HistoricalV2PublicSurfaceDelta,
    pub outcome: HistoricalV2QualificationOutcome,
    pub qualification_sha256: String,
}
