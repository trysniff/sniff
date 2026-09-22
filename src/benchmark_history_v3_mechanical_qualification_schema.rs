use super::super::{
    HistoricalV3RankIdentity, HistoricalV3SourceSide, IntentionalBoundaryIndexerKind,
    IntentionalBoundarySemanticMethodStatus,
};
use serde::{Deserialize, Serialize};

pub const HISTORICAL_V3_MECHANICAL_QUALIFICATION_SCHEMA_VERSION: u32 = 1;
pub const HISTORICAL_V3_MECHANICAL_QUALIFICATION_EXCLUSION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV3PathChangeKind {
    Added,
    Deleted,
    Modified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV3NonProductionRole {
    Generated,
    Vendored,
    Documentation,
    Fixture,
    Test,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "basis", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV3RoleEvidence {
    CompilerOccurrence {
        role: HistoricalV3NonProductionRole,
    },
    PathSegment {
        role: HistoricalV3NonProductionRole,
        segment: String,
    },
    FileSuffix {
        role: HistoricalV3NonProductionRole,
        suffix: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3QualifiedPath {
    pub path: String,
    pub change: HistoricalV3PathChangeKind,
    pub base_object_id: Option<String>,
    pub merge_object_id: Option<String>,
    pub base_source_sha256: Option<String>,
    pub merge_source_sha256: Option<String>,
    pub base_syntax_sha256: Option<String>,
    pub merge_syntax_sha256: Option<String>,
    pub base_non_whitespace_lines: usize,
    pub merge_non_whitespace_lines: usize,
    pub base_roles: Vec<HistoricalV3RoleEvidence>,
    pub merge_roles: Vec<HistoricalV3RoleEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3ChangedMethod {
    pub side: HistoricalV3SourceSide,
    pub language: String,
    pub repository_path: String,
    pub parser_unit_id: String,
    pub symbol_name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub source_sha256: String,
    pub non_whitespace_line_count: usize,
    pub syntax_sha256: String,
    pub indexer: IntentionalBoundaryIndexerKind,
    pub compiler_symbol_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3UnresolvedChangedMethod {
    pub side: HistoricalV3SourceSide,
    pub language: String,
    pub repository_path: String,
    pub parser_unit_id: String,
    pub symbol_name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub source_sha256: String,
    pub non_whitespace_line_count: usize,
    pub syntax_sha256: String,
    pub indexer: IntentionalBoundaryIndexerKind,
    pub status: IntentionalBoundarySemanticMethodStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3SurfaceEntry {
    pub indexer: IntentionalBoundaryIndexerKind,
    pub symbol_id: String,
    pub api_fingerprint_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3SurfaceChange {
    pub indexer: IntentionalBoundaryIndexerKind,
    pub symbol_id: String,
    pub base_api_fingerprint_sha256: String,
    pub merge_api_fingerprint_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3SurfaceDelta {
    pub base: Vec<HistoricalV3SurfaceEntry>,
    pub merge: Vec<HistoricalV3SurfaceEntry>,
    pub removed: Vec<HistoricalV3SurfaceEntry>,
    pub added: Vec<HistoricalV3SurfaceEntry>,
    pub changed: Vec<HistoricalV3SurfaceChange>,
    pub preserved: bool,
    pub delta_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV3SimplificationKind {
    ProductionLineReduction,
    ProductionMethodConsolidation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3MechanicalEvidence {
    pub changed_paths: Vec<HistoricalV3QualifiedPath>,
    pub base_production_method_count: usize,
    pub merge_production_method_count: usize,
    pub production_method_minimum: usize,
    pub production_method_maximum: usize,
    pub changed_methods: Vec<HistoricalV3ChangedMethod>,
    pub unresolved_changed_methods: Vec<HistoricalV3UnresolvedChangedMethod>,
    pub base_changed_production_non_whitespace_lines: usize,
    pub merge_changed_production_non_whitespace_lines: usize,
    pub base_changed_production_method_count: usize,
    pub merge_changed_production_method_count: usize,
    pub simplifications: Vec<HistoricalV3SimplificationKind>,
    pub formatting_only: bool,
    pub non_production_roles: Vec<HistoricalV3NonProductionRole>,
    pub public_surface: HistoricalV3SurfaceDelta,
    pub evidence_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV3MechanicalExclusionReason {
    RepositoryMethodCountBelowMinimum,
    RepositoryMethodCountAboveMaximum,
    NoChangedProductionMethods,
    NoChangedRankLanguageMethods,
    ChangedProductionMethodUnresolved,
    NoNetProductionReductionOrConsolidation,
    PublicSurfaceChanged,
    GeneratedOnly,
    VendoredOnly,
    DocumentationOnly,
    FixtureOnly,
    FormattingOnly,
    TestOnly,
    MixedNonProductionOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3MechanicalQualification {
    pub schema_version: u32,
    pub qualification_contract: String,
    pub rank: HistoricalV3RankIdentity,
    pub materialization_sha256: String,
    pub source_census_sha256: String,
    pub semantic_census_sha256: String,
    pub evidence: HistoricalV3MechanicalEvidence,
    pub qualification_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3MechanicalQualificationExclusion {
    pub schema_version: u32,
    pub exclusion_contract: String,
    pub rank: HistoricalV3RankIdentity,
    pub materialization_sha256: String,
    pub source_census_sha256: String,
    pub semantic_census_sha256: String,
    pub evidence: HistoricalV3MechanicalEvidence,
    pub reasons: Vec<HistoricalV3MechanicalExclusionReason>,
    pub exclusion_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoricalV3MechanicalQualificationOutcome {
    Qualified(Box<HistoricalV3MechanicalQualification>),
    Excluded(Box<HistoricalV3MechanicalQualificationExclusion>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoricalV3MechanicalQualificationStageRun {
    Qualified {
        artifact: Box<HistoricalV3MechanicalQualification>,
        resumed: bool,
    },
    Excluded {
        artifact: Box<HistoricalV3MechanicalQualificationExclusion>,
        resumed: bool,
    },
}
