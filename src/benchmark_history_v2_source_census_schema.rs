use super::{HistoricalV2NodePackageSurfaceCensus, IntentionalBoundaryProjectModelCensus};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const HISTORICAL_V2_SOURCE_CENSUS_SCHEMA_VERSION: u32 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2SourceSemanticCoverage {
    Required,
    GeneratedPath,
    GeneratedHeader,
    VendoredPath,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SourceMethod {
    pub parser_unit_id: String,
    pub symbol_name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub source_sha256: String,
    pub is_exported: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2PublicSurfaceCoverage {
    Complete,
    UnsupportedLanguage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2SourcePublicSymbolKind {
    CompilerDefined,
    Callable,
    Method,
    Type,
    Module,
    Field,
    Variable,
    Constant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2SourcePublicBindingKind {
    Definition,
    Reference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2SourcePublicReexportKind {
    Wildcard,
    Namespace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2SourcePublicNamespace {
    Module,
    InstanceMember,
    StaticMember,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SourceByteRange {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SourcePosition {
    pub line_zero_based: u32,
    pub character_zero_based: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SourcePositionRange {
    pub start: HistoricalV2SourcePosition,
    pub end: HistoricalV2SourcePosition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SourceIdentifierPositions {
    pub utf8: HistoricalV2SourcePositionRange,
    pub utf16: HistoricalV2SourcePositionRange,
    pub utf32: HistoricalV2SourcePositionRange,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SourcePublicDeclaration {
    pub surface_unit_id: String,
    pub declaration_unit_id: String,
    pub name: String,
    pub target_name: String,
    pub owner: Option<String>,
    pub namespace: HistoricalV2SourcePublicNamespace,
    pub kind: HistoricalV2SourcePublicSymbolKind,
    pub binding: HistoricalV2SourcePublicBindingKind,
    pub source_module: Option<String>,
    pub exposed_identifier: HistoricalV2SourceByteRange,
    pub exposed_identifier_positions: HistoricalV2SourceIdentifierPositions,
    pub identifier: HistoricalV2SourceByteRange,
    pub identifier_positions: HistoricalV2SourceIdentifierPositions,
    pub owner_identifier: Option<HistoricalV2SourceByteRange>,
    pub owner_identifier_positions: Option<HistoricalV2SourceIdentifierPositions>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SourcePublicReexport {
    pub reexport_unit_id: String,
    pub kind: HistoricalV2SourcePublicReexportKind,
    pub name: Option<String>,
    pub source_module: String,
    pub directive: HistoricalV2SourceByteRange,
    pub exposed_identifier: Option<HistoricalV2SourceByteRange>,
    pub identifier: HistoricalV2SourceByteRange,
    pub identifier_positions: HistoricalV2SourceIdentifierPositions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SourceFile {
    pub repository_path: String,
    pub object_id: String,
    pub byte_length: u64,
    pub source_sha256: String,
    pub non_whitespace_lines: usize,
    pub language: String,
    pub semantic_coverage: HistoricalV2SourceSemanticCoverage,
    pub methods: Vec<HistoricalV2SourceMethod>,
    pub public_surface_coverage: HistoricalV2PublicSurfaceCoverage,
    pub public_declarations: Vec<HistoricalV2SourcePublicDeclaration>,
    pub public_reexports: Vec<HistoricalV2SourcePublicReexport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SourceSnapshotCensus {
    pub revision: String,
    pub inventory_sha256: String,
    pub parser_census_sha256: String,
    pub cargo_project_model: IntentionalBoundaryProjectModelCensus,
    pub node_package_surfaces: HistoricalV2NodePackageSurfaceCensus,
    pub tracked_entry_count: usize,
    pub source_files: Vec<HistoricalV2SourceFile>,
    pub source_file_count: usize,
    pub method_counts_by_language: BTreeMap<String, usize>,
    pub method_count: usize,
    pub public_declaration_count: usize,
    pub public_reexport_count: usize,
    pub snapshot_census_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SourceCensus {
    pub schema_version: u32,
    pub source_census_contract: String,
    pub canonical_repository: String,
    pub materialization_sha256: String,
    pub base: HistoricalV2SourceSnapshotCensus,
    pub patched: HistoricalV2SourceSnapshotCensus,
    pub source_census_sha256: String,
}
