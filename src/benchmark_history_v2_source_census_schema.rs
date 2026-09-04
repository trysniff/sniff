use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const HISTORICAL_V2_SOURCE_CENSUS_SCHEMA_VERSION: u32 = 4;

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
    Callable,
    Method,
    Type,
    Field,
    Variable,
    Constant,
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
    pub owner: Option<String>,
    pub kind: HistoricalV2SourcePublicSymbolKind,
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SourceSnapshotCensus {
    pub revision: String,
    pub inventory_sha256: String,
    pub parser_census_sha256: String,
    pub tracked_entry_count: usize,
    pub source_files: Vec<HistoricalV2SourceFile>,
    pub source_file_count: usize,
    pub method_counts_by_language: BTreeMap<String, usize>,
    pub method_count: usize,
    pub public_declaration_count: usize,
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
