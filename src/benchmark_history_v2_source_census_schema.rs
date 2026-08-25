use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const HISTORICAL_V2_SOURCE_CENSUS_SCHEMA_VERSION: u32 = 2;

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
