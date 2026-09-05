use super::IntentionalBoundarySemanticRange;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const HISTORICAL_V2_NODE_PACKAGE_SURFACE_CENSUS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2NodePackageEntryKind {
    Exports,
    Main,
    Module,
    Types,
    Typings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2NodePackageTargetStatus {
    TrackedRegularFile,
    MissingFromInventory,
    NotRegularFile,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2NodePackageCondition {
    pub name: String,
    pub ordinal: usize,
    pub location: IntentionalBoundarySemanticRange,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2NodePackageExposure {
    pub exposure_id: String,
    pub manifest_repository_path: String,
    pub manifest_object_id: String,
    pub package_name: Option<String>,
    pub entry_kind: HistoricalV2NodePackageEntryKind,
    pub public_subpath: String,
    pub public_subpath_location: IntentionalBoundarySemanticRange,
    pub conditions: Vec<HistoricalV2NodePackageCondition>,
    pub fallback_indices: Vec<usize>,
    pub target_repository_path: String,
    pub target_location: IntentionalBoundarySemanticRange,
    pub target_status: HistoricalV2NodePackageTargetStatus,
    pub target_object_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2NodePackageDocument {
    pub manifest_repository_path: String,
    pub manifest_object_id: String,
    pub source_sha256: String,
    pub package_name: Option<String>,
    pub private: bool,
    pub has_exports: bool,
    pub exposure_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2NodePackageSurfaceCensus {
    pub schema_version: u32,
    pub contract: String,
    pub repository: String,
    pub revision: String,
    pub inventory_sha256: String,
    pub documents: Vec<HistoricalV2NodePackageDocument>,
    pub exposures: Vec<HistoricalV2NodePackageExposure>,
    pub exposure_count_by_entry_kind: BTreeMap<HistoricalV2NodePackageEntryKind, usize>,
    pub census_sha256: String,
}
