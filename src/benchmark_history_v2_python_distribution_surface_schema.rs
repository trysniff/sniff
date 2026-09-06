use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const HISTORICAL_V2_PYTHON_DISTRIBUTION_SURFACE_CENSUS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2PythonWheelRoot {
    Purelib,
    Platlib,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2PythonModuleKind {
    SourceModule,
    SourcePackageInit,
    StubModule,
    StubPackageInit,
    NamespacePackage,
    ExtensionModule,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2PythonBuildRequirement {
    pub ordinal: usize,
    pub requirement: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2PythonDistribution {
    pub distribution_id: String,
    pub manifest_repository_path: String,
    pub manifest_object_id: String,
    pub manifest_source_sha256: String,
    pub build_backend: String,
    pub backend_path: Vec<String>,
    pub build_requirements: Vec<HistoricalV2PythonBuildRequirement>,
    pub toolchain_identity_sha256: String,
    pub command_contract: String,
    pub wheel_filename: String,
    pub wheel_sha256: String,
    pub wheel_byte_length: u64,
    pub distribution_name: String,
    pub normalized_distribution_name: String,
    pub distribution_version: String,
    pub wheel_root: HistoricalV2PythonWheelRoot,
    pub metadata_member_path: String,
    pub wheel_metadata_member_path: String,
    pub record_member_path: String,
    pub module_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2PythonDistributionModule {
    pub module_exposure_id: String,
    pub surface_slot_id: String,
    pub distribution_id: String,
    pub normalized_distribution_name: String,
    pub import_name: String,
    pub kind: HistoricalV2PythonModuleKind,
    pub is_distribution_root: bool,
    pub archive_member_path: Option<String>,
    pub installed_path: Option<String>,
    pub member_sha256: Option<String>,
    pub member_byte_length: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2PythonDistributionSurfaceCensus {
    pub schema_version: u32,
    pub contract: String,
    pub repository: String,
    pub revision: String,
    pub inventory_sha256: String,
    pub distributions: Vec<HistoricalV2PythonDistribution>,
    pub modules: Vec<HistoricalV2PythonDistributionModule>,
    pub module_count_by_kind: BTreeMap<HistoricalV2PythonModuleKind, usize>,
    pub census_sha256: String,
}
