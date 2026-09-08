use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const HISTORICAL_V2_NODE_CONSUMER_PROFILE_CENSUS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2NodeConsumerMode {
    Import,
    Require,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2TypeScriptModuleResolution {
    Classic,
    Node10,
    Node16,
    NodeNext,
    Bundler,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2NodeConsumerUnresolvedReason {
    MissingPackageName,
    NoOwningCompilerProject,
    UnsupportedCompilerModuleResolution,
    CompilerResolutionFailed,
    CompilerBranchAmbiguous,
    CompilerTargetOutsidePackage,
    CompilerTargetNotTrackedSource,
    RuntimeResolutionFailed,
    RuntimeBranchAmbiguous,
    RuntimeTargetOutsidePackage,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV2NodeConsumerResolution {
    Resolved {
        selected_exposure_id: String,
        selected_surface_slot_id: String,
        declared_target_repository_path: String,
        resolved_repository_path: String,
        resolved_object_id: Option<String>,
        compiler_source_substitution: bool,
        evidence_sha256: String,
    },
    Unresolved {
        reason: HistoricalV2NodeConsumerUnresolvedReason,
        evidence_sha256: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2NodeConsumerProfile {
    pub profile_id: String,
    pub consumer_surface_slot_id: String,
    pub manifest_repository_path: String,
    pub manifest_object_id: String,
    pub package_name: Option<String>,
    pub public_subpath: String,
    pub specifier: Option<String>,
    pub mode: HistoricalV2NodeConsumerMode,
    pub project_model_execution_id: Option<String>,
    pub compiler_project_config_repository_path: Option<String>,
    pub compiler_options_sha256: Option<String>,
    pub toolchain_identity_sha256: Option<String>,
    pub compiler_module_resolution: Option<HistoricalV2TypeScriptModuleResolution>,
    pub compiler_conditions: Vec<String>,
    pub custom_conditions: Vec<String>,
    pub declared_exposure_ids: Vec<String>,
    pub compiler: HistoricalV2NodeConsumerResolution,
    pub runtime: HistoricalV2NodeConsumerResolution,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2NodeConsumerProfileCensus {
    pub schema_version: u32,
    pub contract: String,
    pub repository: String,
    pub revision: String,
    pub inventory_sha256: String,
    pub node_package_surface_census_sha256: String,
    pub typescript_project_model_census_sha256: String,
    pub typescript_compiler_version: Option<String>,
    pub node_runtime_version: Option<String>,
    pub node_runtime_sha256: Option<String>,
    pub profiles: Vec<HistoricalV2NodeConsumerProfile>,
    pub profile_count_by_mode: BTreeMap<HistoricalV2NodeConsumerMode, usize>,
    pub unresolved_resolution_count: usize,
    pub census_sha256: String,
}
