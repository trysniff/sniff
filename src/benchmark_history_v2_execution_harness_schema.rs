use serde::{Deserialize, Serialize};

pub const HISTORICAL_V2_EXECUTION_HARNESS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2ExecutionBaseImage {
    pub base_image_name: String,
    pub languages: Vec<String>,
    pub dockerfile_path: String,
    pub git_blob_oid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2ExecutionHarness {
    pub schema_version: u32,
    pub execution_harness_contract: String,
    pub upstream_repository: String,
    pub upstream_revision: String,
    pub base_dockerfiles_tree_oid: String,
    pub execution_platform: String,
    pub install_network_enabled: bool,
    pub test_network_enabled: bool,
    pub dataset_labels_forbidden: bool,
    pub install_failures_are_terminal: bool,
    pub supported_images: Vec<HistoricalV2ExecutionBaseImage>,
    pub execution_harness_sha256: String,
}
