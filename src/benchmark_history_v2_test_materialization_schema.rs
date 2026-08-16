use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const HISTORICAL_V2_TEST_MATERIALIZATION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2TestMaterialization {
    pub schema_version: u32,
    pub test_materialization_contract: String,
    pub materialization_sha256: String,
    pub test_patch_sha256: String,
    pub base_input_commit_oid: String,
    pub base_test_tree_oid: String,
    pub base_test_commit_oid: String,
    pub patched_input_commit_oid: String,
    pub patched_test_tree_oid: String,
    pub patched_test_commit_oid: String,
    pub test_materialization_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalV2TestMaterializedRoots {
    pub base_test_root: PathBuf,
    pub patched_test_root: PathBuf,
}
