use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const HISTORICAL_V2_MATERIALIZATION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2Materialization {
    pub schema_version: u32,
    pub materialization_contract: String,
    pub canonical_repository: String,
    pub base_revision: String,
    pub object_format: String,
    pub base_tree_oid: String,
    pub historical_patch_sha256: String,
    pub patched_tree_oid: String,
    pub patched_commit_oid: String,
    pub materialization_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalV2MaterializedRoots {
    pub repository_root: PathBuf,
    pub base_root: PathBuf,
    pub patched_root: PathBuf,
}
