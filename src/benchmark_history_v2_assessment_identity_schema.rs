use serde::{Deserialize, Serialize};

pub const HISTORICAL_V2_ASSESSMENT_IDENTITY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2AssessmentIdentity {
    pub schema_version: u32,
    pub assessment_identity_contract: String,
    pub protocol_sha256: String,
    pub frame_sha256: String,
    pub exclusion_manifest_sha256: String,
    pub selection_sha256: String,
    pub payloads_sha256: String,
    pub language: String,
    pub slot_number: usize,
    pub global_row_index: usize,
    pub instance_id: String,
    pub canonical_repository: String,
    pub pull_number: u64,
    pub base_revision: String,
    pub rank_sha256: String,
    pub payload_sha256: String,
    pub historical_patch_sha256: String,
    pub install_config_sha256: Option<String>,
    pub test_patch_sha256: Option<String>,
    pub materialization_sha256: String,
    pub test_materialization_sha256: Option<String>,
    pub source_census_sha256: String,
    pub base_source_snapshot_sha256: String,
    pub patched_source_snapshot_sha256: String,
    pub semantic_census_sha256: String,
    pub base_semantic_snapshot_sha256: String,
    pub patched_semantic_snapshot_sha256: String,
    pub assessment_identity_sha256: String,
}
