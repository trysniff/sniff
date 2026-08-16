use serde::{Deserialize, Serialize};

pub const HISTORICAL_V2_SELECTED_PAYLOADS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SelectedPayload {
    pub language: String,
    pub slot_number: usize,
    pub source_shard_index: usize,
    pub source_row_index: usize,
    pub global_row_index: usize,
    pub instance_id: String,
    pub patch: String,
    pub patch_sha256: String,
    pub install_config: Option<String>,
    pub install_config_sha256: Option<String>,
    pub test_patch: Option<String>,
    pub test_patch_sha256: Option<String>,
    pub payload_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SelectedPayloads {
    pub schema_version: u32,
    pub payload_contract: String,
    pub protocol_sha256: String,
    pub frame_sha256: String,
    pub exclusion_manifest_sha256: String,
    pub selection_sha256: String,
    pub selected_count: usize,
    pub records: Vec<HistoricalV2SelectedPayload>,
    pub payloads_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(feature = "sniffbench-frame")]
pub(super) struct HistoricalV2ProjectedPayloadRow {
    pub(super) source_shard_index: usize,
    pub(super) source_row_index: usize,
    pub(super) global_row_index: usize,
    pub(super) instance_id: String,
    pub(super) patch: String,
    pub(super) install_config: Option<String>,
    pub(super) test_patch: Option<String>,
}
