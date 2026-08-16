use super::HistoricalV2SelectedPayload;
use serde::{Deserialize, Serialize};

pub const HISTORICAL_V2_STAGE_ARTIFACT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SelectedSlotPayloadArtifact {
    pub schema_version: u32,
    pub artifact_contract: String,
    pub selection_sha256: String,
    pub language: String,
    pub slot_number: usize,
    pub global_row_index: usize,
    pub instance_id: String,
    pub canonical_repository: String,
    pub pull_number: u64,
    pub base_revision: String,
    pub rank_sha256: String,
    pub payload: HistoricalV2SelectedPayload,
    pub artifact_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2NoTestPatchArtifact {
    pub schema_version: u32,
    pub artifact_contract: String,
    pub selected_slot_payload_sha256: String,
    pub materialization_sha256: String,
    pub language: String,
    pub slot_number: usize,
    pub canonical_repository: String,
    pub artifact_sha256: String,
}
