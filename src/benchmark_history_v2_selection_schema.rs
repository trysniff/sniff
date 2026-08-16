use serde::{Deserialize, Serialize};

pub const HISTORICAL_V2_EXCLUSION_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const HISTORICAL_V2_SLOT_SELECTION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2ExclusionArtifact {
    pub artifact_path: String,
    pub artifact_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2PartitionExclusions {
    pub partition: String,
    pub artifacts: Vec<HistoricalV2ExclusionArtifact>,
    pub repositories: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2ExclusionManifest {
    pub schema_version: u32,
    pub protocol_sha256: String,
    pub partitions: Vec<HistoricalV2PartitionExclusions>,
    pub repository_count: usize,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV2CandidateOutcome {
    Selected { slot_number: usize },
    ExcludedPartition { partitions: Vec<String> },
    RepositoryAlreadySelected { selected_global_row_index: usize },
    LanguageSlotsFilled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2CandidateDecision {
    pub global_rank: usize,
    pub global_row_index: usize,
    pub instance_id: String,
    pub canonical_repository: String,
    pub pull_number: u64,
    pub base_revision: String,
    pub patch_sha256: String,
    pub language: String,
    pub rank_sha256: String,
    pub outcome: HistoricalV2CandidateOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV2SlotOutcome {
    Selected {
        global_row_index: usize,
        instance_id: String,
        canonical_repository: String,
        pull_number: u64,
        base_revision: String,
        patch_sha256: String,
        rank_sha256: String,
    },
    Unfilled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2Slot {
    pub language: String,
    pub slot_number: usize,
    pub outcome: HistoricalV2SlotOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SlotSelection {
    pub schema_version: u32,
    pub selection_contract: String,
    pub protocol_sha256: String,
    pub frame_sha256: String,
    pub exclusion_manifest_sha256: String,
    pub ranking_seed: String,
    pub ranking_contract: String,
    pub slots_per_language: usize,
    pub candidate_decisions: Vec<HistoricalV2CandidateDecision>,
    pub slots: Vec<HistoricalV2Slot>,
    pub selected_count: usize,
    pub unfilled_slot_count: usize,
    pub excluded_partition_count: usize,
    pub repository_collision_count: usize,
    pub language_capacity_count: usize,
    pub selection_sha256: String,
}
