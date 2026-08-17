use super::{BoundaryGitEntryKind, HistoricalRevisionSide, HistoricalV2ExecutionCommandEvidence};
use serde::{Deserialize, Serialize};

pub const HISTORICAL_V2_SOURCE_REVIEW_BUNDLE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalV2ReviewSnapshotSide {
    Before,
    After,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2ReviewSourceArtifact {
    pub repository_path: String,
    pub mode: String,
    pub kind: BoundaryGitEntryKind,
    pub object_id: String,
    pub byte_length: Option<u64>,
    pub artifact_path: Option<String>,
    pub content_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2ReviewSourceSnapshot {
    pub side: HistoricalV2ReviewSnapshotSide,
    pub revision: String,
    pub tree_oid: String,
    pub inventory_sha256: String,
    pub source_snapshot_sha256: String,
    pub tracked_entry_count: usize,
    pub artifacts: Vec<HistoricalV2ReviewSourceArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2ReviewChangedMethod {
    pub side: HistoricalRevisionSide,
    pub language: String,
    pub repository_path: String,
    pub symbol_name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub source_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2ReviewBehaviorEvidence {
    pub test_plan_sha256: String,
    pub execution_sha256: String,
    pub events: Vec<HistoricalV2ExecutionCommandEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV2SourceReviewBundle {
    pub schema_version: u32,
    pub bundle_contract: String,
    pub protocol_sha256: String,
    pub selection_sha256: String,
    pub assessment_identity_sha256: String,
    pub terminal_checkpoint_sha256: String,
    pub review_item_id: String,
    pub language: String,
    pub source_only: bool,
    pub sniff_output_included: bool,
    pub dataset_judgments_included: bool,
    pub public_surface_preserved: bool,
    pub public_surface_delta_sha256: String,
    pub snapshots: Vec<HistoricalV2ReviewSourceSnapshot>,
    pub changed_methods: Vec<HistoricalV2ReviewChangedMethod>,
    pub behavior: HistoricalV2ReviewBehaviorEvidence,
    pub bundle_sha256: String,
}
