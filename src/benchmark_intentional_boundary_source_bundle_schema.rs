use super::BoundaryGitEntryKind;
use serde::{Deserialize, Serialize};

pub const INTENTIONAL_BOUNDARY_SOURCE_BUNDLE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySourceArtifact {
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
pub struct IntentionalBoundarySourceRepository {
    pub source_repository_id: String,
    pub repository: String,
    pub revision: String,
    pub inventory_sha256: String,
    pub source_census_sha256: String,
    pub tracked_entry_count: usize,
    pub artifacts: Vec<IntentionalBoundarySourceArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySourceReviewItem {
    pub review_item_id: String,
    pub source_repository_id: String,
    pub repository: String,
    pub revision: String,
    pub repository_path: String,
    pub source_artifact_path: String,
    pub language: String,
    pub symbol_name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub source_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentionalBoundarySourceBundle {
    pub schema_version: u32,
    pub bundle_contract: String,
    pub protocol_sha256: String,
    pub policy_sha256: String,
    pub frame_task_sha256: String,
    pub candidate_frame_sha256: String,
    pub selection_sha256: String,
    pub selected_slot_count: usize,
    pub unfilled_slot_count: usize,
    pub repositories: Vec<IntentionalBoundarySourceRepository>,
    pub review_items: Vec<IntentionalBoundarySourceReviewItem>,
    pub bundle_sha256: String,
}
