use super::{HistoricalV3CandidateIdentity, HistoricalV3Language, HistoricalV3StreamTask};
use serde::{Deserialize, Serialize};

pub const HISTORICAL_V3_CANDIDATE_REQUEST_SCHEMA_VERSION: u32 = 1;
pub const HISTORICAL_V3_CANDIDATE_CHECKPOINT_SCHEMA_VERSION: u32 = 1;
pub const HISTORICAL_V3_CANDIDATE_MANIFEST_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3CandidateRepository {
    pub language: HistoricalV3Language,
    pub repository_id: u64,
    pub name_with_owner: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3CandidatePartition {
    pub language: HistoricalV3Language,
    pub repository_id: u64,
    pub name_with_owner: String,
    pub path: String,
    pub merged_at_or_after_utc: String,
    pub merged_at_or_before_utc: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3CandidatePageRequest {
    pub schema_version: u32,
    pub request_contract: String,
    pub protocol_sha256: String,
    pub source_binding_audit_sha256: String,
    pub query_document_sha256: String,
    pub partition: HistoricalV3CandidatePartition,
    pub page_number: usize,
    pub after_cursor: Option<String>,
    pub request_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3CandidatePageCheckpoint {
    pub schema_version: u32,
    pub checkpoint_contract: String,
    pub request: HistoricalV3CandidatePageRequest,
    pub response_sha256: String,
    pub response_base64: String,
    pub checkpoint_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoricalV3CandidatePartitionRecord {
    Split {
        partition: HistoricalV3CandidatePartition,
        issue_count: usize,
        probe_request_sha256: String,
        left: Box<HistoricalV3CandidatePartition>,
        right: Box<HistoricalV3CandidatePartition>,
    },
    Complete {
        partition: HistoricalV3CandidatePartition,
        issue_count: usize,
        candidate_count: usize,
        page_request_sha256s: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3CandidateCollectionManifest {
    pub schema_version: u32,
    pub manifest_contract: String,
    pub protocol_sha256: String,
    pub source_binding_audit_sha256: String,
    pub query_document_sha256: String,
    pub repositories: Vec<HistoricalV3CandidateRepository>,
    pub partitions: Vec<HistoricalV3CandidatePartitionRecord>,
    pub page_checkpoint_sha256s: Vec<String>,
    pub candidate_count: usize,
    pub stream_task: HistoricalV3StreamTask,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalV3CandidateCollection {
    pub manifest: HistoricalV3CandidateCollectionManifest,
    pub candidates: Vec<HistoricalV3CandidateIdentity>,
}
