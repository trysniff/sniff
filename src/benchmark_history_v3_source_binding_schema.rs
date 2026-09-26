use super::HistoricalV3Language;
use serde::{Deserialize, Serialize};

pub const HISTORICAL_V3_PRIOR_IDENTITY_SEAL_SCHEMA_VERSION: u32 = 1;
pub const HISTORICAL_V3_SOURCE_BINDING_AUDIT_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3PriorArtifactBinding {
    pub artifact_id: String,
    pub artifact_sha256: String,
    pub repositories: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3PriorBenchmarkIdentitySeal {
    pub schema_version: u32,
    pub seal_contract: String,
    pub inputs: Vec<HistoricalV3PriorArtifactBinding>,
    pub repositories: Vec<String>,
    pub seal_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3BoundSourceFrame {
    pub language: HistoricalV3Language,
    pub frame_id: String,
    pub repository_count: usize,
    pub eligible_repository_count: usize,
    pub excluded_prior_repository_count: usize,
    pub eligible_repositories_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3SourceBindingAudit {
    pub schema_version: u32,
    pub audit_contract: String,
    pub protocol_sha256: String,
    pub prior_benchmark_identity_seal_sha256: String,
    pub frames: Vec<HistoricalV3BoundSourceFrame>,
    pub audit_sha256: String,
}
