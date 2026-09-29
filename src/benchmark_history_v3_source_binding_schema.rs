use super::{HistoricalV3Language, HistoricalV3SourceKind};
use serde::{Deserialize, Serialize};

pub const HISTORICAL_V3_PRIOR_IDENTITY_SEAL_SCHEMA_VERSION: u32 = 1;
pub const HISTORICAL_V3_SOURCE_BINDING_AUDIT_SCHEMA_VERSION: u32 = 2;
pub const HISTORICAL_V3_PUBLIC_ID_CENSUS_AUDIT_SCHEMA_VERSION: u32 = 3;
pub const HISTORICAL_V3_PUBLIC_ID_CENSUS_V2_AUDIT_SCHEMA_VERSION: u32 = 4;

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
pub struct HistoricalV3ResolvablePopulationAudit {
    pub listed_repository_count: usize,
    pub resolved_in_window_count: usize,
    pub resolved_ineligible_count: usize,
    pub probe_only_null_count: usize,
    pub crawled_null_count: usize,
    pub name_disagreement_count: usize,
    pub null_ledger_artifact_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3SourceBindingAudit {
    pub schema_version: u32,
    pub audit_contract: String,
    pub protocol_sha256: String,
    pub prior_benchmark_identity_seal_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_kind: Option<HistoricalV3SourceKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_manifest_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolvable_population: Option<HistoricalV3ResolvablePopulationAudit>,
    pub frames: Vec<HistoricalV3BoundSourceFrame>,
    pub audit_sha256: String,
}
