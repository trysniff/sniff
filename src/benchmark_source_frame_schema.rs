use super::json_sha256;
use serde::{Deserialize, Serialize};

pub const SOURCE_FRAME_COLLECTION_POLICY_SCHEMA_VERSION: u32 = 1;
pub const SOURCE_FRAME_COLLECTION_MANIFEST_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFrameCollectionPolicy {
    pub schema_version: u32,
    pub frame_id: String,
    pub source: String,
    pub api_version: String,
    pub language: String,
    pub created_day_utc: String,
    pub derivation_seed: String,
    pub derivation_period_start_utc: String,
    pub derivation_period_days: usize,
    pub derivation_rule: String,
    pub partition: String,
    pub include_forks: bool,
    pub include_archived: bool,
    pub include_mirrors: bool,
    pub include_templates: bool,
    pub ordering: String,
    pub attestation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFrameRawPage {
    pub query: String,
    pub page: usize,
    pub per_page: usize,
    pub response_sha256: String,
    pub response: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFramePageCommitment {
    pub query: String,
    pub page: usize,
    pub artifact_path: String,
    pub artifact_sha256: String,
    pub response_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFrameCollectionManifest {
    pub schema_version: u32,
    pub policy: SourceFrameCollectionPolicy,
    pub policy_sha256: String,
    pub frame_sha256: String,
    pub repository_count: usize,
    pub pages: Vec<SourceFramePageCommitment>,
    pub manifest_sha256: String,
}

impl SourceFrameCollectionManifest {
    pub fn computed_manifest_sha256(&self) -> Result<String, String> {
        #[derive(Serialize)]
        struct Commitment<'a> {
            schema_version: u32,
            policy: &'a SourceFrameCollectionPolicy,
            policy_sha256: &'a str,
            frame_sha256: &'a str,
            repository_count: usize,
            pages: &'a [SourceFramePageCommitment],
        }
        json_sha256(&Commitment {
            schema_version: self.schema_version,
            policy: &self.policy,
            policy_sha256: &self.policy_sha256,
            frame_sha256: &self.frame_sha256,
            repository_count: self.repository_count,
            pages: &self.pages,
        })
    }
}
