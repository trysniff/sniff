use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const PUBLIC_ID_CENSUS_V2_POLICY_SCHEMA_VERSION: u32 = 2;
pub const PUBLIC_ID_CENSUS_V2_PUBLIC_POLICY_SHA256: &str =
    "af2c32c07def15853bf5c57231c3f362fcba5d0ba8c82e73db0b0a8021e94019";

const PUBLIC_POLICY: &str = include_str!("../sniffbench/historical-v3-id-census-v2/policy.json");

#[path = "benchmark_public_id_census_v2_replay.rs"]
mod replay;

pub use replay::*;

#[path = "benchmark_public_id_census_v2_manifest.rs"]
mod manifest;

pub use manifest::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIdCensusV2Policy {
    pub schema_version: u32,
    pub census_id: String,
    pub source: String,
    pub metadata_source: String,
    pub api_version: String,
    pub rest_request_rule: String,
    pub graphql_request_rule: String,
    pub auth_scope: String,
    pub created_at_or_after_utc: String,
    pub created_before_utc: String,
    pub repository_created_after_utc: String,
    pub languages: Vec<String>,
    pub rest_page_size: usize,
    pub graphql_batch_size: usize,
    pub include_forks: bool,
    pub include_archived: bool,
    pub include_mirrors: bool,
    pub include_templates: bool,
    pub require_public_at_enrichment: bool,
    pub start_rule: String,
    pub stop_rule: String,
    pub ordering: String,
    pub ordering_assumption: String,
    pub population: String,
    pub metadata_rule: String,
    pub name_rule: String,
    pub eligibility_rule: String,
    pub missing_metadata_rule: String,
    pub null_audit_rule: String,
    pub pagination_error_rule: String,
    pub artifact_rule: String,
    pub source_failure_rule: String,
    pub transport_retry_rule: String,
    pub prior_identity_rule: String,
    pub precommit_rule: String,
    pub frame_ids: BTreeMap<String, String>,
    pub attestation: String,
}

fn public_policy_bytes() -> Vec<u8> {
    PUBLIC_POLICY.replace("\r\n", "\n").into_bytes()
}

pub fn committed_public_id_census_v2_policy() -> Result<PublicIdCensusV2Policy, String> {
    let bytes = public_policy_bytes();
    if format!("{:x}", Sha256::digest(&bytes)) != PUBLIC_ID_CENSUS_V2_PUBLIC_POLICY_SHA256 {
        return Err("public-ID census v2 policy bytes differ from the pinned hash".to_string());
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid public-ID census v2 policy: {error}"))
}

pub fn validate_public_id_census_v2_policy(policy: &PublicIdCensusV2Policy) -> Result<(), String> {
    if policy.schema_version != PUBLIC_ID_CENSUS_V2_POLICY_SCHEMA_VERSION
        || *policy != committed_public_id_census_v2_policy()?
    {
        return Err("public-ID census v2 policy differs from the committed contract".to_string());
    }
    Ok(())
}

pub fn public_id_census_v2_policy_sha256(
    policy: &PublicIdCensusV2Policy,
) -> Result<String, String> {
    validate_public_id_census_v2_policy(policy)?;
    let bytes = serde_json::to_vec(policy)
        .map_err(|error| format!("failed to serialize public-ID census v2 policy: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_v2_policy_is_typed_and_pinned() {
        let policy = committed_public_id_census_v2_policy().unwrap();
        validate_public_id_census_v2_policy(&policy).unwrap();
        assert_eq!(policy.schema_version, 2);
        assert_eq!(policy.languages.len(), 6);
        assert_eq!(policy.frame_ids.len(), 6);
        assert_eq!(policy.created_at_or_after_utc, "2026-08-08T00:00:00Z");
        assert_eq!(policy.created_before_utc, "2026-08-15T00:00:00Z");
        assert_eq!(
            public_id_census_v2_policy_sha256(&policy).unwrap().len(),
            64
        );
    }

    #[test]
    fn public_v2_policy_rejects_any_amendment_or_unknown_field() {
        let mut policy = committed_public_id_census_v2_policy().unwrap();
        policy.population = "all REST-listed repositories".to_string();
        assert!(validate_public_id_census_v2_policy(&policy).is_err());
        let mut value: serde_json::Value = serde_json::from_str(PUBLIC_POLICY).unwrap();
        value["allow_search_fallback"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<PublicIdCensusV2Policy>(value).is_err());
    }
}
