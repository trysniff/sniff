use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const PUBLIC_ID_CENSUS_POLICY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIdCensusPolicy {
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
    pub pagination_error_rule: String,
    pub source_failure_rule: String,
    pub transport_retry_rule: String,
    pub prior_identity_rule: String,
    pub precommit_rule: String,
    pub frame_ids: BTreeMap<String, String>,
    pub attestation: String,
}

pub fn committed_public_id_census_policy() -> Result<PublicIdCensusPolicy, String> {
    serde_json::from_str(include_str!(
        "../sniffbench/historical-v3-id-census/policy.json"
    ))
    .map_err(|error| format!("invalid committed public-ID census policy: {error}"))
}

pub fn validate_public_id_census_policy(policy: &PublicIdCensusPolicy) -> Result<(), String> {
    if policy.schema_version != PUBLIC_ID_CENSUS_POLICY_SCHEMA_VERSION
        || *policy != committed_public_id_census_policy()?
    {
        return Err("public-ID census policy differs from the committed contract".to_string());
    }
    Ok(())
}

pub fn public_id_census_policy_sha256(policy: &PublicIdCensusPolicy) -> Result<String, String> {
    validate_public_id_census_policy(policy)?;
    let bytes = serde_json::to_vec(policy)
        .map_err(|error| format!("failed to serialize public-ID census policy: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_policy_fixes_one_six_language_post_august_census() {
        let policy = committed_public_id_census_policy().unwrap();
        validate_public_id_census_policy(&policy).unwrap();
        assert_eq!(policy.created_at_or_after_utc, "2026-08-08T00:00:00Z");
        assert_eq!(policy.created_before_utc, "2026-08-15T00:00:00Z");
        assert_eq!(policy.repository_created_after_utc, "2026-08-07T20:46:11Z");
        assert_eq!(policy.languages.len(), 6);
        assert_eq!(policy.frame_ids.len(), 6);
        assert!(!policy.include_forks);
        assert!(!policy.include_archived);
        assert!(!policy.include_mirrors);
        assert!(!policy.include_templates);
        assert!(policy.require_public_at_enrichment);
        assert!(
            policy
                .languages
                .iter()
                .all(|language| policy.frame_ids.contains_key(language))
        );
        assert_eq!(public_id_census_policy_sha256(&policy).unwrap().len(), 64);
    }

    #[test]
    fn changing_source_or_cutoff_is_not_a_valid_amendment() {
        let mut policy = committed_public_id_census_policy().unwrap();
        policy.source = "https://api.github.com/search/repositories".to_string();
        assert!(validate_public_id_census_policy(&policy).is_err());
        policy = committed_public_id_census_policy().unwrap();
        policy.repository_created_after_utc = "2026-08-07T00:00:00Z".to_string();
        assert!(validate_public_id_census_policy(&policy).is_err());
    }

    #[test]
    fn unknown_policy_fields_are_rejected() {
        let mut value: serde_json::Value = serde_json::from_str(include_str!(
            "../sniffbench/historical-v3-id-census/policy.json"
        ))
        .unwrap();
        value["allow_search_fallback"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<PublicIdCensusPolicy>(value).is_err());
    }
}
