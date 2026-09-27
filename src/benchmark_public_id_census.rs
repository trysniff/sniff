use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const PUBLIC_ID_CENSUS_POLICY_SCHEMA_VERSION: u32 = 1;
pub const PUBLIC_ID_CENSUS_PUBLIC_POLICY_SHA256: &str =
    "9ab97d4dc42f4904052678d68cb36855a28197fb7973870a1534454995f2aa50";

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
    Ok(PublicIdCensusPolicy {
        schema_version: 1,
        census_id: "historical-v3-post-aug7-public-id-census-v1".to_string(),
        source: "https://api.github.com/repositories".to_string(),
        metadata_source: "https://api.github.com/graphql".to_string(),
        api_version: "2022-11-28".to_string(),
        rest_request_rule: "GET /repositories?per_page=100&since=<cursor>;application/vnd.github+json;follow_verified_rel_next_since".to_string(),
        graphql_request_rule: "POST /graphql nodes(ids:[ID!]!) in REST page order;id databaseId nameWithOwner createdAt primaryLanguage.name isArchived isFork isTemplate mirrorUrl isPrivate".to_string(),
        auth_scope: "public_repository_metadata_only;reject_graphql_isPrivate_true".to_string(),
        created_at_or_after_utc: "2026-08-08T00:00:00Z".to_string(),
        created_before_utc: "2026-08-15T00:00:00Z".to_string(),
        repository_created_after_utc: "2026-08-07T20:46:11Z".to_string(),
        languages: ["Go", "JavaScript", "Kotlin", "Python", "Rust", "TypeScript"]
            .map(str::to_string)
            .to_vec(),
        rest_page_size: 100,
        graphql_batch_size: 100,
        include_forks: false,
        include_archived: false,
        include_mirrors: false,
        include_templates: false,
        require_public_at_enrichment: true,
        start_rule: "binary_search_first_public_repository_at_or_after_start_then_retain_preceding_boundary".to_string(),
        stop_rule: "retain_first_page_crossing_created_before_utc".to_string(),
        ordering: "github_repository_id_ascending_with_nondecreasing_created_at".to_string(),
        ordering_assumption: "github_public_repository_list_is_in_creation_order_as_documented;observed_inversion_fails_closed;live_visibility_changes_are_not_an_atomic_snapshot".to_string(),
        population: "public_at_rest_listing_and_public_at_graphql_enrichment_observation_not_historical_snapshot".to_string(),
        metadata_rule: "single_graphql_observation_per_rest_id;node_id_and_database_id_must_match;graphql_name_and_primary_language_authoritative".to_string(),
        name_rule: "canonical_lowercase_github.com_owner_repository_from_graphql_nameWithOwner".to_string(),
        eligibility_rule: "created_at_in_window_and_after_cutoff;exclude_forks_archived_mirrors_templates;exact_primary_language_match".to_string(),
        missing_metadata_rule: "fail_closed_without_frame".to_string(),
        pagination_error_rule: "fail_closed_without_frame".to_string(),
        source_failure_rule: "fail_closed_without_search_fallback".to_string(),
        transport_retry_rule: "retry_only_transport_timeout_429_or_5xx_with_same_request;retain_attempts;stop_after_12_failed_attempts".to_string(),
        prior_identity_rule: "strict_created_at_after_2026-08-07T20:46:11Z_is_prior_cohort_disjointness_proof;name_filter_is_conservative_only".to_string(),
        precommit_rule: "before_first_rest_probe_fetch_immutable_public_git_policy_url;verify_exact_bytes_and_sha256_against_pinned_public_hash_and_typed_contract;retain_preflight_receipt".to_string(),
        frame_ids: BTreeMap::from([
            ("Go".to_string(), "historical-v3-post-aug7-id-census-go".to_string()),
            ("JavaScript".to_string(), "historical-v3-post-aug7-id-census-javascript".to_string()),
            ("Kotlin".to_string(), "historical-v3-post-aug7-id-census-kotlin".to_string()),
            ("Python".to_string(), "historical-v3-post-aug7-id-census-python".to_string()),
            ("Rust".to_string(), "historical-v3-post-aug7-id-census-rust".to_string()),
            ("TypeScript".to_string(), "historical-v3-post-aug7-id-census-typescript".to_string()),
        ]),
        attestation: "Must be committed publicly before collecting this census or inspecting candidate identities, labels, or Sniff output. The six frames share one live, non-atomic public-ID traversal. No Search-derived frame or partial checkpoint is substituted.".to_string(),
    })
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
        let mut value = serde_json::to_value(committed_public_id_census_policy().unwrap()).unwrap();
        value["allow_search_fallback"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<PublicIdCensusPolicy>(value).is_err());
    }

    #[test]
    fn repository_public_policy_matches_the_typed_contract() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("sniffbench/historical-v3-id-census/policy.json");
        if !path.is_file() {
            return;
        }
        let bytes = std::fs::read(path).unwrap();
        let public: PublicIdCensusPolicy = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(public, committed_public_id_census_policy().unwrap());
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            PUBLIC_ID_CENSUS_PUBLIC_POLICY_SHA256
        );
    }
}
