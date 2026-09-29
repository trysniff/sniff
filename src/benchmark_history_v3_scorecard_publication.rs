use super::HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC;
use super::history_v3_time::parse_utc_second;
use super::non_blind_history::NonBlindSelectionPolicy;
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const POLICY_SHA256: &str = "43269a234b55ff406edf1893584418d0eefc3a79eada16764c2114fd7f88c44d";
const FRAME_SHA256: &str = "55b1de849d6d401bd6529a2806d587b53170cfbe7cdbc2ac5799ab65bf42807a";
const RESPONSE_SHA256: &str = "339a32a4664a18951e033c4e8babd7d94ddca170e1a59b43e4fe51a586845017";
const FRAME_COMMIT: &str = "40c1e35996730d4fdcbdb2e6a23917a2467e29b7";
const PRE_CUTOFF_HEAD: &str = "61aa2b50d672f3da8e52bfd5dd9f1b77532a7752";
const EVENT_NODE: &str = "HRFPE_lADOEgpjzc71xS6ZzwAAAAbIjjfd";
const SCORECARD_PUBLICATION_CONTRACT: &str =
    "sniffbench-historical-v3-scorecard-frame-publication-v1";

// Reproduce the captured response against https://api.github.com/graphql.
pub const SCORECARD_PUBLICATION_QUERY: &str = "query={ node(id:\"HRFPE_lADOEgpjzc71xS6ZzwAAAAbIjjfd\") { ... on HeadRefForcePushedEvent { id createdAt afterCommit { oid } pullRequest { number repository { nameWithOwner } } } } repository(owner:\"ossf\", name:\"scorecard\") { object(expression:\"61aa2b50d672f3da8e52bfd5dd9f1b77532a7752:cron/internal/data/projects.csv\") { oid } } }";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScorecardFramePublicationWitness {
    pub contract: String,
    pub policy_sha256: String,
    pub frame_sha256: String,
    pub response_sha256: String,
    pub query_sha256: String,
    pub published_at_utc: String,
    pub head_commit: String,
    pub frame_blob_oid: String,
    pub cutoff_utc: String,
    pub witness_sha256: String,
}

/// Proves the Scorecard CSV was present in a GitHub PR head before the cutoff.
/// This does not prove when any repository named inside the CSV was created.
pub fn derive_scorecard_frame_publication_witness(
    policy_bytes: &[u8],
    frame_bytes: &[u8],
    response_bytes: &[u8],
) -> Result<ScorecardFramePublicationWitness, String> {
    if sha256(policy_bytes) != POLICY_SHA256 {
        return Err("Scorecard publication policy differs from the frozen source".to_string());
    }
    if sha256(frame_bytes) != FRAME_SHA256 {
        return Err("Scorecard publication frame differs from the frozen source".to_string());
    }
    if sha256(response_bytes) != RESPONSE_SHA256 {
        return Err(
            "Scorecard publication GraphQL response differs from the captured source".to_string(),
        );
    }
    let policy: NonBlindSelectionPolicy = serde_json::from_slice(policy_bytes)
        .map_err(|error| format!("invalid Scorecard publication policy: {error}"))?;
    let source = &policy.historical_simplification;
    if policy.policy_id != "sniffbench-non-blind-v1"
        || source.sampling_frame_commit != FRAME_COMMIT
        || source.sampling_frame_sha256 != FRAME_SHA256
        || source.sampling_frame_url
            != format!(
                "https://raw.githubusercontent.com/ossf/scorecard/{FRAME_COMMIT}/cron/internal/data/projects.csv"
            )
    {
        return Err("Scorecard publication source does not match the frozen policy".to_string());
    }
    let frame_blob_oid = git_blob_oid(frame_bytes);
    if frame_blob_oid != source.sampling_frame_blob {
        return Err("Scorecard publication frame is not the policy's Git blob".to_string());
    }
    let response: Value = serde_json::from_slice(response_bytes)
        .map_err(|error| format!("invalid Scorecard publication response: {error}"))?;
    let published_at_utc = validate_publication_response(&response, &frame_blob_oid)?;
    let mut witness = ScorecardFramePublicationWitness {
        contract: SCORECARD_PUBLICATION_CONTRACT.to_string(),
        policy_sha256: POLICY_SHA256.to_string(),
        frame_sha256: FRAME_SHA256.to_string(),
        response_sha256: RESPONSE_SHA256.to_string(),
        query_sha256: sha256(SCORECARD_PUBLICATION_QUERY.as_bytes()),
        published_at_utc,
        head_commit: PRE_CUTOFF_HEAD.to_string(),
        frame_blob_oid,
        cutoff_utc: HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC.to_string(),
        witness_sha256: String::new(),
    };
    witness.witness_sha256 = sha256(
        &serde_json::to_vec(&witness)
            .map_err(|error| format!("failed to commit Scorecard publication witness: {error}"))?,
    );
    Ok(witness)
}

pub fn validate_scorecard_frame_publication_witness(
    policy_bytes: &[u8],
    frame_bytes: &[u8],
    response_bytes: &[u8],
    witness: &ScorecardFramePublicationWitness,
) -> Result<(), String> {
    if witness
        != &derive_scorecard_frame_publication_witness(policy_bytes, frame_bytes, response_bytes)?
    {
        return Err("Scorecard frame publication witness does not replay".to_string());
    }
    Ok(())
}

fn validate_publication_response(response: &Value, frame_blob_oid: &str) -> Result<String, String> {
    if response.get("errors").is_some() {
        return Err("Scorecard publication GraphQL response contains errors".to_string());
    }
    let at = |pointer: &str| response.pointer(pointer).and_then(Value::as_str);
    if at("/data/node/id") != Some(EVENT_NODE)
        || at("/data/node/afterCommit/oid") != Some(PRE_CUTOFF_HEAD)
        || response
            .pointer("/data/node/pullRequest/number")
            .and_then(Value::as_u64)
            != Some(4977)
        || at("/data/node/pullRequest/repository/nameWithOwner") != Some("ossf/scorecard")
        || at("/data/repository/object/oid") != Some(frame_blob_oid)
    {
        return Err("Scorecard publication event, PR, head, or frame blob changed".to_string());
    }
    let published_at =
        at("/data/node/createdAt").ok_or("Scorecard publication event timestamp is missing")?;
    if parse_utc_second(published_at)?
        >= parse_utc_second(HISTORICAL_V3_REPOSITORY_CREATED_AFTER_UTC)?
    {
        return Err("Scorecard frame publication is not before the v3 cutoff".to_string());
    }
    Ok(published_at.to_string())
}

fn git_blob_oid(bytes: &[u8]) -> String {
    let mut hasher = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
    hasher.update(format!("blob {}\0", bytes.len()).as_bytes());
    hasher.update(bytes);
    hasher
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "benchmark_history_v3_scorecard_publication_tests.rs"]
mod tests;
