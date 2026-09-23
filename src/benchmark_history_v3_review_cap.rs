use super::history_v2_slot_store_support::{
    read_limited, require_plain_directory, write_compact_json_new,
};
use super::{
    HistoricalV3CandidateCollection, HistoricalV3OrderedRankOutcome, HistoricalV3OrderedStopStatus,
    HistoricalV3Protocol, HistoricalV3RankIdentity, HistoricalV3VerifiedQualification,
    evaluate_historical_v3_ordered_prefix, historical_v3_rank_identity,
    validate_historical_v3_candidate_collection_commitment,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

pub const HISTORICAL_V3_REVIEW_CAP_SCHEMA_VERSION: u32 = 1;
const REVIEW_CAP_CONTRACT: &str = "sniffbench-historical-v3-repository-review-cap-v1";
const REVIEW_CAP_REASON: &str = "repository_review_cap_reached";
const MAX_REVIEW_CAP_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalV3ReviewCapArtifact {
    pub schema_version: u32,
    pub contract: String,
    pub rank: HistoricalV3RankIdentity,
    pub qualification_sha256: String,
    pub prior_reviewable_rank_sha256s: Vec<String>,
    pub reason: String,
    pub cap_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalV3VerifiedReviewCap {
    rank: HistoricalV3RankIdentity,
    qualification_sha256: String,
    prior_reviewable_rank_sha256s: Vec<String>,
    cap_sha256: String,
}

impl HistoricalV3VerifiedReviewCap {
    pub fn rank(&self) -> &HistoricalV3RankIdentity {
        &self.rank
    }

    pub fn prior_reviewable_rank_sha256s(&self) -> &[String] {
        &self.prior_reviewable_rank_sha256s
    }

    pub fn cap_sha256(&self) -> &str {
        &self.cap_sha256
    }

    pub fn qualification_sha256(&self) -> &str {
        &self.qualification_sha256
    }
}

pub fn prepare_historical_v3_review_cap(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    qualification: &HistoricalV3VerifiedQualification,
    prior: &[HistoricalV3OrderedRankOutcome],
) -> Result<HistoricalV3ReviewCapArtifact, String> {
    validate_historical_v3_candidate_collection_commitment(protocol, collection)?;
    let rank = qualification.rank();
    let candidates = collection
        .manifest
        .stream_task
        .candidates
        .iter()
        .filter(|candidate| candidate.identity.language == rank.language())
        .collect::<Vec<_>>();
    let candidate = candidates.get(prior.len()).ok_or_else(|| {
        "historical-v3 review cap is beyond the committed language stream".to_string()
    })?;
    let expected = historical_v3_rank_identity(protocol, collection, candidate.stream_rank)?;
    if rank != &expected {
        return Err("historical-v3 review cap moved to a different candidate rank".to_string());
    }
    if !matches!(
        evaluate_historical_v3_ordered_prefix(protocol, collection, rank.language(), prior)?,
        HistoricalV3OrderedStopStatus::Continue { .. }
    ) {
        return Err("historical-v3 review cap follows a terminal stop".to_string());
    }
    let prior_reviewable_rank_sha256s = prior
        .iter()
        .filter(|outcome| {
            outcome.rank().candidate.repository_id == rank.candidate.repository_id
                && outcome.reviewable_qualification()
        })
        .map(|outcome| outcome.rank().rank_sha256.clone())
        .collect::<Vec<_>>();
    if prior_reviewable_rank_sha256s.len()
        != protocol.stop_rule.reviewable_candidate_cap_per_repository
    {
        return Err(
            "historical-v3 review cap lacks the exact earlier reviewable candidates".to_string(),
        );
    }
    let mut artifact = HistoricalV3ReviewCapArtifact {
        schema_version: HISTORICAL_V3_REVIEW_CAP_SCHEMA_VERSION,
        contract: REVIEW_CAP_CONTRACT.to_string(),
        rank: rank.clone(),
        qualification_sha256: qualification.qualification_sha256().to_string(),
        prior_reviewable_rank_sha256s,
        reason: REVIEW_CAP_REASON.to_string(),
        cap_sha256: String::new(),
    };
    artifact.cap_sha256 = cap_sha256(&artifact)?;
    Ok(artifact)
}

pub fn verify_historical_v3_review_cap(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    qualification: &HistoricalV3VerifiedQualification,
    prior: &[HistoricalV3OrderedRankOutcome],
    path: &Path,
) -> Result<HistoricalV3VerifiedReviewCap, String> {
    let artifact = read_historical_v3_review_cap(path)?;
    let expected = prepare_historical_v3_review_cap(protocol, collection, qualification, prior)?;
    if artifact != expected {
        return Err("historical-v3 review-cap artifact changed".to_string());
    }
    Ok(HistoricalV3VerifiedReviewCap {
        rank: artifact.rank,
        qualification_sha256: artifact.qualification_sha256,
        prior_reviewable_rank_sha256s: artifact.prior_reviewable_rank_sha256s,
        cap_sha256: artifact.cap_sha256,
    })
}

pub fn write_historical_v3_review_cap_new(
    path: &Path,
    artifact: &HistoricalV3ReviewCapArtifact,
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "historical-v3 review-cap path has no parent".to_string())?;
    require_plain_directory(parent, "historical-v3 review-cap parent")?;
    write_compact_json_new(path, artifact, MAX_REVIEW_CAP_BYTES)
        .map_err(|error| format!("failed to create historical-v3 review cap: {error}"))
}

pub fn read_historical_v3_review_cap(path: &Path) -> Result<HistoricalV3ReviewCapArtifact, String> {
    let bytes = read_limited(path, MAX_REVIEW_CAP_BYTES, "historical-v3 review cap")?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid historical-v3 review cap: {error}"))
}

fn cap_sha256(artifact: &HistoricalV3ReviewCapArtifact) -> Result<String, String> {
    let mut committed = artifact.clone();
    committed.cap_sha256.clear();
    serde_json::to_vec(&committed)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v3 review cap: {error}"))
}

#[cfg(test)]
#[path = "benchmark_history_v3_review_cap_tests.rs"]
mod tests;
