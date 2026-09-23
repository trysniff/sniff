use super::{
    HistoricalV3CandidateCollection, HistoricalV3Language, HistoricalV3Protocol,
    HistoricalV3RankIdentity, HistoricalV3RankStage, HistoricalV3ReviewDisposition,
    HistoricalV3VerifiedFinalReview, HistoricalV3VerifiedReviewCap,
    HistoricalV3VerifiedTerminalExclusion, historical_v3_rank_identity,
    validate_historical_v3_candidate_collection_commitment,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoricalV3OrderedRankOutcome {
    Excluded(HistoricalV3VerifiedTerminalExclusion),
    Reviewed(HistoricalV3VerifiedFinalReview),
    Capped(HistoricalV3VerifiedReviewCap),
}

impl HistoricalV3OrderedRankOutcome {
    pub(super) fn rank(&self) -> &HistoricalV3RankIdentity {
        match self {
            Self::Excluded(proof) => proof.rank(),
            Self::Reviewed(proof) => proof.rank(),
            Self::Capped(proof) => proof.rank(),
        }
    }

    pub(super) fn reviewable_qualification(&self) -> bool {
        match self {
            Self::Excluded(proof) => proof.stage() > HistoricalV3RankStage::MechanicalQualification,
            Self::Reviewed(_) => true,
            Self::Capped(_) => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoricalV3OrderedStopStatus {
    Continue {
        processed_ranks: usize,
        reviewed: usize,
        accepted: usize,
        distinct_accepted_repositories: usize,
    },
    TargetReached {
        processed_ranks: usize,
        reviewed: usize,
        accepted: usize,
        distinct_accepted_repositories: usize,
    },
    FailedAdjudicationCap {
        processed_ranks: usize,
        reviewed: usize,
        accepted: usize,
        distinct_accepted_repositories: usize,
    },
    FailedSourceExhausted {
        processed_ranks: usize,
        reviewed: usize,
        accepted: usize,
        distinct_accepted_repositories: usize,
    },
}

pub fn evaluate_historical_v3_ordered_prefix(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    language: HistoricalV3Language,
    outcomes: &[HistoricalV3OrderedRankOutcome],
) -> Result<HistoricalV3OrderedStopStatus, String> {
    validate_historical_v3_candidate_collection_commitment(protocol, collection)?;
    if !protocol.languages.contains(&language) {
        return Err("historical-v3 ordered-stop language is outside the protocol".to_string());
    }
    let candidates = collection
        .manifest
        .stream_task
        .candidates
        .iter()
        .filter(|candidate| candidate.identity.language == language)
        .collect::<Vec<_>>();
    if outcomes.len() > candidates.len() {
        return Err("historical-v3 ordered stop extends past the language stream".to_string());
    }

    let rule = &protocol.stop_rule;
    let mut reviewable_by_repository = BTreeMap::<u64, Vec<String>>::new();
    let mut accepted_by_repository = BTreeMap::<u64, usize>::new();
    let mut accepted_repositories = BTreeSet::new();
    let mut reviewed = 0;
    let mut accepted = 0;

    for (index, outcome) in outcomes.iter().enumerate() {
        let candidate = candidates[index];
        let expected = historical_v3_rank_identity(protocol, collection, candidate.stream_rank)?;
        if outcome.rank() != &expected {
            return Err(
                "historical-v3 ordered stop contains a foreign or skipped rank".to_string(),
            );
        }
        let repository_id = expected.candidate.repository_id;
        let reviewable = reviewable_by_repository.entry(repository_id).or_default();
        if let HistoricalV3OrderedRankOutcome::Capped(proof) = outcome {
            if reviewable.len() != rule.reviewable_candidate_cap_per_repository
                || proof.prior_reviewable_rank_sha256s() != reviewable
            {
                return Err("historical-v3 review cap changed its exact prior ranks".to_string());
            }
        } else if outcome.reviewable_qualification() {
            if reviewable.len() >= rule.reviewable_candidate_cap_per_repository {
                return Err(
                    "historical-v3 repository review cap requires a committed cap outcome"
                        .to_string(),
                );
            }
            reviewable.push(expected.rank_sha256.clone());
        }

        if let HistoricalV3OrderedRankOutcome::Reviewed(proof) = outcome {
            reviewed += 1;
            match proof.record().disposition {
                HistoricalV3ReviewDisposition::Accepted => {
                    accepted += 1;
                    accepted_repositories.insert(repository_id);
                    let repository_accepted =
                        accepted_by_repository.entry(repository_id).or_default();
                    *repository_accepted += 1;
                    if *repository_accepted > rule.accepted_case_cap_per_repository {
                        return Err(
                            "historical-v3 repository acceptance cap was exceeded".to_string()
                        );
                    }
                }
                HistoricalV3ReviewDisposition::Rejected => {}
                HistoricalV3ReviewDisposition::Disputed => {
                    return Err(
                        "historical-v3 ordered stop contains an unresolved dispute".to_string()
                    );
                }
            }
        }

        let processed_ranks = index + 1;
        let distinct_accepted_repositories = accepted_repositories.len();
        if accepted >= rule.accepted_target_per_language
            && distinct_accepted_repositories >= rule.distinct_repository_floor_per_language
        {
            if processed_ranks != outcomes.len() {
                return Err(
                    "historical-v3 ordered stop continued past its first successful prefix"
                        .to_string(),
                );
            }
            return Ok(HistoricalV3OrderedStopStatus::TargetReached {
                processed_ranks,
                reviewed,
                accepted,
                distinct_accepted_repositories,
            });
        }
        if reviewed == rule.adjudication_cap_per_language {
            if processed_ranks != outcomes.len() {
                return Err(
                    "historical-v3 ordered stop continued past its adjudication cap".to_string(),
                );
            }
            return Ok(HistoricalV3OrderedStopStatus::FailedAdjudicationCap {
                processed_ranks,
                reviewed,
                accepted,
                distinct_accepted_repositories,
            });
        }
    }

    let status = if outcomes.len() == candidates.len() {
        HistoricalV3OrderedStopStatus::FailedSourceExhausted {
            processed_ranks: outcomes.len(),
            reviewed,
            accepted,
            distinct_accepted_repositories: accepted_repositories.len(),
        }
    } else {
        HistoricalV3OrderedStopStatus::Continue {
            processed_ranks: outcomes.len(),
            reviewed,
            accepted,
            distinct_accepted_repositories: accepted_repositories.len(),
        }
    };
    Ok(status)
}

#[cfg(test)]
#[path = "benchmark_history_v3_ordered_stop_tests.rs"]
mod tests;
