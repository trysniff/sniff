use super::history_v3_rank_journal::historical_v3_rank_identity_in_validated_collection;
use super::{
    HistoricalV3CandidateCollection, HistoricalV3Language, HistoricalV3OrderedRankOutcome,
    HistoricalV3OrderedStopStatus, HistoricalV3Protocol, HistoricalV3RankIdentity,
    HistoricalV3RankStage, HistoricalV3StopArtifact, evaluate_historical_v3_ordered_prefix,
    prepare_historical_v3_stop_artifact, validate_historical_v3_candidate_collection_commitment,
    verify_historical_v3_stop_artifact,
};
use std::path::Path;

use paths::ensure_no_later_state;
use paths::plain_file_exists;
use rank::RankReplay;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoricalV3NextStep {
    RankStage(HistoricalV3RankStage),
    RepositoryReviewCap,
    HumanReview,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoricalV3ReplayProgress {
    PendingRank {
        processed_ranks: usize,
        rank: HistoricalV3RankIdentity,
        next: HistoricalV3NextStep,
    },
    AwaitingStopPublication {
        artifact: HistoricalV3StopArtifact,
    },
    Terminal {
        artifact: HistoricalV3StopArtifact,
    },
}

pub fn replay_historical_v3_ordered_progress(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    language: HistoricalV3Language,
    journal_root: &Path,
    review_root: &Path,
    stop_path: &Path,
) -> Result<HistoricalV3ReplayProgress, String> {
    validate_historical_v3_candidate_collection_commitment(protocol, collection)?;
    if !protocol.languages.contains(&language) {
        return Err("historical-v3 progress language is outside the protocol".to_string());
    }
    let candidates = collection
        .manifest
        .stream_task
        .candidates
        .iter()
        .filter(|candidate| candidate.identity.language == language)
        .collect::<Vec<_>>();
    let stop_exists = plain_file_exists(stop_path, "historical-v3 stop artifact")?;
    let mut outcomes = Vec::new();
    for (index, candidate) in candidates.iter().enumerate() {
        let rank = historical_v3_rank_identity_in_validated_collection(
            protocol,
            collection,
            candidate.stream_rank,
        )?;
        match rank::replay_rank(
            protocol,
            collection,
            &rank,
            journal_root,
            review_root,
            &outcomes,
        )? {
            RankReplay::Complete(outcome) => outcomes.push(*outcome),
            RankReplay::Pending(next) => {
                ensure_no_later_state(
                    protocol,
                    collection,
                    &candidates[index + 1..],
                    journal_root,
                    review_root,
                )?;
                return pending(&outcomes, stop_exists, rank, next);
            }
        }
        if !matches!(
            evaluate_historical_v3_ordered_prefix(protocol, collection, language, &outcomes)?,
            HistoricalV3OrderedStopStatus::Continue { .. }
        ) {
            ensure_no_later_state(
                protocol,
                collection,
                &candidates[index + 1..],
                journal_root,
                review_root,
            )?;
            return finish(
                protocol,
                collection,
                language,
                &outcomes,
                stop_path,
                stop_exists,
            );
        }
    }
    finish(
        protocol,
        collection,
        language,
        &outcomes,
        stop_path,
        stop_exists,
    )
}

fn pending(
    outcomes: &[HistoricalV3OrderedRankOutcome],
    stop_exists: bool,
    rank: HistoricalV3RankIdentity,
    next: HistoricalV3NextStep,
) -> Result<HistoricalV3ReplayProgress, String> {
    if stop_exists {
        return Err("historical-v3 stop artifact exists before the prefix is terminal".to_string());
    }
    Ok(HistoricalV3ReplayProgress::PendingRank {
        processed_ranks: outcomes.len(),
        rank,
        next,
    })
}

fn finish(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    language: HistoricalV3Language,
    outcomes: &[HistoricalV3OrderedRankOutcome],
    stop_path: &Path,
    stop_exists: bool,
) -> Result<HistoricalV3ReplayProgress, String> {
    if stop_exists {
        Ok(HistoricalV3ReplayProgress::Terminal {
            artifact: verify_historical_v3_stop_artifact(
                protocol, collection, language, outcomes, stop_path,
            )?,
        })
    } else {
        Ok(HistoricalV3ReplayProgress::AwaitingStopPublication {
            artifact: prepare_historical_v3_stop_artifact(
                protocol, collection, language, outcomes,
            )?,
        })
    }
}

#[path = "benchmark_history_v3_progress_replay_paths.rs"]
mod paths;

#[path = "benchmark_history_v3_progress_replay_rank.rs"]
mod rank;

#[path = "benchmark_history_v3_progress_replay_human.rs"]
mod human;

#[cfg(test)]
#[path = "benchmark_history_v3_progress_replay_tests.rs"]
mod tests;
