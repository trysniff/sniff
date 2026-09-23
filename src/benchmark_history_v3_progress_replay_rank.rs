use super::super::history_v3_rank_journal::historical_v3_rank_journal_path;
use super::super::{
    HistoricalV3CandidateCollection, HistoricalV3OrderedRankOutcome, HistoricalV3Protocol,
    HistoricalV3RankIdentity, HistoricalV3RankJournal, HistoricalV3RankStage,
    HistoricalV3RankStageOutcome, HistoricalV3ReviewRecordPaths,
    verify_historical_v3_qualified_rank, verify_historical_v3_review_cap,
    verify_historical_v3_source_review_rank, verify_historical_v3_terminal_exclusion,
};
use super::paths::{
    human_files_exist, plain_file_exists, rank_directory_exists, review_directory_exists,
};
use super::{HistoricalV3NextStep, human};
use std::path::Path;

pub(super) enum RankReplay {
    Complete(HistoricalV3OrderedRankOutcome),
    Pending(HistoricalV3NextStep),
}

pub(super) fn replay_rank(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    rank: &HistoricalV3RankIdentity,
    journal_root: &Path,
    review_root: &Path,
    prior: &[HistoricalV3OrderedRankOutcome],
) -> Result<RankReplay, String> {
    let paths = HistoricalV3ReviewRecordPaths::new(review_root, rank);
    let journal_path = historical_v3_rank_journal_path(journal_root, rank);
    let journal_exists = rank_directory_exists(journal_root, &journal_path)?;
    let review_exists = review_directory_exists(review_root, &paths)?;
    if !journal_exists {
        if review_exists {
            return Err("historical-v3 review record has no rank journal".to_string());
        }
        return Ok(RankReplay::Pending(HistoricalV3NextStep::RankStage(
            HistoricalV3RankStage::Materialization,
        )));
    }
    let journal =
        HistoricalV3RankJournal::open(journal_root, rank).map_err(|error| error.to_string())?;
    let last = journal
        .history()
        .last()
        .map(|stored| stored.checkpoint.outcome.clone());
    let completed_count = journal.history().len();
    let next_stage = journal.next_stage();
    drop(journal);
    let cap_exists = if review_exists {
        plain_file_exists(&paths.cap, "historical-v3 review cap")?
    } else {
        false
    };
    let human_exists = if review_exists {
        human_files_exist(&paths)?
    } else {
        false
    };
    match last {
        Some(HistoricalV3RankStageOutcome::Excluded { .. }) => {
            if cap_exists || human_exists {
                return Err("historical-v3 excluded rank has review records".to_string());
            }
            Ok(RankReplay::Complete(
                HistoricalV3OrderedRankOutcome::Excluded(
                    verify_historical_v3_terminal_exclusion(
                        protocol,
                        collection,
                        rank.stream_rank,
                        journal_root,
                    )
                    .map_err(|error| error.to_string())?,
                ),
            ))
        }
        Some(HistoricalV3RankStageOutcome::ReadyForSourceReview { .. }) => {
            if cap_exists {
                return Err("historical-v3 reviewable rank also has a cap".to_string());
            }
            let source = verify_historical_v3_source_review_rank(
                protocol,
                collection,
                rank.stream_rank,
                journal_root,
            )
            .map_err(|error| error.to_string())?;
            match human::replay_human_review(protocol, collection, &source, &paths)? {
                Some(proof) => Ok(RankReplay::Complete(
                    HistoricalV3OrderedRankOutcome::Reviewed(proof),
                )),
                None => Ok(RankReplay::Pending(HistoricalV3NextStep::HumanReview)),
            }
        }
        _ if completed_count == 4 => {
            if human_exists {
                return Err("historical-v3 qualified rank has premature human records".to_string());
            }
            replay_qualified_rank(
                protocol,
                collection,
                rank,
                journal_root,
                prior,
                &paths,
                cap_exists,
            )
        }
        _ => {
            if cap_exists || human_exists {
                return Err("historical-v3 unfinished rank has review records".to_string());
            }
            let next = next_stage.ok_or_else(|| {
                "historical-v3 rank has no valid next stage or terminal outcome".to_string()
            })?;
            Ok(RankReplay::Pending(HistoricalV3NextStep::RankStage(next)))
        }
    }
}

fn replay_qualified_rank(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    rank: &HistoricalV3RankIdentity,
    journal_root: &Path,
    prior: &[HistoricalV3OrderedRankOutcome],
    paths: &HistoricalV3ReviewRecordPaths,
    cap_exists: bool,
) -> Result<RankReplay, String> {
    let prior_reviewable = prior
        .iter()
        .filter(|outcome| {
            outcome.rank().candidate.repository_id == rank.candidate.repository_id
                && outcome.reviewable_qualification()
        })
        .count();
    if prior_reviewable == protocol.stop_rule.reviewable_candidate_cap_per_repository {
        if !cap_exists {
            return Ok(RankReplay::Pending(
                HistoricalV3NextStep::RepositoryReviewCap,
            ));
        }
        let qualification = verify_historical_v3_qualified_rank(
            protocol,
            collection,
            rank.stream_rank,
            journal_root,
        )
        .map_err(|error| error.to_string())?;
        Ok(RankReplay::Complete(
            HistoricalV3OrderedRankOutcome::Capped(verify_historical_v3_review_cap(
                protocol,
                collection,
                &qualification,
                prior,
                &paths.cap,
            )?),
        ))
    } else {
        if cap_exists {
            return Err("historical-v3 review cap precedes eight candidates".to_string());
        }
        Ok(RankReplay::Pending(HistoricalV3NextStep::RankStage(
            HistoricalV3RankStage::TestRecipe,
        )))
    }
}
