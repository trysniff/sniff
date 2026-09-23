use super::history_v3_rank_journal::historical_v3_rank_identity_in_validated_collection;
use super::{
    HistoricalV3CandidateCollection, HistoricalV3Language, HistoricalV3OrderedRankOutcome,
    HistoricalV3Protocol, HistoricalV3ReviewRecordPaths, HistoricalV3StopArtifact,
    HistoricalV3StopRankDecision, read_historical_v3_stop_artifact,
    validate_historical_v3_candidate_collection_commitment,
    verify_historical_v3_final_review_from_disk, verify_historical_v3_qualified_rank,
    verify_historical_v3_review_cap, verify_historical_v3_stop_artifact,
    verify_historical_v3_terminal_exclusion,
};
use std::path::Path;

pub fn verify_historical_v3_stop_from_disk(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    language: HistoricalV3Language,
    journal_root: &Path,
    review_root: &Path,
    stop_path: &Path,
) -> Result<HistoricalV3StopArtifact, String> {
    validate_historical_v3_candidate_collection_commitment(protocol, collection)?;
    let stored = read_historical_v3_stop_artifact(stop_path)?;
    let candidates = collection
        .manifest
        .stream_task
        .candidates
        .iter()
        .filter(|candidate| candidate.identity.language == language)
        .collect::<Vec<_>>();
    if stored.entries.len() > candidates.len() {
        return Err("historical-v3 stop replay extends past the committed stream".to_string());
    }
    let mut outcomes = Vec::with_capacity(stored.entries.len());
    for (entry, candidate) in stored.entries.iter().zip(candidates) {
        let expected = historical_v3_rank_identity_in_validated_collection(
            protocol,
            collection,
            candidate.stream_rank,
        )?;
        if entry.rank != expected {
            return Err("historical-v3 stop replay contains a foreign or skipped rank".to_string());
        }
        let outcome = match &entry.decision {
            HistoricalV3StopRankDecision::Excluded { .. } => {
                HistoricalV3OrderedRankOutcome::Excluded(
                    verify_historical_v3_terminal_exclusion(
                        protocol,
                        collection,
                        candidate.stream_rank,
                        journal_root,
                    )
                    .map_err(|error| error.to_string())?,
                )
            }
            HistoricalV3StopRankDecision::Reviewed { .. } => {
                HistoricalV3OrderedRankOutcome::Reviewed(
                    verify_historical_v3_final_review_from_disk(
                        protocol,
                        collection,
                        candidate.stream_rank,
                        journal_root,
                        review_root,
                    )?,
                )
            }
            HistoricalV3StopRankDecision::Capped { .. } => {
                let qualification = verify_historical_v3_qualified_rank(
                    protocol,
                    collection,
                    candidate.stream_rank,
                    journal_root,
                )
                .map_err(|error| error.to_string())?;
                let paths = HistoricalV3ReviewRecordPaths::new(review_root, &expected);
                HistoricalV3OrderedRankOutcome::Capped(verify_historical_v3_review_cap(
                    protocol,
                    collection,
                    &qualification,
                    &outcomes,
                    &paths.cap,
                )?)
            }
        };
        outcomes.push(outcome);
    }
    verify_historical_v3_stop_artifact(protocol, collection, language, &outcomes, stop_path)
}
