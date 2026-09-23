use super::{
    HistoricalV3CandidateCollection, HistoricalV3Protocol, HistoricalV3RankIdentity,
    HistoricalV3VerifiedFinalReview, read_historical_v3_label_audit,
    read_historical_v3_label_worksheet, read_historical_v3_resolution_worksheet,
    verify_historical_v3_final_review, verify_historical_v3_source_review_rank,
};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalV3ReviewRecordPaths {
    pub cap: PathBuf,
    pub reviewer_one: PathBuf,
    pub reviewer_two: PathBuf,
    pub audit: PathBuf,
    pub resolution: PathBuf,
    pub final_label: PathBuf,
}

impl HistoricalV3ReviewRecordPaths {
    pub fn new(root: &Path, rank: &HistoricalV3RankIdentity) -> Self {
        let directory = root.join(&rank.stream_task_sha256).join(&rank.rank_sha256);
        Self {
            cap: directory.join("review-cap.json"),
            reviewer_one: directory.join("reviewer-one.json"),
            reviewer_two: directory.join("reviewer-two.json"),
            audit: directory.join("audit.json"),
            resolution: directory.join("resolution.json"),
            final_label: directory.join("final-label.json"),
        }
    }
}

pub fn verify_historical_v3_final_review_from_disk(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    stream_rank: usize,
    journal_root: &Path,
    review_root: &Path,
) -> Result<HistoricalV3VerifiedFinalReview, String> {
    let source =
        verify_historical_v3_source_review_rank(protocol, collection, stream_rank, journal_root)
            .map_err(|error| error.to_string())?;
    let paths = HistoricalV3ReviewRecordPaths::new(review_root, source.rank());
    let worksheets = [
        read_historical_v3_label_worksheet(&paths.reviewer_one)?,
        read_historical_v3_label_worksheet(&paths.reviewer_two)?,
    ];
    let audit = read_historical_v3_label_audit(&paths.audit)?;
    let resolution = read_historical_v3_resolution_worksheet(&paths.resolution)?;
    let proof = verify_historical_v3_final_review(
        &source.inputs(protocol, collection),
        source.bundle(),
        &worksheets,
        &audit,
        &resolution,
        &paths.final_label,
    )?;
    if proof.rank() != source.rank() {
        return Err("historical-v3 review record moved to another rank".to_string());
    }
    Ok(proof)
}

#[cfg(test)]
#[path = "benchmark_history_v3_review_replay_tests.rs"]
mod tests;
