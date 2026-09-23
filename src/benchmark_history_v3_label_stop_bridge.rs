use super::history_v2_slot_store_support::{
    read_limited, require_plain_directory, write_compact_json_new,
};
use super::{
    HistoricalV3FinalLabel, HistoricalV3FinalLabelOutcome, HistoricalV3LabelAudit,
    HistoricalV3LabelWorksheet, HistoricalV3RankIdentity, HistoricalV3ResolutionWorksheet,
    HistoricalV3ReviewDisposition, HistoricalV3ReviewRecord, HistoricalV3SourceReviewBundle,
    HistoricalV3SourceReviewInputs, validate_historical_v3_final_label,
};
use std::path::Path;

const MAX_FINAL_LABEL_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalV3VerifiedFinalReview {
    rank: HistoricalV3RankIdentity,
    record: HistoricalV3ReviewRecord,
    source_bundle_sha256: String,
    final_label_sha256: String,
}

impl HistoricalV3VerifiedFinalReview {
    pub fn rank(&self) -> &HistoricalV3RankIdentity {
        &self.rank
    }

    pub fn record(&self) -> &HistoricalV3ReviewRecord {
        &self.record
    }

    pub fn source_bundle_sha256(&self) -> &str {
        &self.source_bundle_sha256
    }

    pub fn final_label_sha256(&self) -> &str {
        &self.final_label_sha256
    }
}

#[cfg(test)]
impl HistoricalV3VerifiedFinalReview {
    pub(crate) fn synthetic(
        rank: HistoricalV3RankIdentity,
        disposition: HistoricalV3ReviewDisposition,
    ) -> Self {
        Self {
            record: HistoricalV3ReviewRecord {
                stream_rank: rank.stream_rank,
                rank_sha256: rank.rank_sha256.clone(),
                language: rank.language(),
                repository_id: rank.candidate.repository_id,
                disposition,
            },
            rank,
            source_bundle_sha256: "a".repeat(64),
            final_label_sha256: "b".repeat(64),
        }
    }
}

pub fn historical_v3_review_record_from_final_label(
    inputs: &HistoricalV3SourceReviewInputs<'_>,
    bundle: &HistoricalV3SourceReviewBundle,
    worksheets: &[HistoricalV3LabelWorksheet],
    audit: &HistoricalV3LabelAudit,
    resolution: &HistoricalV3ResolutionWorksheet,
    label: &HistoricalV3FinalLabel,
) -> Result<HistoricalV3ReviewRecord, String> {
    derive_validated_final_review(inputs, bundle, worksheets, audit, resolution, label)
        .map(|proof| proof.record)
}

pub fn verify_historical_v3_final_review(
    inputs: &HistoricalV3SourceReviewInputs<'_>,
    bundle: &HistoricalV3SourceReviewBundle,
    worksheets: &[HistoricalV3LabelWorksheet],
    audit: &HistoricalV3LabelAudit,
    resolution: &HistoricalV3ResolutionWorksheet,
    path: &Path,
) -> Result<HistoricalV3VerifiedFinalReview, String> {
    let label = read_historical_v3_final_label(path)?;
    derive_validated_final_review(inputs, bundle, worksheets, audit, resolution, &label)
}

pub fn write_historical_v3_final_label_new(
    path: &Path,
    label: &HistoricalV3FinalLabel,
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "historical-v3 final-label path has no parent".to_string())?;
    require_plain_directory(parent, "historical-v3 final-label parent")?;
    write_compact_json_new(path, label, MAX_FINAL_LABEL_BYTES)
        .map_err(|error| format!("failed to create historical-v3 final label: {error}"))
}

pub fn read_historical_v3_final_label(path: &Path) -> Result<HistoricalV3FinalLabel, String> {
    let bytes = read_limited(path, MAX_FINAL_LABEL_BYTES, "historical-v3 final label")?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid historical-v3 final label: {error}"))
}

fn derive_validated_final_review(
    inputs: &HistoricalV3SourceReviewInputs<'_>,
    bundle: &HistoricalV3SourceReviewBundle,
    worksheets: &[HistoricalV3LabelWorksheet],
    audit: &HistoricalV3LabelAudit,
    resolution: &HistoricalV3ResolutionWorksheet,
    label: &HistoricalV3FinalLabel,
) -> Result<HistoricalV3VerifiedFinalReview, String> {
    validate_historical_v3_final_label(inputs, bundle, worksheets, audit, resolution, label)?;
    let rank = &inputs.qualification.rank;
    let candidate = rank
        .stream_rank
        .checked_sub(1)
        .and_then(|index| inputs.collection.manifest.stream_task.candidates.get(index))
        .ok_or_else(|| {
            "historical-v3 final label rank is outside the committed stream".to_string()
        })?;
    if candidate.stream_rank != rank.stream_rank
        || candidate.rank_sha256 != rank.rank_sha256
        || candidate.identity != rank.candidate
    {
        return Err("historical-v3 final label is detached from its committed rank".to_string());
    }

    let disposition = match label.outcome {
        HistoricalV3FinalLabelOutcome::Accepted { .. } => HistoricalV3ReviewDisposition::Accepted,
        HistoricalV3FinalLabelOutcome::Closed { .. } => HistoricalV3ReviewDisposition::Rejected,
    };
    Ok(HistoricalV3VerifiedFinalReview {
        rank: rank.clone(),
        record: HistoricalV3ReviewRecord {
            stream_rank: rank.stream_rank,
            rank_sha256: rank.rank_sha256.clone(),
            language: rank.language(),
            repository_id: rank.candidate.repository_id,
            disposition,
        },
        source_bundle_sha256: bundle.bundle_sha256.clone(),
        final_label_sha256: label.final_sha256.clone(),
    })
}

#[cfg(test)]
#[path = "benchmark_history_v3_label_stop_bridge_tests.rs"]
mod tests;
