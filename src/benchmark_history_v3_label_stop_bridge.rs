use super::{
    HistoricalV3FinalLabel, HistoricalV3FinalLabelOutcome, HistoricalV3LabelAudit,
    HistoricalV3LabelWorksheet, HistoricalV3ResolutionWorksheet, HistoricalV3ReviewDisposition,
    HistoricalV3ReviewRecord, HistoricalV3SourceReviewBundle, HistoricalV3SourceReviewInputs,
    validate_historical_v3_final_label,
};

pub fn historical_v3_review_record_from_final_label(
    inputs: &HistoricalV3SourceReviewInputs<'_>,
    bundle: &HistoricalV3SourceReviewBundle,
    worksheets: &[HistoricalV3LabelWorksheet],
    audit: &HistoricalV3LabelAudit,
    resolution: &HistoricalV3ResolutionWorksheet,
    label: &HistoricalV3FinalLabel,
) -> Result<HistoricalV3ReviewRecord, String> {
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
    Ok(HistoricalV3ReviewRecord {
        stream_rank: rank.stream_rank,
        rank_sha256: rank.rank_sha256.clone(),
        language: rank.language(),
        repository_id: rank.candidate.repository_id,
        disposition,
    })
}

#[cfg(test)]
#[path = "benchmark_history_v3_label_stop_bridge_tests.rs"]
mod tests;
