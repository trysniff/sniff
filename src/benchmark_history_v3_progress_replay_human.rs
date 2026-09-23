use super::super::{
    HistoricalV3CandidateCollection, HistoricalV3LabelStatus, HistoricalV3LabelWorksheet,
    HistoricalV3Protocol, HistoricalV3ReviewRecordPaths, HistoricalV3VerifiedFinalReview,
    HistoricalV3VerifiedSourceReview, prepare_historical_v3_label_resolution,
    prepare_historical_v3_label_review, read_historical_v3_label_audit,
    read_historical_v3_label_worksheet, read_historical_v3_resolution_worksheet,
    validate_historical_v3_label_audit, validate_historical_v3_label_resolution,
    validate_historical_v3_label_review, verify_historical_v3_final_review,
};
use super::plain_file_exists;

pub(super) fn replay_human_review(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    source: &HistoricalV3VerifiedSourceReview,
    paths: &HistoricalV3ReviewRecordPaths,
) -> Result<Option<HistoricalV3VerifiedFinalReview>, String> {
    let first_exists = plain_file_exists(&paths.reviewer_one, "historical-v3 first review")?;
    let second_exists = plain_file_exists(&paths.reviewer_two, "historical-v3 second review")?;
    let audit_exists = plain_file_exists(&paths.audit, "historical-v3 audit")?;
    let resolution_exists = plain_file_exists(&paths.resolution, "historical-v3 resolution")?;
    let final_exists = plain_file_exists(&paths.final_label, "historical-v3 final label")?;
    let inputs = source.inputs(protocol, collection);
    let bundle = source.bundle();
    let blank = prepare_historical_v3_label_review(&inputs, bundle)?;
    let first = read_review(first_exists, &paths.reviewer_one, &blank, &inputs, bundle)?;
    let second = read_review(second_exists, &paths.reviewer_two, &blank, &inputs, bundle)?;
    let (Some(first), Some(second)) = (first, second) else {
        if audit_exists || resolution_exists || final_exists {
            return Err("historical-v3 human record skips independent reviews".to_string());
        }
        return Ok(None);
    };
    let worksheets = [first, second];
    if !audit_exists {
        if resolution_exists || final_exists {
            return Err("historical-v3 human record skips the label audit".to_string());
        }
        return Ok(None);
    }
    let audit = read_historical_v3_label_audit(&paths.audit)?;
    validate_historical_v3_label_audit(&inputs, bundle, &worksheets, &audit)?;
    if !resolution_exists {
        if final_exists {
            return Err("historical-v3 human record skips the resolution task".to_string());
        }
        return Ok(None);
    }
    let resolution = read_historical_v3_resolution_worksheet(&paths.resolution)?;
    let blank_resolution =
        prepare_historical_v3_label_resolution(&inputs, bundle, &worksheets, &audit)?;
    if audit.status == HistoricalV3LabelStatus::Disputed && resolution == blank_resolution {
        if final_exists {
            return Err("historical-v3 final label precedes dispute resolution".to_string());
        }
        return Ok(None);
    }
    validate_historical_v3_label_resolution(&inputs, bundle, &worksheets, &audit, &resolution)?;
    if !final_exists {
        return Ok(None);
    }
    verify_historical_v3_final_review(
        &inputs,
        bundle,
        &worksheets,
        &audit,
        &resolution,
        &paths.final_label,
    )
    .map(Some)
}

fn read_review(
    exists: bool,
    path: &std::path::Path,
    blank: &HistoricalV3LabelWorksheet,
    inputs: &super::super::HistoricalV3SourceReviewInputs<'_>,
    bundle: &super::super::HistoricalV3SourceReviewBundle,
) -> Result<Option<HistoricalV3LabelWorksheet>, String> {
    if !exists {
        return Ok(None);
    }
    let worksheet = read_historical_v3_label_worksheet(path)?;
    if &worksheet == blank {
        return Ok(None);
    }
    validate_historical_v3_label_review(inputs, bundle, &worksheet)?;
    Ok(Some(worksheet))
}
