use super::super::{
    HistoricalV3SourceReviewBundle, HistoricalV3SourceReviewInputs,
    validate_historical_v3_protocol, validate_historical_v3_source_review_bundle,
};
use super::validation::validate_completed_worksheet;
use super::{
    HISTORICAL_V3_LABEL_REVIEW_SCHEMA_VERSION, HistoricalV3LabelAudit, HistoricalV3LabelStatus,
    HistoricalV3LabelTask, HistoricalV3LabelWorksheet, HistoricalV3ReviewDecision,
    HistoricalV3ReviewerLabel, HistoricalV3ReviewerVerdict, LABEL_AUDIT_CONTRACT,
    LABEL_TASK_CONTRACT,
};
use crate::product_contract::SlopPattern;
use serde::Serialize;
use sha2::{Digest, Sha256};

pub fn prepare_historical_v3_label_review(
    inputs: &HistoricalV3SourceReviewInputs<'_>,
    bundle: &HistoricalV3SourceReviewBundle,
) -> Result<HistoricalV3LabelWorksheet, String> {
    validate_review_protocol(inputs)?;
    validate_historical_v3_source_review_bundle(inputs, bundle)?;
    let task = HistoricalV3LabelTask {
        review_item_id: bundle.review_item_id.clone(),
        language: bundle.language.clone(),
        public_surface_preserved: bundle.public_surface_preserved,
        public_surface_delta_sha256: bundle.public_surface_delta_sha256.clone(),
        simplifications: bundle.simplifications.clone(),
        methods: bundle.methods.clone(),
        behavior: bundle.behavior.clone(),
        decision: HistoricalV3ReviewDecision::blank(),
    };
    let task_sha256 = task_sha256(bundle, &task)?;
    Ok(HistoricalV3LabelWorksheet {
        schema_version: HISTORICAL_V3_LABEL_REVIEW_SCHEMA_VERSION,
        protocol_sha256: inputs.protocol.protocol_sha256.clone(),
        source_bundle_sha256: bundle.bundle_sha256.clone(),
        task_sha256,
        reviewer: None,
        task,
    })
}

pub fn validate_historical_v3_label_review(
    inputs: &HistoricalV3SourceReviewInputs<'_>,
    bundle: &HistoricalV3SourceReviewBundle,
    worksheet: &HistoricalV3LabelWorksheet,
) -> Result<(), String> {
    let expected = prepare_historical_v3_label_review(inputs, bundle)?;
    validate_completed_worksheet(worksheet, &expected)
}

pub fn audit_historical_v3_label_reviews(
    inputs: &HistoricalV3SourceReviewInputs<'_>,
    bundle: &HistoricalV3SourceReviewBundle,
    worksheets: &[HistoricalV3LabelWorksheet],
) -> Result<HistoricalV3LabelAudit, String> {
    let required = inputs
        .protocol
        .human_review_policy
        .as_ref()
        .ok_or_else(|| {
            "historical-v3 human label audit requires human-review authority".to_string()
        })?
        .independent_reviewers;
    if required != 2 || worksheets.len() != required {
        return Err(format!(
            "historical-v3 label audit requires exactly {required} independent reviews"
        ));
    }
    let expected = prepare_historical_v3_label_review(inputs, bundle)?;
    let mut committed = worksheets
        .iter()
        .map(|worksheet| {
            validate_completed_worksheet(worksheet, &expected)?;
            let reviewer = worksheet.reviewer.as_ref().expect("validated reviewer");
            Ok((
                reviewer.clone(),
                json_sha256(worksheet)?,
                HistoricalV3ReviewerLabel {
                    reviewer_id: reviewer.reviewer_id.clone(),
                    decision: worksheet.task.decision.clone(),
                },
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    committed.sort_by_key(|entry| normalized_reviewer_id(&entry.0.reviewer_id));
    if normalized_reviewer_id(&committed[0].0.reviewer_id)
        == normalized_reviewer_id(&committed[1].0.reviewer_id)
    {
        return Err("historical-v3 label audit repeats a reviewer".to_string());
    }
    let status = label_status(&committed[0].2.decision, &committed[1].2.decision);
    let reviewers = committed
        .iter()
        .map(|entry| entry.0.clone())
        .collect::<Vec<_>>();
    let worksheet_sha256s = committed
        .iter()
        .map(|entry| entry.1.clone())
        .collect::<Vec<_>>();
    let labels = committed
        .into_iter()
        .map(|entry| entry.2)
        .collect::<Vec<_>>();
    let mut audit = HistoricalV3LabelAudit {
        schema_version: HISTORICAL_V3_LABEL_REVIEW_SCHEMA_VERSION,
        protocol_sha256: inputs.protocol.protocol_sha256.clone(),
        source_bundle_sha256: bundle.bundle_sha256.clone(),
        task_sha256: expected.task_sha256,
        worksheet_sha256s,
        reviewers,
        review_item_id: bundle.review_item_id.clone(),
        status,
        labels,
        audit_sha256: String::new(),
    };
    audit.audit_sha256 = audit_sha256(&audit)?;
    Ok(audit)
}

pub fn validate_historical_v3_label_audit(
    inputs: &HistoricalV3SourceReviewInputs<'_>,
    bundle: &HistoricalV3SourceReviewBundle,
    worksheets: &[HistoricalV3LabelWorksheet],
    audit: &HistoricalV3LabelAudit,
) -> Result<(), String> {
    let expected = audit_historical_v3_label_reviews(inputs, bundle, worksheets)?;
    if audit != &expected {
        return Err("historical-v3 label audit changed".to_string());
    }
    Ok(())
}

fn label_status(
    first: &HistoricalV3ReviewDecision,
    second: &HistoricalV3ReviewDecision,
) -> HistoricalV3LabelStatus {
    match (first.verdict, second.verdict) {
        (Some(HistoricalV3ReviewerVerdict::Slop), Some(HistoricalV3ReviewerVerdict::Slop))
            if pattern_signature(first) == pattern_signature(second) =>
        {
            HistoricalV3LabelStatus::Accepted
        }
        (Some(left), Some(right)) if left == right && left != HistoricalV3ReviewerVerdict::Slop => {
            HistoricalV3LabelStatus::Rejected
        }
        _ => HistoricalV3LabelStatus::Disputed,
    }
}

fn pattern_signature(decision: &HistoricalV3ReviewDecision) -> (SlopPattern, String) {
    let pattern = decision.pattern.expect("validated pattern");
    let other = if pattern == SlopPattern::Other {
        normalized_text(&decision.other_pattern)
    } else {
        String::new()
    };
    (pattern, other)
}

fn validate_review_protocol(inputs: &HistoricalV3SourceReviewInputs<'_>) -> Result<(), String> {
    validate_historical_v3_protocol(inputs.protocol)?;
    let policy = inputs
        .protocol
        .human_review_policy
        .as_ref()
        .ok_or_else(|| "historical-v3 human review requires human-review authority".to_string())?;
    if !policy.source_only_review
        || policy.independent_reviewers != 2
        || !policy.distinct_dispute_resolver
        || !policy.reviewers_must_not_see_sniff_output
        || !policy.reviewers_must_not_see_repository_identity
        || !policy.reviewers_must_not_see_change_metadata
        || !policy.reviewers_must_not_see_each_other_labels
        || !policy.human_only_review
        || !policy.complete_source_context_required
        || !policy.behavior_evidence_required
        || !policy.exact_before_mechanism_required
        || !policy.exact_after_removal_required
        || !policy.relocation_check_required
        || !policy.simpler_counterfactual_required
    {
        return Err("historical-v3 independent-review protocol changed".to_string());
    }
    Ok(())
}

fn task_sha256(
    bundle: &HistoricalV3SourceReviewBundle,
    task: &HistoricalV3LabelTask,
) -> Result<String, String> {
    json_sha256(&(
        LABEL_TASK_CONTRACT,
        &bundle.bundle_sha256,
        &task.review_item_id,
        &task.language,
        task.public_surface_preserved,
        &task.public_surface_delta_sha256,
        &task.simplifications,
        &task.methods,
        &task.behavior,
    ))
}

fn audit_sha256(audit: &HistoricalV3LabelAudit) -> Result<String, String> {
    json_sha256(&(
        LABEL_AUDIT_CONTRACT,
        audit.schema_version,
        &audit.protocol_sha256,
        &audit.source_bundle_sha256,
        &audit.task_sha256,
        &audit.worksheet_sha256s,
        &audit.reviewers,
        &audit.review_item_id,
        audit.status,
        &audit.labels,
    ))
}

fn normalized_reviewer_id(value: &str) -> String {
    normalized_text(value)
}

fn normalized_text(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn json_sha256(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v3 labels: {error}"))
}
