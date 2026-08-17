use super::*;
use crate::product_contract::SlopPattern;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path};

const LABEL_TASK_CONTRACT: &str = "sniffbench-historical-v2-label-task-v1";
const LABEL_AUDIT_CONTRACT: &str = "sniffbench-historical-v2-label-audit-v1";

pub fn prepare_historical_v2_label_review(
    protocol: &ValidatedHistoricalV2Protocol,
    bundle_root: &Path,
    bundle: &HistoricalV2SourceReviewBundle,
) -> Result<HistoricalV2LabelWorksheet, String> {
    validate_review_protocol(protocol, bundle)?;
    validate_historical_v2_source_review_bundle(bundle_root, bundle)?;
    let changed_methods = bundle
        .changed_methods
        .iter()
        .map(|method| {
            Ok(HistoricalV2ReviewMethodSource {
                method: method.clone(),
                source: exact_method_source(bundle_root, bundle, method)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let task = HistoricalV2LabelTask {
        review_item_id: bundle.review_item_id.clone(),
        language: bundle.language.clone(),
        changed_methods,
        decision: HistoricalV2ReviewDecision::blank(),
    };
    let task_sha256 = label_task_sha256(bundle, &task)?;
    Ok(HistoricalV2LabelWorksheet {
        schema_version: HISTORICAL_V2_LABEL_SCHEMA_VERSION,
        protocol_sha256: protocol.protocol_sha256.clone(),
        source_bundle_sha256: bundle.bundle_sha256.clone(),
        task_sha256,
        reviewer: None,
        task,
    })
}

pub fn validate_historical_v2_label_review(
    protocol: &ValidatedHistoricalV2Protocol,
    bundle_root: &Path,
    bundle: &HistoricalV2SourceReviewBundle,
    worksheet: &HistoricalV2LabelWorksheet,
) -> Result<(), String> {
    let expected = prepare_historical_v2_label_review(protocol, bundle_root, bundle)?;
    validate_completed_worksheet(bundle_root, bundle, worksheet, &expected)
}

pub fn audit_historical_v2_label_reviews(
    protocol: &ValidatedHistoricalV2Protocol,
    bundle_root: &Path,
    bundle: &HistoricalV2SourceReviewBundle,
    worksheets: &[HistoricalV2LabelWorksheet],
) -> Result<HistoricalV2LabelAudit, String> {
    let required = protocol.protocol.review.independent_reviewers;
    if worksheets.len() != required || required != 2 {
        return Err(format!(
            "historical-v2 label audit requires exactly {required} independent reviews"
        ));
    }
    let expected = prepare_historical_v2_label_review(protocol, bundle_root, bundle)?;
    let mut committed = worksheets
        .iter()
        .map(|worksheet| {
            validate_completed_worksheet(bundle_root, bundle, worksheet, &expected)?;
            let reviewer = worksheet.reviewer.as_ref().expect("validated reviewer");
            Ok((
                reviewer.clone(),
                hash_json(worksheet)?,
                HistoricalV2ReviewerLabel {
                    reviewer_id: reviewer.reviewer_id.clone(),
                    decision: worksheet.task.decision.clone(),
                },
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    committed.sort_by(|left, right| left.0.reviewer_id.cmp(&right.0.reviewer_id));
    if committed[0].0.reviewer_id == committed[1].0.reviewer_id {
        return Err("historical-v2 label audit repeats a reviewer".into());
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
    let mut audit = HistoricalV2LabelAudit {
        schema_version: HISTORICAL_V2_LABEL_SCHEMA_VERSION,
        protocol_sha256: protocol.protocol_sha256.clone(),
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

pub fn validate_historical_v2_label_audit(
    protocol: &ValidatedHistoricalV2Protocol,
    bundle_root: &Path,
    bundle: &HistoricalV2SourceReviewBundle,
    worksheets: &[HistoricalV2LabelWorksheet],
    audit: &HistoricalV2LabelAudit,
) -> Result<(), String> {
    let expected = audit_historical_v2_label_reviews(protocol, bundle_root, bundle, worksheets)?;
    if audit != &expected {
        return Err("historical-v2 label audit changed".into());
    }
    Ok(())
}

fn validate_completed_worksheet(
    bundle_root: &Path,
    bundle: &HistoricalV2SourceReviewBundle,
    worksheet: &HistoricalV2LabelWorksheet,
    expected: &HistoricalV2LabelWorksheet,
) -> Result<(), String> {
    if worksheet.schema_version != expected.schema_version
        || worksheet.protocol_sha256 != expected.protocol_sha256
        || worksheet.source_bundle_sha256 != expected.source_bundle_sha256
        || worksheet.task_sha256 != expected.task_sha256
        || worksheet.task.review_item_id != expected.task.review_item_id
        || worksheet.task.language != expected.task.language
        || worksheet.task.changed_methods != expected.task.changed_methods
    {
        return Err("historical-v2 label worksheet changed its immutable source task".into());
    }
    let reviewer = worksheet
        .reviewer
        .as_ref()
        .ok_or_else(|| "historical-v2 label worksheet has no reviewer".to_string())?;
    validate_reviewer(reviewer)?;
    validate_decision(bundle_root, bundle, &worksheet.task.decision)
}

fn validate_reviewer(reviewer: &HistoricalV2Reviewer) -> Result<(), String> {
    require_text("historical-v2 reviewer ID", &reviewer.reviewer_id)?;
    require_text("historical-v2 reviewer affiliation", &reviewer.affiliation)?;
    require_text("historical-v2 reviewer attestation", &reviewer.attestation)?;
    if reviewer.years_experience == 0
        || !reviewer.independent_from_sniff
        || !reviewer.sniff_output_hidden
        || !reviewer.dataset_judgments_hidden
        || !reviewer.other_reviewer_labels_hidden
        || !reviewer.complete_source_context_inspected
        || !reviewer.behavior_evidence_inspected
        || reviewer.model_assistance_used
    {
        return Err(
            "historical-v2 reviewer must be experienced, independent, human-only, source-complete, and blind to Sniff, dataset judgments, and other labels"
                .into(),
        );
    }
    Ok(())
}

fn validate_decision(
    bundle_root: &Path,
    bundle: &HistoricalV2SourceReviewBundle,
    decision: &HistoricalV2ReviewDecision,
) -> Result<(), String> {
    let verdict = decision
        .verdict
        .ok_or_else(|| "historical-v2 review has no verdict".to_string())?;
    let pattern = decision
        .pattern
        .ok_or_else(|| "historical-v2 review has no typed pattern".to_string())?;
    require_text("historical-v2 review mechanism", &decision.mechanism)?;
    require_text(
        "historical-v2 simpler counterfactual",
        &decision.simpler_counterfactual,
    )?;
    require_text("historical-v2 review rationale", &decision.rationale)?;
    let criteria = [
        decision.exact_before_slop_mechanism,
        decision.exact_after_removal,
        decision.simpler_counterfactual_matches,
        decision.public_surface_preserved,
        decision.behavior_preserved,
    ];
    if criteria.iter().any(Option::is_none) {
        return Err("historical-v2 review left a protocol criterion unanswered".into());
    }
    let all_criteria = criteria.into_iter().all(|value| value == Some(true));
    if (pattern == SlopPattern::None) != (decision.exact_before_slop_mechanism == Some(false)) {
        return Err("historical-v2 typed pattern contradicts the before-mechanism decision".into());
    }
    match verdict {
        HistoricalV2ReviewerVerdict::Accept if !all_criteria || pattern == SlopPattern::None => {
            return Err(
                "historical-v2 acceptance requires every criterion and a slop pattern".into(),
            );
        }
        HistoricalV2ReviewerVerdict::Reject if all_criteria && pattern != SlopPattern::None => {
            return Err("historical-v2 rejection contradicts its completed criteria".into());
        }
        _ => {}
    }
    match pattern {
        SlopPattern::Other => require_text("historical-v2 other pattern", &decision.other_pattern)?,
        _ if !decision.other_pattern.trim().is_empty() => {
            return Err("historical-v2 known pattern cannot carry an other-pattern label".into());
        }
        _ => {}
    }
    if decision.citations.is_empty() || decision.citations.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err("historical-v2 review requires ordered unique citations".into());
    }
    let sides = decision
        .citations
        .iter()
        .map(|citation| citation.side)
        .collect::<BTreeSet<_>>();
    if sides
        != BTreeSet::from([
            HistoricalV2ReviewSnapshotSide::Before,
            HistoricalV2ReviewSnapshotSide::After,
        ])
    {
        return Err("historical-v2 review requires before and after source citations".into());
    }
    for citation in &decision.citations {
        validate_citation(bundle_root, bundle, citation)?;
    }
    Ok(())
}

fn validate_citation(
    bundle_root: &Path,
    bundle: &HistoricalV2SourceReviewBundle,
    citation: &HistoricalV2SourceCitation,
) -> Result<(), String> {
    if citation.start_line == 0 || citation.end_line < citation.start_line {
        return Err("historical-v2 source citation has an invalid range".into());
    }
    let snapshot = bundle
        .snapshots
        .iter()
        .find(|snapshot| snapshot.side == citation.side)
        .ok_or_else(|| "historical-v2 citation snapshot disappeared".to_string())?;
    let artifact = snapshot
        .artifacts
        .iter()
        .find(|artifact| artifact.repository_path == citation.repository_path)
        .ok_or_else(|| "historical-v2 citation invents a source path".to_string())?;
    let relative = artifact
        .artifact_path
        .as_deref()
        .ok_or_else(|| "historical-v2 citation does not name a Git blob".to_string())?;
    let text = fs::read_to_string(safe_bundle_path(bundle_root, relative)?)
        .map_err(|_| "historical-v2 cited source is not UTF-8".to_string())?;
    let lines = text
        .lines()
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect::<Vec<_>>();
    if citation.end_line > lines.len() {
        return Err("historical-v2 citation exceeds its source".into());
    }
    let exact = lines[citation.start_line - 1..citation.end_line].join("\n");
    if citation.quote != exact || citation.quote.trim().is_empty() {
        return Err("historical-v2 citation is not exact source".into());
    }
    Ok(())
}

fn exact_method_source(
    bundle_root: &Path,
    bundle: &HistoricalV2SourceReviewBundle,
    method: &HistoricalV2ReviewChangedMethod,
) -> Result<String, String> {
    let side = match method.side {
        HistoricalRevisionSide::Parent => HistoricalV2ReviewSnapshotSide::Before,
        HistoricalRevisionSide::Commit => HistoricalV2ReviewSnapshotSide::After,
    };
    let snapshot = bundle
        .snapshots
        .iter()
        .find(|snapshot| snapshot.side == side)
        .ok_or_else(|| "historical-v2 changed-method snapshot disappeared".to_string())?;
    let artifact = snapshot
        .artifacts
        .iter()
        .find(|artifact| artifact.repository_path == method.repository_path)
        .ok_or_else(|| "historical-v2 changed-method artifact disappeared".to_string())?;
    let bytes = fs::read(safe_bundle_path(
        bundle_root,
        artifact
            .artifact_path
            .as_deref()
            .ok_or_else(|| "historical-v2 changed method is not a Git blob".to_string())?,
    )?)
    .map_err(|error| format!("failed to read historical-v2 changed method: {error}"))?;
    let parsed = crate::parser::parse_source_checked(&method.repository_path, &bytes)?;
    parsed
        .methods
        .into_iter()
        .find(|candidate| {
            candidate.name == method.symbol_name
                && candidate.start_line == method.start_line
                && candidate.end_line == method.end_line
                && sha256(candidate.source.as_bytes()) == method.source_sha256
        })
        .map(|method| method.source)
        .ok_or_else(|| "historical-v2 exact changed method disappeared".to_string())
}

fn label_status(
    first: &HistoricalV2ReviewDecision,
    second: &HistoricalV2ReviewDecision,
) -> HistoricalV2LabelStatus {
    match (first.verdict, second.verdict) {
        (Some(HistoricalV2ReviewerVerdict::Reject), Some(HistoricalV2ReviewerVerdict::Reject)) => {
            HistoricalV2LabelStatus::Rejected
        }
        (Some(HistoricalV2ReviewerVerdict::Accept), Some(HistoricalV2ReviewerVerdict::Accept))
            if pattern_signature(first) == pattern_signature(second) =>
        {
            HistoricalV2LabelStatus::Accepted
        }
        _ => HistoricalV2LabelStatus::Disputed,
    }
}

fn pattern_signature(decision: &HistoricalV2ReviewDecision) -> (SlopPattern, String) {
    let pattern = decision.pattern.expect("validated pattern");
    let other = if pattern == SlopPattern::Other {
        decision
            .other_pattern
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
    } else {
        String::new()
    };
    (pattern, other)
}

fn validate_review_protocol(
    protocol: &ValidatedHistoricalV2Protocol,
    bundle: &HistoricalV2SourceReviewBundle,
) -> Result<(), String> {
    let review = &protocol.protocol.review;
    if protocol.protocol_sha256 != bundle.protocol_sha256
        || !review.source_only_review
        || review.independent_reviewers != 2
        || !review.reviewers_must_not_see_sniff_output
        || !review.reviewers_must_not_see_each_other_labels
        || !review.exact_before_slop_mechanism_required
        || !review.exact_after_removal_required
        || !review.historical_patch_must_match_simpler_counterfactual
        || !review.behavior_evidence_required
    {
        return Err("historical-v2 independent-review protocol changed".into());
    }
    Ok(())
}

fn label_task_sha256(
    bundle: &HistoricalV2SourceReviewBundle,
    task: &HistoricalV2LabelTask,
) -> Result<String, String> {
    hash_json(&(
        LABEL_TASK_CONTRACT,
        &bundle.bundle_sha256,
        &task.review_item_id,
        &task.language,
        &task.changed_methods,
    ))
}

fn audit_sha256(audit: &HistoricalV2LabelAudit) -> Result<String, String> {
    hash_json(&(
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

fn safe_bundle_path(root: &Path, relative: &str) -> Result<std::path::PathBuf, String> {
    let relative = Path::new(relative);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("historical-v2 label artifact path is unsafe".into());
    }
    Ok(root.join(relative))
}

fn require_text(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to commit historical-v2 labels: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "benchmark_history_v2_label_review_tests.rs"]
mod tests;
