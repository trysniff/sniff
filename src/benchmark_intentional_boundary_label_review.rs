use super::*;
use crate::types::FindingTier;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const LABEL_TASK_CONTRACT: &str = "sniffbench-intentional-boundary-label-task-v1";
const LABEL_AUDIT_CONTRACT: &str = "sniffbench-intentional-boundary-label-audit-v1";

pub fn prepare_intentional_boundary_label_review(
    bundle_root: &Path,
    bundle: &IntentionalBoundarySourceBundle,
) -> Result<IntentionalBoundaryLabelWorksheet, String> {
    validate_intentional_boundary_source_bundle_artifacts(bundle_root, bundle)?;
    let mut items = bundle
        .review_items
        .iter()
        .map(|item| label_task(bundle_root, bundle, item))
        .collect::<Result<Vec<_>, _>>()?;
    items.sort_by(|left, right| left.source.review_item_id.cmp(&right.source.review_item_id));
    let task_sha256 = label_task_sha256(&bundle.bundle_sha256, &items)?;
    Ok(IntentionalBoundaryLabelWorksheet {
        schema_version: INTENTIONAL_BOUNDARY_LABEL_SCHEMA_VERSION,
        source_bundle_sha256: bundle.bundle_sha256.clone(),
        task_sha256,
        reviewer: None,
        items,
    })
}

pub fn validate_intentional_boundary_label_review(
    bundle_root: &Path,
    bundle: &IntentionalBoundarySourceBundle,
    worksheet: &IntentionalBoundaryLabelWorksheet,
) -> Result<(), String> {
    let expected = prepare_intentional_boundary_label_review(bundle_root, bundle)?;
    validate_completed_worksheet(bundle_root, bundle, worksheet, &expected)
}

pub fn audit_intentional_boundary_label_reviews(
    protocol: &ValidatedIntentionalBoundaryProtocol,
    bundle_root: &Path,
    bundle: &IntentionalBoundarySourceBundle,
    worksheets: &[IntentionalBoundaryLabelWorksheet],
) -> Result<IntentionalBoundaryLabelAudit, String> {
    let required_reviewers = protocol.protocol.label_contract.independent_reviewers;
    if worksheets.len() != required_reviewers || required_reviewers < 2 {
        return Err(format!(
            "intentional-boundary label audit requires exactly {required_reviewers} independent reviews"
        ));
    }
    if protocol.protocol_sha256 != bundle.protocol_sha256
        || !protocol.protocol.label_contract.source_only_review
        || !protocol
            .protocol
            .label_contract
            .reviewers_must_not_see_sniff_output
        || !protocol
            .protocol
            .label_contract
            .reviewers_must_not_see_each_other_labels
    {
        return Err("intentional-boundary label protocol changed".to_string());
    }
    let expected = prepare_intentional_boundary_label_review(bundle_root, bundle)?;
    let mut reviewers = Vec::with_capacity(worksheets.len());
    let mut reviewer_ids = BTreeSet::new();
    let mut worksheet_sha256s = Vec::with_capacity(worksheets.len());
    for worksheet in worksheets {
        validate_completed_worksheet(bundle_root, bundle, worksheet, &expected)?;
        let reviewer = worksheet.reviewer.as_ref().expect("validated reviewer");
        if !reviewer_ids.insert(reviewer.reviewer_id.as_str()) {
            return Err(format!(
                "intentional-boundary label audit repeats reviewer {}",
                reviewer.reviewer_id
            ));
        }
        reviewers.push(reviewer.clone());
        worksheet_sha256s.push(hash_json(worksheet)?);
    }
    reviewers.sort_by(|left, right| left.reviewer_id.cmp(&right.reviewer_id));
    worksheet_sha256s.sort();

    let mut items = Vec::with_capacity(expected.items.len());
    for expected_item in &expected.items {
        let mut labels = worksheets
            .iter()
            .map(|worksheet| IntentionalBoundaryReviewerLabel {
                reviewer_id: worksheet
                    .reviewer
                    .as_ref()
                    .expect("validated reviewer")
                    .reviewer_id
                    .clone(),
                decision: worksheet
                    .items
                    .iter()
                    .find(|item| item.source.review_item_id == expected_item.source.review_item_id)
                    .expect("validated review-item census")
                    .decision
                    .clone(),
            })
            .collect::<Vec<_>>();
        labels.sort_by(|left, right| left.reviewer_id.cmp(&right.reviewer_id));
        let signatures = labels
            .iter()
            .map(|label| decision_signature(&label.decision))
            .collect::<Vec<_>>();
        let status = if signatures
            .iter()
            .all(|signature| *signature == (FindingTier::Clean, true))
        {
            IntentionalBoundaryLabelStatus::Accepted
        } else if signatures.windows(2).all(|pair| pair[0] == pair[1]) {
            IntentionalBoundaryLabelStatus::Rejected
        } else {
            IntentionalBoundaryLabelStatus::Disputed
        };
        items.push(IntentionalBoundaryLabelAuditItem {
            review_item_id: expected_item.source.review_item_id.clone(),
            status,
            labels,
        });
    }
    let accepted_count = count_status(&items, IntentionalBoundaryLabelStatus::Accepted);
    let rejected_count = count_status(&items, IntentionalBoundaryLabelStatus::Rejected);
    let disputed_count = count_status(&items, IntentionalBoundaryLabelStatus::Disputed);
    let mut audit = IntentionalBoundaryLabelAudit {
        schema_version: INTENTIONAL_BOUNDARY_LABEL_SCHEMA_VERSION,
        protocol_sha256: protocol.protocol_sha256.clone(),
        source_bundle_sha256: bundle.bundle_sha256.clone(),
        task_sha256: expected.task_sha256,
        worksheet_sha256s,
        reviewers,
        items,
        accepted_count,
        rejected_count,
        disputed_count,
        audit_sha256: String::new(),
    };
    audit.audit_sha256 = audit_sha256(&audit)?;
    Ok(audit)
}

pub fn validate_intentional_boundary_label_audit(
    protocol: &ValidatedIntentionalBoundaryProtocol,
    bundle_root: &Path,
    bundle: &IntentionalBoundarySourceBundle,
    worksheets: &[IntentionalBoundaryLabelWorksheet],
    audit: &IntentionalBoundaryLabelAudit,
) -> Result<(), String> {
    let expected =
        audit_intentional_boundary_label_reviews(protocol, bundle_root, bundle, worksheets)?;
    if audit != &expected {
        return Err("intentional-boundary label audit changed".to_string());
    }
    Ok(())
}

pub(super) fn validate_boundary_decision(
    bundle_root: &Path,
    bundle: &IntentionalBoundarySourceBundle,
    source: &IntentionalBoundarySourceReviewItem,
    decision: &IntentionalBoundaryLabelDecision,
) -> Result<(), String> {
    let _tier = decision.tier.ok_or_else(|| {
        format!(
            "intentional-boundary review {} has no tier",
            source.review_item_id
        )
    })?;
    decision.intentional_boundary.ok_or_else(|| {
        format!(
            "intentional-boundary review {} has no boundary decision",
            source.review_item_id
        )
    })?;
    require_text("intentional-boundary rationale", &decision.rationale)?;
    if decision.citations.is_empty() || decision.citations.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(format!(
            "intentional-boundary review {} requires ordered unique source citations",
            source.review_item_id
        ));
    }
    let repository = bundle
        .repositories
        .iter()
        .find(|repository| repository.source_repository_id == source.source_repository_id)
        .ok_or_else(|| "intentional-boundary review repository disappeared".to_string())?;
    for citation in &decision.citations {
        validate_citation(bundle_root, repository, citation)?;
    }
    Ok(())
}

fn validate_completed_worksheet(
    bundle_root: &Path,
    bundle: &IntentionalBoundarySourceBundle,
    worksheet: &IntentionalBoundaryLabelWorksheet,
    expected: &IntentionalBoundaryLabelWorksheet,
) -> Result<(), String> {
    if worksheet.schema_version != expected.schema_version
        || worksheet.source_bundle_sha256 != expected.source_bundle_sha256
        || worksheet.task_sha256 != expected.task_sha256
        || worksheet.items.len() != expected.items.len()
    {
        return Err("intentional-boundary label worksheet changed its immutable task".to_string());
    }
    let reviewer = worksheet
        .reviewer
        .as_ref()
        .ok_or_else(|| "intentional-boundary label worksheet has no reviewer".to_string())?;
    validate_reviewer(reviewer)?;
    for (actual, protected) in worksheet.items.iter().zip(&expected.items) {
        if actual.source != protected.source || actual.method_source != protected.method_source {
            return Err(format!(
                "intentional-boundary worksheet changed source item {}",
                protected.source.review_item_id
            ));
        }
        validate_boundary_decision(bundle_root, bundle, &actual.source, &actual.decision)?;
    }
    Ok(())
}

fn label_task(
    bundle_root: &Path,
    bundle: &IntentionalBoundarySourceBundle,
    item: &IntentionalBoundarySourceReviewItem,
) -> Result<IntentionalBoundaryLabelTask, String> {
    let repository = bundle
        .repositories
        .iter()
        .find(|repository| repository.source_repository_id == item.source_repository_id)
        .ok_or_else(|| "intentional-boundary source repository disappeared".to_string())?;
    let artifact = repository
        .artifacts
        .iter()
        .find(|artifact| artifact.artifact_path.as_deref() == Some(&item.source_artifact_path))
        .ok_or_else(|| "intentional-boundary source artifact disappeared".to_string())?;
    let bytes = fs::read(bundle_root.join(&item.source_artifact_path)).map_err(|error| {
        format!(
            "failed to read intentional-boundary label source {}: {error}",
            artifact.repository_path
        )
    })?;
    let parsed = crate::parser::parse_source_checked(&item.repository_path, &bytes)?;
    let method = parsed
        .methods
        .into_iter()
        .find(|method| {
            method.name == item.symbol_name
                && method.start_line == item.start_line
                && method.end_line == item.end_line
                && sha256(method.source.as_bytes()) == item.source_sha256
        })
        .ok_or_else(|| {
            format!(
                "intentional-boundary label source method disappeared: {}",
                item.review_item_id
            )
        })?;
    Ok(IntentionalBoundaryLabelTask {
        source: item.clone(),
        method_source: method.source,
        decision: IntentionalBoundaryLabelDecision::blank(),
    })
}

fn validate_reviewer(reviewer: &IntentionalBoundaryLabelReviewer) -> Result<(), String> {
    require_text("intentional-boundary reviewer ID", &reviewer.reviewer_id)?;
    require_text(
        "intentional-boundary reviewer affiliation",
        &reviewer.affiliation,
    )?;
    require_text(
        "intentional-boundary reviewer attestation",
        &reviewer.attestation,
    )?;
    if reviewer.years_experience == 0
        || !reviewer.independent_from_sniff
        || !reviewer.sniff_output_hidden
        || !reviewer.other_reviewer_labels_hidden
        || !reviewer.complete_source_context_inspected
    {
        return Err(
            "intentional-boundary reviewer must be experienced, independent, source-complete, and blind to Sniff and other labels"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_citation(
    bundle_root: &Path,
    repository: &IntentionalBoundarySourceRepository,
    citation: &IntentionalBoundarySourceCitation,
) -> Result<(), String> {
    if citation.start_line == 0 || citation.end_line < citation.start_line {
        return Err("intentional-boundary citation has an invalid line range".to_string());
    }
    let artifact = repository
        .artifacts
        .iter()
        .find(|artifact| artifact.repository_path == citation.repository_path)
        .ok_or_else(|| {
            format!(
                "intentional-boundary citation invents source {}",
                citation.repository_path
            )
        })?;
    let artifact_path = artifact.artifact_path.as_deref().ok_or_else(|| {
        format!(
            "intentional-boundary citation source is not a committed blob: {}",
            citation.repository_path
        )
    })?;
    let text = fs::read_to_string(bundle_root.join(artifact_path)).map_err(|_| {
        format!(
            "intentional-boundary citation source is not UTF-8: {}",
            citation.repository_path
        )
    })?;
    let lines = text
        .lines()
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect::<Vec<_>>();
    if citation.end_line > lines.len() {
        return Err(format!(
            "intentional-boundary citation exceeds source {}",
            citation.repository_path
        ));
    }
    let exact = lines[citation.start_line - 1..citation.end_line].join("\n");
    if citation.quote != exact || citation.quote.trim().is_empty() {
        return Err(format!(
            "intentional-boundary citation is not exact source: {}:{}",
            citation.repository_path, citation.start_line
        ));
    }
    Ok(())
}

fn decision_signature(decision: &IntentionalBoundaryLabelDecision) -> (FindingTier, bool) {
    (
        decision.tier.expect("validated tier"),
        decision
            .intentional_boundary
            .expect("validated boundary decision"),
    )
}

fn count_status(
    items: &[IntentionalBoundaryLabelAuditItem],
    status: IntentionalBoundaryLabelStatus,
) -> usize {
    items.iter().filter(|item| item.status == status).count()
}

fn label_task_sha256(
    bundle_sha256: &str,
    items: &[IntentionalBoundaryLabelTask],
) -> Result<String, String> {
    let protected = items
        .iter()
        .map(|item| (&item.source, &item.method_source))
        .collect::<Vec<_>>();
    hash_json(&(LABEL_TASK_CONTRACT, bundle_sha256, protected))
}

fn audit_sha256(audit: &IntentionalBoundaryLabelAudit) -> Result<String, String> {
    hash_json(&(
        LABEL_AUDIT_CONTRACT,
        audit.schema_version,
        &audit.protocol_sha256,
        &audit.source_bundle_sha256,
        &audit.task_sha256,
        &audit.worksheet_sha256s,
        &audit.reviewers,
        &audit.items,
        audit.accepted_count,
        audit.rejected_count,
        audit.disputed_count,
    ))
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
        .map_err(|error| format!("failed to commit intentional-boundary labels: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_label_review_tests.rs"]
pub(super) mod tests;
