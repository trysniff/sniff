use super::history_v2_label_review::{
    normalized_historical_v2_reviewer_id, validate_historical_v2_review_decision,
};
use super::*;
use crate::product_contract::SlopPattern;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

const RESOLUTION_TASK_CONTRACT: &str = "sniffbench-historical-v2-resolution-task-v1";
const FINAL_LABEL_CONTRACT: &str = "sniffbench-historical-v2-final-label-v1";

pub fn prepare_historical_v2_label_resolution(
    protocol: &ValidatedHistoricalV2Protocol,
    bundle_root: &Path,
    bundle: &HistoricalV2SourceReviewBundle,
    worksheets: &[HistoricalV2LabelWorksheet],
    audit: &HistoricalV2LabelAudit,
) -> Result<HistoricalV2ResolutionWorksheet, String> {
    validate_historical_v2_label_audit(protocol, bundle_root, bundle, worksheets, audit)?;
    if !protocol.protocol.review.distinct_dispute_resolver
        || !protocol.protocol.review.rejected_label_closes_slot
    {
        return Err("historical-v2 resolution protocol changed".into());
    }
    let item = HistoricalV2ResolutionItem {
        review_item_id: audit.review_item_id.clone(),
        audit_status: audit.status,
        decision: (audit.status == HistoricalV2LabelStatus::Disputed)
            .then(HistoricalV2ReviewDecision::blank),
    };
    let resolution_task_sha256 = resolution_task_sha256(audit, &item)?;
    Ok(HistoricalV2ResolutionWorksheet {
        schema_version: HISTORICAL_V2_LABEL_RESOLUTION_SCHEMA_VERSION,
        protocol_sha256: protocol.protocol_sha256.clone(),
        source_bundle_sha256: bundle.bundle_sha256.clone(),
        label_audit_sha256: audit.audit_sha256.clone(),
        resolution_task_sha256,
        resolver: None,
        item,
    })
}

pub fn validate_historical_v2_label_resolution(
    protocol: &ValidatedHistoricalV2Protocol,
    bundle_root: &Path,
    bundle: &HistoricalV2SourceReviewBundle,
    worksheets: &[HistoricalV2LabelWorksheet],
    audit: &HistoricalV2LabelAudit,
    resolution: &HistoricalV2ResolutionWorksheet,
) -> Result<(), String> {
    let expected =
        prepare_historical_v2_label_resolution(protocol, bundle_root, bundle, worksheets, audit)?;
    if resolution.schema_version != expected.schema_version
        || resolution.protocol_sha256 != expected.protocol_sha256
        || resolution.source_bundle_sha256 != expected.source_bundle_sha256
        || resolution.label_audit_sha256 != expected.label_audit_sha256
        || resolution.resolution_task_sha256 != expected.resolution_task_sha256
        || resolution.item.review_item_id != expected.item.review_item_id
        || resolution.item.audit_status != expected.item.audit_status
    {
        return Err("historical-v2 resolution changed its immutable task".into());
    }
    match audit.status {
        HistoricalV2LabelStatus::Disputed => {
            let resolver = resolution
                .resolver
                .as_ref()
                .ok_or_else(|| "historical-v2 dispute requires a distinct resolver".to_string())?;
            validate_resolver(resolver, audit)?;
            let decision = resolution.item.decision.as_ref().ok_or_else(|| {
                "historical-v2 disputed review has no resolution decision".to_string()
            })?;
            validate_historical_v2_review_decision(bundle_root, bundle, decision)?;
        }
        HistoricalV2LabelStatus::Accepted | HistoricalV2LabelStatus::Rejected => {
            if resolution.resolver.is_some() || resolution.item.decision.is_some() {
                return Err("historical-v2 resolution cannot rewrite reviewer consensus".into());
            }
        }
    }
    Ok(())
}

pub fn resolve_historical_v2_label(
    protocol: &ValidatedHistoricalV2Protocol,
    bundle_root: &Path,
    bundle: &HistoricalV2SourceReviewBundle,
    worksheets: &[HistoricalV2LabelWorksheet],
    audit: &HistoricalV2LabelAudit,
    resolution: &HistoricalV2ResolutionWorksheet,
) -> Result<HistoricalV2FinalLabel, String> {
    validate_historical_v2_label_resolution(
        protocol,
        bundle_root,
        bundle,
        worksheets,
        audit,
        resolution,
    )?;
    let outcome = final_outcome(audit, resolution)?;
    let mut label = HistoricalV2FinalLabel {
        schema_version: HISTORICAL_V2_LABEL_RESOLUTION_SCHEMA_VERSION,
        final_contract: FINAL_LABEL_CONTRACT.to_string(),
        protocol_sha256: protocol.protocol_sha256.clone(),
        selection_sha256: bundle.selection_sha256.clone(),
        source_bundle_sha256: bundle.bundle_sha256.clone(),
        assessment_identity_sha256: bundle.assessment_identity_sha256.clone(),
        terminal_checkpoint_sha256: bundle.terminal_checkpoint_sha256.clone(),
        review_item_id: bundle.review_item_id.clone(),
        language: bundle.language.clone(),
        label_audit_sha256: audit.audit_sha256.clone(),
        resolution_task_sha256: resolution.resolution_task_sha256.clone(),
        resolver: resolution.resolver.clone(),
        outcome,
        final_sha256: String::new(),
    };
    label.final_sha256 = final_sha256(&label)?;
    Ok(label)
}

pub fn validate_historical_v2_final_label(
    protocol: &ValidatedHistoricalV2Protocol,
    bundle_root: &Path,
    bundle: &HistoricalV2SourceReviewBundle,
    worksheets: &[HistoricalV2LabelWorksheet],
    audit: &HistoricalV2LabelAudit,
    resolution: &HistoricalV2ResolutionWorksheet,
    label: &HistoricalV2FinalLabel,
) -> Result<(), String> {
    let expected =
        resolve_historical_v2_label(protocol, bundle_root, bundle, worksheets, audit, resolution)?;
    if label != &expected {
        return Err("historical-v2 final label changed".into());
    }
    Ok(())
}

fn validate_resolver(
    resolver: &HistoricalV2LabelResolver,
    audit: &HistoricalV2LabelAudit,
) -> Result<(), String> {
    require_text("historical-v2 resolver ID", &resolver.resolver_id)?;
    require_text("historical-v2 resolver affiliation", &resolver.affiliation)?;
    require_text("historical-v2 resolver attestation", &resolver.attestation)?;
    if resolver.years_experience == 0
        || !resolver.independent_from_sniff
        || !resolver.complete_source_context_inspected
        || !resolver.behavior_evidence_inspected
        || resolver.model_assistance_used
        || audit.reviewers.iter().any(|reviewer| {
            normalized_historical_v2_reviewer_id(&reviewer.reviewer_id)
                == normalized_historical_v2_reviewer_id(&resolver.resolver_id)
        })
    {
        return Err(
            "historical-v2 resolver must be an experienced, independent, human-only third party with complete source and behavior context"
                .into(),
        );
    }
    Ok(())
}

fn final_outcome(
    audit: &HistoricalV2LabelAudit,
    resolution: &HistoricalV2ResolutionWorksheet,
) -> Result<HistoricalV2FinalLabelOutcome, String> {
    match audit.status {
        HistoricalV2LabelStatus::Accepted => {
            let (pattern, other_pattern) = consensus_pattern(audit)?;
            Ok(HistoricalV2FinalLabelOutcome::Accepted {
                basis: HistoricalV2FinalLabelBasis::ReviewerConsensus,
                pattern,
                other_pattern,
            })
        }
        HistoricalV2LabelStatus::Rejected => Ok(HistoricalV2FinalLabelOutcome::Closed {
            basis: HistoricalV2FinalLabelBasis::ConsensusRejected,
            resolver_verdict: None,
        }),
        HistoricalV2LabelStatus::Disputed => {
            let decision = resolution
                .item
                .decision
                .as_ref()
                .expect("validated dispute decision");
            match decision.verdict.expect("validated resolver verdict") {
                HistoricalV2ReviewerVerdict::Accept => {
                    let pattern = decision.pattern.expect("validated resolver pattern");
                    Ok(HistoricalV2FinalLabelOutcome::Accepted {
                        basis: HistoricalV2FinalLabelBasis::DisputeResolution,
                        pattern,
                        other_pattern: normalized_other(pattern, &decision.other_pattern),
                    })
                }
                HistoricalV2ReviewerVerdict::Reject => Ok(HistoricalV2FinalLabelOutcome::Closed {
                    basis: HistoricalV2FinalLabelBasis::DisputeResolvedRejected,
                    resolver_verdict: Some(HistoricalV2ReviewerVerdict::Reject),
                }),
            }
        }
    }
}

fn consensus_pattern(audit: &HistoricalV2LabelAudit) -> Result<(SlopPattern, String), String> {
    let first = audit
        .labels
        .first()
        .ok_or_else(|| "historical-v2 accepted audit has no labels".to_string())?;
    let pattern = first
        .decision
        .pattern
        .ok_or_else(|| "historical-v2 accepted audit has no pattern".to_string())?;
    if first.decision.verdict != Some(HistoricalV2ReviewerVerdict::Accept)
        || pattern == SlopPattern::None
    {
        return Err("historical-v2 accepted audit has an invalid consensus pattern".into());
    }
    let other_pattern = normalized_other(pattern, &first.decision.other_pattern);
    if audit.labels.iter().any(|label| {
        label.decision.verdict != Some(HistoricalV2ReviewerVerdict::Accept)
            || label.decision.pattern != Some(pattern)
            || normalized_other(pattern, &label.decision.other_pattern) != other_pattern
    }) {
        return Err("historical-v2 accepted audit patterns disagree".into());
    }
    Ok((pattern, other_pattern))
}

fn normalized_other(pattern: SlopPattern, value: &str) -> String {
    if pattern == SlopPattern::Other {
        value
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
    } else {
        String::new()
    }
}

fn resolution_task_sha256(
    audit: &HistoricalV2LabelAudit,
    item: &HistoricalV2ResolutionItem,
) -> Result<String, String> {
    hash_json(&(
        RESOLUTION_TASK_CONTRACT,
        &audit.audit_sha256,
        &item.review_item_id,
        item.audit_status,
    ))
}

fn final_sha256(label: &HistoricalV2FinalLabel) -> Result<String, String> {
    hash_json(&(
        label.schema_version,
        &label.final_contract,
        &label.protocol_sha256,
        &label.selection_sha256,
        &label.source_bundle_sha256,
        &label.assessment_identity_sha256,
        &label.terminal_checkpoint_sha256,
        &label.review_item_id,
        &label.language,
        &label.label_audit_sha256,
        &label.resolution_task_sha256,
        &label.resolver,
        &label.outcome,
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
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v2 resolution: {error}"))
}

#[cfg(test)]
#[path = "benchmark_history_v2_label_resolution_tests.rs"]
mod tests;
