use super::super::history_v3_label_review::validate_historical_v3_review_decision;
use super::super::{
    HistoricalV3LabelAudit, HistoricalV3LabelStatus, HistoricalV3LabelWorksheet,
    HistoricalV3ReviewDecision, HistoricalV3ReviewerVerdict, HistoricalV3SourceReviewBundle,
    HistoricalV3SourceReviewInputs, prepare_historical_v3_label_review,
    validate_historical_v3_label_audit,
};
use super::{
    FINAL_LABEL_CONTRACT, HISTORICAL_V3_LABEL_RESOLUTION_SCHEMA_VERSION, HistoricalV3FinalLabel,
    HistoricalV3FinalLabelBasis, HistoricalV3FinalLabelOutcome, HistoricalV3LabelResolver,
    HistoricalV3ResolutionItem, HistoricalV3ResolutionWorksheet, RESOLUTION_TASK_CONTRACT,
};
use crate::product_contract::SlopPattern;
use serde::Serialize;
use sha2::{Digest, Sha256};

pub fn prepare_historical_v3_label_resolution(
    inputs: &HistoricalV3SourceReviewInputs<'_>,
    bundle: &HistoricalV3SourceReviewBundle,
    worksheets: &[HistoricalV3LabelWorksheet],
    audit: &HistoricalV3LabelAudit,
) -> Result<HistoricalV3ResolutionWorksheet, String> {
    validate_historical_v3_label_audit(inputs, bundle, worksheets, audit)?;
    if !inputs
        .protocol
        .human_review_policy
        .distinct_dispute_resolver
    {
        return Err("historical-v3 resolution protocol changed".to_string());
    }
    let item = HistoricalV3ResolutionItem {
        review_item_id: audit.review_item_id.clone(),
        audit_status: audit.status,
        decision: (audit.status == HistoricalV3LabelStatus::Disputed)
            .then(HistoricalV3ReviewDecision::blank),
    };
    let resolution_task_sha256 = resolution_task_sha256(audit, &item)?;
    Ok(HistoricalV3ResolutionWorksheet {
        schema_version: HISTORICAL_V3_LABEL_RESOLUTION_SCHEMA_VERSION,
        protocol_sha256: inputs.protocol.protocol_sha256.clone(),
        source_bundle_sha256: bundle.bundle_sha256.clone(),
        label_audit_sha256: audit.audit_sha256.clone(),
        resolution_task_sha256,
        resolver: None,
        item,
    })
}

pub fn validate_historical_v3_label_resolution(
    inputs: &HistoricalV3SourceReviewInputs<'_>,
    bundle: &HistoricalV3SourceReviewBundle,
    worksheets: &[HistoricalV3LabelWorksheet],
    audit: &HistoricalV3LabelAudit,
    resolution: &HistoricalV3ResolutionWorksheet,
) -> Result<(), String> {
    let expected = prepare_historical_v3_label_resolution(inputs, bundle, worksheets, audit)?;
    if resolution.schema_version != expected.schema_version
        || resolution.protocol_sha256 != expected.protocol_sha256
        || resolution.source_bundle_sha256 != expected.source_bundle_sha256
        || resolution.label_audit_sha256 != expected.label_audit_sha256
        || resolution.resolution_task_sha256 != expected.resolution_task_sha256
        || resolution.item.review_item_id != expected.item.review_item_id
        || resolution.item.audit_status != expected.item.audit_status
    {
        return Err("historical-v3 resolution changed its immutable task".to_string());
    }
    match audit.status {
        HistoricalV3LabelStatus::Disputed => {
            let resolver = resolution
                .resolver
                .as_ref()
                .ok_or_else(|| "historical-v3 dispute requires a distinct resolver".to_string())?;
            validate_resolver(resolver, audit)?;
            let decision = resolution.item.decision.as_ref().ok_or_else(|| {
                "historical-v3 disputed review has no resolution decision".to_string()
            })?;
            let task = prepare_historical_v3_label_review(inputs, bundle)?.task;
            validate_historical_v3_review_decision(&task, decision)?;
        }
        HistoricalV3LabelStatus::Accepted | HistoricalV3LabelStatus::Rejected => {
            if resolution.resolver.is_some() || resolution.item.decision.is_some() {
                return Err(
                    "historical-v3 resolution cannot rewrite reviewer consensus".to_string()
                );
            }
        }
    }
    Ok(())
}

pub fn resolve_historical_v3_label(
    inputs: &HistoricalV3SourceReviewInputs<'_>,
    bundle: &HistoricalV3SourceReviewBundle,
    worksheets: &[HistoricalV3LabelWorksheet],
    audit: &HistoricalV3LabelAudit,
    resolution: &HistoricalV3ResolutionWorksheet,
) -> Result<HistoricalV3FinalLabel, String> {
    validate_historical_v3_label_resolution(inputs, bundle, worksheets, audit, resolution)?;
    let outcome = final_outcome(audit, resolution)?;
    let mut label = HistoricalV3FinalLabel {
        schema_version: HISTORICAL_V3_LABEL_RESOLUTION_SCHEMA_VERSION,
        final_contract: FINAL_LABEL_CONTRACT.to_string(),
        protocol_sha256: inputs.protocol.protocol_sha256.clone(),
        source_bundle_sha256: bundle.bundle_sha256.clone(),
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

pub fn validate_historical_v3_final_label(
    inputs: &HistoricalV3SourceReviewInputs<'_>,
    bundle: &HistoricalV3SourceReviewBundle,
    worksheets: &[HistoricalV3LabelWorksheet],
    audit: &HistoricalV3LabelAudit,
    resolution: &HistoricalV3ResolutionWorksheet,
    label: &HistoricalV3FinalLabel,
) -> Result<(), String> {
    let expected = resolve_historical_v3_label(inputs, bundle, worksheets, audit, resolution)?;
    if label != &expected {
        return Err("historical-v3 final label changed".to_string());
    }
    Ok(())
}

fn validate_resolver(
    resolver: &HistoricalV3LabelResolver,
    audit: &HistoricalV3LabelAudit,
) -> Result<(), String> {
    require_text("historical-v3 resolver ID", &resolver.resolver_id)?;
    require_text("historical-v3 resolver affiliation", &resolver.affiliation)?;
    require_text("historical-v3 resolver attestation", &resolver.attestation)?;
    if resolver.years_experience == 0
        || !resolver.independent_from_sniff
        || !resolver.sniff_output_hidden
        || !resolver.repository_identity_hidden
        || !resolver.change_metadata_hidden
        || !resolver.complete_source_context_inspected
        || !resolver.behavior_evidence_inspected
        || resolver.model_assistance_used
        || audit.reviewers.iter().any(|reviewer| {
            normalized_id(&reviewer.reviewer_id) == normalized_id(&resolver.resolver_id)
        })
    {
        return Err(
            "historical-v3 resolver must be an experienced, independent, human-only third party with complete blinded source and behavior context"
                .to_string(),
        );
    }
    Ok(())
}

fn final_outcome(
    audit: &HistoricalV3LabelAudit,
    resolution: &HistoricalV3ResolutionWorksheet,
) -> Result<HistoricalV3FinalLabelOutcome, String> {
    match audit.status {
        HistoricalV3LabelStatus::Accepted => {
            let (pattern, other_pattern) = consensus_pattern(audit)?;
            Ok(HistoricalV3FinalLabelOutcome::Accepted {
                basis: HistoricalV3FinalLabelBasis::ReviewerConsensus,
                pattern,
                other_pattern,
            })
        }
        HistoricalV3LabelStatus::Rejected => Ok(HistoricalV3FinalLabelOutcome::Closed {
            basis: HistoricalV3FinalLabelBasis::ConsensusNonSlop,
            verdict: consensus_non_slop_verdict(audit)?,
        }),
        HistoricalV3LabelStatus::Disputed => {
            let decision = resolution
                .item
                .decision
                .as_ref()
                .expect("validated dispute decision");
            match decision.verdict.expect("validated resolver verdict") {
                HistoricalV3ReviewerVerdict::Slop => {
                    let pattern = decision.pattern.expect("validated resolver pattern");
                    Ok(HistoricalV3FinalLabelOutcome::Accepted {
                        basis: HistoricalV3FinalLabelBasis::DisputeResolution,
                        pattern,
                        other_pattern: normalized_other(pattern, &decision.other_pattern),
                    })
                }
                verdict => Ok(HistoricalV3FinalLabelOutcome::Closed {
                    basis: HistoricalV3FinalLabelBasis::DisputeResolvedNonSlop,
                    verdict,
                }),
            }
        }
    }
}

fn consensus_pattern(audit: &HistoricalV3LabelAudit) -> Result<(SlopPattern, String), String> {
    let first = audit
        .labels
        .first()
        .ok_or_else(|| "historical-v3 accepted audit has no labels".to_string())?;
    let pattern = first
        .decision
        .pattern
        .ok_or_else(|| "historical-v3 accepted audit has no pattern".to_string())?;
    let other = normalized_other(pattern, &first.decision.other_pattern);
    if pattern == SlopPattern::None
        || first.decision.verdict != Some(HistoricalV3ReviewerVerdict::Slop)
        || audit.labels.iter().any(|label| {
            label.decision.verdict != Some(HistoricalV3ReviewerVerdict::Slop)
                || label.decision.pattern != Some(pattern)
                || normalized_other(pattern, &label.decision.other_pattern) != other
        })
    {
        return Err("historical-v3 accepted audit patterns disagree".to_string());
    }
    Ok((pattern, other))
}

fn consensus_non_slop_verdict(
    audit: &HistoricalV3LabelAudit,
) -> Result<HistoricalV3ReviewerVerdict, String> {
    let verdict = audit
        .labels
        .first()
        .and_then(|label| label.decision.verdict)
        .ok_or_else(|| "historical-v3 rejected audit has no verdict".to_string())?;
    if verdict == HistoricalV3ReviewerVerdict::Slop
        || audit
            .labels
            .iter()
            .any(|label| label.decision.verdict != Some(verdict))
    {
        return Err("historical-v3 rejected audit verdicts disagree".to_string());
    }
    Ok(verdict)
}

fn normalized_other(pattern: SlopPattern, value: &str) -> String {
    if pattern == SlopPattern::Other {
        normalized_id(value)
    } else {
        String::new()
    }
}

fn resolution_task_sha256(
    audit: &HistoricalV3LabelAudit,
    item: &HistoricalV3ResolutionItem,
) -> Result<String, String> {
    hash_json(&(
        RESOLUTION_TASK_CONTRACT,
        &audit.audit_sha256,
        &item.review_item_id,
        item.audit_status,
    ))
}

fn final_sha256(label: &HistoricalV3FinalLabel) -> Result<String, String> {
    hash_json(&(
        label.schema_version,
        &label.final_contract,
        &label.protocol_sha256,
        &label.source_bundle_sha256,
        &label.review_item_id,
        &label.language,
        &label.label_audit_sha256,
        &label.resolution_task_sha256,
        &label.resolver,
        &label.outcome,
    ))
}

fn normalized_id(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
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
        .map_err(|error| format!("failed to commit historical-v3 resolution: {error}"))
}
