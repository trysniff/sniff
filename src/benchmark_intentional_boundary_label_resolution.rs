use super::intentional_boundary_label_review::validate_boundary_decision;
use super::*;
use crate::types::FindingTier;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

const RESOLUTION_TASK_CONTRACT: &str = "sniffbench-intentional-boundary-resolution-task-v1";
const FINAL_LABEL_CONTRACT: &str = "sniffbench-intentional-boundary-final-labels-v1";

pub fn prepare_intentional_boundary_label_resolution(
    protocol: &ValidatedIntentionalBoundaryProtocol,
    bundle_root: &Path,
    bundle: &IntentionalBoundarySourceBundle,
    worksheets: &[IntentionalBoundaryLabelWorksheet],
    audit: &IntentionalBoundaryLabelAudit,
) -> Result<IntentionalBoundaryResolutionWorksheet, String> {
    validate_intentional_boundary_label_audit(protocol, bundle_root, bundle, worksheets, audit)?;
    let contract = &protocol.protocol.label_contract;
    if !contract.distinct_dispute_resolver || !contract.rejected_label_closes_slot {
        return Err("intentional-boundary resolution contract changed".to_string());
    }
    let items = audit
        .items
        .iter()
        .map(|item| IntentionalBoundaryResolutionItem {
            review_item_id: item.review_item_id.clone(),
            audit_status: item.status,
            decision: (item.status == IntentionalBoundaryLabelStatus::Disputed)
                .then(IntentionalBoundaryLabelDecision::blank),
        })
        .collect::<Vec<_>>();
    let resolution_task_sha256 = resolution_task_sha256(audit, &items)?;
    Ok(IntentionalBoundaryResolutionWorksheet {
        schema_version: INTENTIONAL_BOUNDARY_LABEL_RESOLUTION_SCHEMA_VERSION,
        protocol_sha256: protocol.protocol_sha256.clone(),
        source_bundle_sha256: bundle.bundle_sha256.clone(),
        label_audit_sha256: audit.audit_sha256.clone(),
        resolution_task_sha256,
        resolver: None,
        items,
    })
}

pub fn validate_intentional_boundary_label_resolution(
    protocol: &ValidatedIntentionalBoundaryProtocol,
    bundle_root: &Path,
    bundle: &IntentionalBoundarySourceBundle,
    worksheets: &[IntentionalBoundaryLabelWorksheet],
    audit: &IntentionalBoundaryLabelAudit,
    resolution: &IntentionalBoundaryResolutionWorksheet,
) -> Result<(), String> {
    let expected = prepare_intentional_boundary_label_resolution(
        protocol,
        bundle_root,
        bundle,
        worksheets,
        audit,
    )?;
    if resolution.schema_version != expected.schema_version
        || resolution.protocol_sha256 != expected.protocol_sha256
        || resolution.source_bundle_sha256 != expected.source_bundle_sha256
        || resolution.label_audit_sha256 != expected.label_audit_sha256
        || resolution.resolution_task_sha256 != expected.resolution_task_sha256
        || resolution.items.len() != expected.items.len()
    {
        return Err(
            "intentional-boundary resolution worksheet changed its immutable task".to_string(),
        );
    }
    let disputes = expected
        .items
        .iter()
        .filter(|item| item.audit_status == IntentionalBoundaryLabelStatus::Disputed)
        .count();
    match (&resolution.resolver, disputes) {
        (Some(resolver), 1..) => validate_resolver(resolver, audit)?,
        (None, 0) => {}
        (Some(_), 0) => {
            return Err(
                "intentional-boundary resolution cannot add a resolver without disputes"
                    .to_string(),
            );
        }
        (None, _) => {
            return Err("intentional-boundary disputes require a distinct resolver".to_string());
        }
    }
    let sources = bundle
        .review_items
        .iter()
        .map(|source| (source.review_item_id.as_str(), source))
        .collect::<BTreeMap<_, _>>();
    for (actual, protected) in resolution.items.iter().zip(&expected.items) {
        if actual.review_item_id != protected.review_item_id
            || actual.audit_status != protected.audit_status
        {
            return Err("intentional-boundary resolution changed a fixed slot".to_string());
        }
        match actual.audit_status {
            IntentionalBoundaryLabelStatus::Disputed => {
                let decision = actual.decision.as_ref().ok_or_else(|| {
                    format!(
                        "intentional-boundary dispute {} has no resolution",
                        actual.review_item_id
                    )
                })?;
                let source = sources
                    .get(actual.review_item_id.as_str())
                    .copied()
                    .ok_or_else(|| {
                        "intentional-boundary resolution source disappeared".to_string()
                    })?;
                validate_boundary_decision(bundle_root, bundle, source, decision)?;
            }
            IntentionalBoundaryLabelStatus::Accepted | IntentionalBoundaryLabelStatus::Rejected => {
                if actual.decision.is_some() {
                    return Err(format!(
                        "intentional-boundary resolution rewrites consensus item {}",
                        actual.review_item_id
                    ));
                }
            }
        }
    }
    Ok(())
}

pub fn resolve_intentional_boundary_labels(
    protocol: &ValidatedIntentionalBoundaryProtocol,
    bundle_root: &Path,
    bundle: &IntentionalBoundarySourceBundle,
    worksheets: &[IntentionalBoundaryLabelWorksheet],
    audit: &IntentionalBoundaryLabelAudit,
    resolution: &IntentionalBoundaryResolutionWorksheet,
) -> Result<IntentionalBoundaryFinalLabelBundle, String> {
    validate_intentional_boundary_label_resolution(
        protocol,
        bundle_root,
        bundle,
        worksheets,
        audit,
        resolution,
    )?;
    let audit_items = audit
        .items
        .iter()
        .map(|item| (item.review_item_id.as_str(), item))
        .collect::<BTreeMap<_, _>>();
    let mut labels = resolution
        .items
        .iter()
        .map(|item| {
            let audited = audit_items
                .get(item.review_item_id.as_str())
                .copied()
                .ok_or_else(|| "intentional-boundary final label lost its audit".to_string())?;
            Ok(IntentionalBoundaryFinalLabel {
                review_item_id: item.review_item_id.clone(),
                outcome: final_outcome(audited, item)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    labels.sort_by(|left, right| left.review_item_id.cmp(&right.review_item_id));
    let accepted_count = labels
        .iter()
        .filter(|label| {
            matches!(
                label.outcome,
                IntentionalBoundaryFinalOutcome::Accepted { .. }
            )
        })
        .count();
    let closed_count = labels.len() - accepted_count;
    let mut final_bundle = IntentionalBoundaryFinalLabelBundle {
        schema_version: INTENTIONAL_BOUNDARY_LABEL_RESOLUTION_SCHEMA_VERSION,
        final_contract: FINAL_LABEL_CONTRACT.to_string(),
        protocol_sha256: protocol.protocol_sha256.clone(),
        source_bundle_sha256: bundle.bundle_sha256.clone(),
        selection_sha256: bundle.selection_sha256.clone(),
        label_audit_sha256: audit.audit_sha256.clone(),
        resolution_task_sha256: resolution.resolution_task_sha256.clone(),
        resolver: resolution.resolver.clone(),
        labels,
        accepted_count,
        closed_count,
        unfilled_slot_count: bundle.unfilled_slot_count,
        final_sha256: String::new(),
    };
    final_bundle.final_sha256 = final_sha256(&final_bundle)?;
    Ok(final_bundle)
}

pub fn validate_intentional_boundary_final_labels(
    protocol: &ValidatedIntentionalBoundaryProtocol,
    bundle_root: &Path,
    bundle: &IntentionalBoundarySourceBundle,
    worksheets: &[IntentionalBoundaryLabelWorksheet],
    audit: &IntentionalBoundaryLabelAudit,
    resolution: &IntentionalBoundaryResolutionWorksheet,
    final_bundle: &IntentionalBoundaryFinalLabelBundle,
) -> Result<(), String> {
    let expected = resolve_intentional_boundary_labels(
        protocol,
        bundle_root,
        bundle,
        worksheets,
        audit,
        resolution,
    )?;
    if final_bundle != &expected {
        return Err("intentional-boundary final labels changed".to_string());
    }
    Ok(())
}

fn final_outcome(
    audit: &IntentionalBoundaryLabelAuditItem,
    resolution: &IntentionalBoundaryResolutionItem,
) -> Result<IntentionalBoundaryFinalOutcome, String> {
    match audit.status {
        IntentionalBoundaryLabelStatus::Accepted => Ok(IntentionalBoundaryFinalOutcome::Accepted {
            basis: IntentionalBoundaryFinalBasis::ReviewerConsensus,
        }),
        IntentionalBoundaryLabelStatus::Rejected => {
            let signature = consensus_signature(audit)?;
            Ok(IntentionalBoundaryFinalOutcome::Closed {
                basis: IntentionalBoundaryFinalBasis::ConsensusRejected,
                tier: signature.0,
                intentional_boundary: signature.1,
            })
        }
        IntentionalBoundaryLabelStatus::Disputed => {
            let decision = resolution
                .decision
                .as_ref()
                .expect("validated dispute resolution");
            let tier = decision.tier.expect("validated resolution tier");
            let intentional_boundary = decision
                .intentional_boundary
                .expect("validated resolution boundary");
            if (tier, intentional_boundary) == (FindingTier::Clean, true) {
                Ok(IntentionalBoundaryFinalOutcome::Accepted {
                    basis: IntentionalBoundaryFinalBasis::DisputeResolution,
                })
            } else {
                Ok(IntentionalBoundaryFinalOutcome::Closed {
                    basis: IntentionalBoundaryFinalBasis::DisputeResolvedClosed,
                    tier,
                    intentional_boundary,
                })
            }
        }
    }
}

fn consensus_signature(
    audit: &IntentionalBoundaryLabelAuditItem,
) -> Result<(FindingTier, bool), String> {
    let signatures = audit
        .labels
        .iter()
        .map(|label| {
            Ok((
                label.decision.tier.ok_or_else(|| {
                    "intentional-boundary consensus label has no tier".to_string()
                })?,
                label.decision.intentional_boundary.ok_or_else(|| {
                    "intentional-boundary consensus label has no boundary decision".to_string()
                })?,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let Some(first) = signatures.first().copied() else {
        return Err("intentional-boundary rejected consensus has no labels".to_string());
    };
    if signatures.iter().any(|signature| *signature != first) {
        return Err("intentional-boundary rejected consensus is inconsistent".to_string());
    }
    Ok(first)
}

fn validate_resolver(
    resolver: &IntentionalBoundaryLabelResolver,
    audit: &IntentionalBoundaryLabelAudit,
) -> Result<(), String> {
    if resolver.resolver_id.trim().is_empty()
        || resolver.affiliation.trim().is_empty()
        || resolver.attestation.trim().is_empty()
        || resolver.years_experience == 0
        || !resolver.independent_from_sniff
        || !resolver.complete_source_context_inspected
        || audit
            .reviewers
            .iter()
            .any(|reviewer| reviewer.reviewer_id == resolver.resolver_id)
    {
        return Err(
            "intentional-boundary resolver must be experienced, independent, source-complete, and distinct from reviewers"
                .to_string(),
        );
    }
    Ok(())
}

fn resolution_task_sha256(
    audit: &IntentionalBoundaryLabelAudit,
    items: &[IntentionalBoundaryResolutionItem],
) -> Result<String, String> {
    let protected = items
        .iter()
        .map(|item| (&item.review_item_id, item.audit_status))
        .collect::<Vec<_>>();
    hash_json(&(RESOLUTION_TASK_CONTRACT, &audit.audit_sha256, protected))
}

fn final_sha256(bundle: &IntentionalBoundaryFinalLabelBundle) -> Result<String, String> {
    hash_json(&(
        &bundle.final_contract,
        bundle.schema_version,
        &bundle.protocol_sha256,
        &bundle.source_bundle_sha256,
        &bundle.selection_sha256,
        &bundle.label_audit_sha256,
        &bundle.resolution_task_sha256,
        &bundle.resolver,
        &bundle.labels,
        bundle.accepted_count,
        bundle.closed_count,
        bundle.unfilled_slot_count,
    ))
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit intentional-boundary resolution: {error}"))
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_label_resolution_tests.rs"]
mod tests;
