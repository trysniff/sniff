use super::*;
use crate::types::FindingTier;
use std::collections::BTreeSet;
use std::path::Path;

pub(super) fn build_historical_v2_corpus_binding(
    protocol: &ValidatedHistoricalV2Protocol,
    corpus_root: &Path,
    reviewed: &HistoricalV2ReviewedSlotArtifacts<'_>,
    accepted: &HistoricalV2ReleaseSlotOutcome,
) -> Result<HistoricalV2CorpusCaseBinding, String> {
    validate_historical_v2_source_review_bundle(reviewed.bundle_root, reviewed.bundle)?;
    validate_historical_v2_final_label(
        protocol,
        reviewed.bundle_root,
        reviewed.bundle,
        reviewed.worksheets,
        reviewed.audit,
        reviewed.resolution,
        reviewed.final_label,
    )?;
    let HistoricalV2ReleaseSlotOutcome::Accepted {
        terminal_checkpoint_sha256,
        review_item_id,
        source_bundle_sha256,
        label_audit_sha256,
        final_label_sha256,
        pattern,
        ..
    } = accepted
    else {
        return Err("historical-v2 corpus case requires an accepted release slot".into());
    };
    if reviewed.bundle.terminal_checkpoint_sha256 != *terminal_checkpoint_sha256
        || reviewed.bundle.review_item_id != *review_item_id
        || reviewed.bundle.bundle_sha256 != *source_bundle_sha256
        || reviewed.audit.audit_sha256 != *label_audit_sha256
        || reviewed.final_label.final_sha256 != *final_label_sha256
    {
        return Err("historical-v2 corpus case changed its accepted release lineage".into());
    }
    let source_bundle_artifact_path = relative_plain_directory(corpus_root, reviewed.bundle_root)?;
    let before = source_snapshots(
        corpus_root,
        reviewed.bundle_root,
        &source_bundle_artifact_path,
        reviewed.bundle,
        HistoricalV2ReviewSnapshotSide::Before,
    )?;
    let after = source_snapshots(
        corpus_root,
        reviewed.bundle_root,
        &source_bundle_artifact_path,
        reviewed.bundle,
        HistoricalV2ReviewSnapshotSide::After,
    )?;
    let final_decision = final_review_decision(reviewed)?;
    let changed_before_methods = reviewed
        .bundle
        .changed_methods
        .iter()
        .filter(|method| method.side == HistoricalRevisionSide::Parent)
        .map(|method| {
            (
                method.repository_path.as_str(),
                method.symbol_name.as_str(),
                method.start_line,
                method.end_line,
            )
        })
        .collect::<BTreeSet<_>>()
        .len();
    if changed_before_methods == 0 {
        return Err("historical-v2 corpus case has no changed before method".into());
    }
    let case = HistoricalV2CorpusCase {
        label: BenchmarkCase {
            case_id: format!("historical-v2:{final_label_sha256}"),
            language: reviewed.bundle.language.clone(),
            expected_tier: FindingTier::Slop,
            expected_pattern: pattern.as_str().to_string(),
            intentional_boundary: false,
        },
        before,
        after,
        human_explanation: format!(
            "{} Simpler counterfactual: {}",
            final_decision.mechanism.trim(),
            final_decision.simpler_counterfactual.trim()
        ),
        behavioral_evidence: vec![
            format!(
                "identical test plan sha256: {}",
                reviewed.bundle.behavior.test_plan_sha256
            ),
            format!(
                "passing execution sha256: {}",
                reviewed.bundle.behavior.execution_sha256
            ),
            format!(
                "preserved public surface sha256: {}",
                reviewed.bundle.public_surface_delta_sha256
            ),
        ],
        scope: if changed_before_methods == 1 {
            BenchmarkScope::Method
        } else {
            BenchmarkScope::MultiMethod
        },
        expected_proof_level: 3,
        provenance_id: reviewed.bundle.review_item_id.clone(),
        adjudications: corpus_adjudications(reviewed)?,
        disputed: reviewed.audit.status == HistoricalV2LabelStatus::Disputed,
        dispute_resolution: (reviewed.audit.status == HistoricalV2LabelStatus::Disputed)
            .then(|| final_decision.rationale.clone()),
    };
    Ok(HistoricalV2CorpusCaseBinding {
        language: reviewed.language.to_string(),
        slot_number: reviewed.slot_number,
        terminal_checkpoint_sha256: terminal_checkpoint_sha256.clone(),
        review_item_id: review_item_id.clone(),
        source_bundle_artifact_path,
        source_bundle_sha256: source_bundle_sha256.clone(),
        label_audit_sha256: label_audit_sha256.clone(),
        final_label_sha256: final_label_sha256.clone(),
        worksheets: reviewed.worksheets.to_vec(),
        audit: reviewed.audit.clone(),
        resolution: reviewed.resolution.clone(),
        final_label: reviewed.final_label.clone(),
        case,
    })
}
