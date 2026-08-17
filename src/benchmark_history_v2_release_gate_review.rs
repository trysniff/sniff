use super::*;

pub(super) fn validated_review_outcome(
    protocol: &ValidatedHistoricalV2Protocol,
    selection: &HistoricalV2SlotSelection,
    terminal_checkpoint_sha256: &str,
    reviewed: &HistoricalV2ReviewedSlotArtifacts<'_>,
) -> Result<HistoricalV2ReleaseSlotOutcome, String> {
    validate_historical_v2_source_review_bundle(reviewed.bundle_root, reviewed.bundle)?;
    if reviewed.bundle.selection_sha256 != selection.selection_sha256
        || reviewed.bundle.language != reviewed.language
        || reviewed.bundle.terminal_checkpoint_sha256 != terminal_checkpoint_sha256
    {
        return Err("historical-v2 review crossed its frozen terminal slot".into());
    }
    validate_historical_v2_final_label(
        protocol,
        reviewed.bundle_root,
        reviewed.bundle,
        reviewed.worksheets,
        reviewed.audit,
        reviewed.resolution,
        reviewed.final_label,
    )?;
    let common = (
        terminal_checkpoint_sha256.to_string(),
        reviewed.final_label.review_item_id.clone(),
        reviewed.bundle.bundle_sha256.clone(),
        reviewed.audit.audit_sha256.clone(),
        reviewed.final_label.final_sha256.clone(),
    );
    match &reviewed.final_label.outcome {
        HistoricalV2FinalLabelOutcome::Accepted {
            basis,
            pattern,
            other_pattern,
        } => Ok(HistoricalV2ReleaseSlotOutcome::Accepted {
            terminal_checkpoint_sha256: common.0,
            review_item_id: common.1,
            source_bundle_sha256: common.2,
            label_audit_sha256: common.3,
            final_label_sha256: common.4,
            basis: *basis,
            pattern: *pattern,
            other_pattern: other_pattern.clone(),
        }),
        HistoricalV2FinalLabelOutcome::Closed { basis, .. } => {
            Ok(HistoricalV2ReleaseSlotOutcome::ReviewClosed {
                terminal_checkpoint_sha256: common.0,
                review_item_id: common.1,
                source_bundle_sha256: common.2,
                label_audit_sha256: common.3,
                final_label_sha256: common.4,
                basis: *basis,
            })
        }
    }
}
