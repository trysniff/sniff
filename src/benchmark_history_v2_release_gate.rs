use super::*;
use std::collections::BTreeMap;
use std::path::Path;

#[path = "benchmark_history_v2_release_gate_review.rs"]
mod review;
use review::*;

#[path = "benchmark_history_v2_release_gate_persistence.rs"]
mod persistence;
pub use persistence::*;

#[path = "benchmark_history_v2_release_gate_state.rs"]
mod state;
use state::*;

#[path = "benchmark_history_v2_release_gate_summary.rs"]
mod summary;
use summary::*;

#[derive(Clone, Copy)]
pub struct HistoricalV2ReviewedSlotArtifacts<'a> {
    pub language: &'a str,
    pub slot_number: usize,
    pub bundle_root: &'a Path,
    pub bundle: &'a HistoricalV2SourceReviewBundle,
    pub worksheets: &'a [HistoricalV2LabelWorksheet],
    pub audit: &'a HistoricalV2LabelAudit,
    pub resolution: &'a HistoricalV2ResolutionWorksheet,
    pub final_label: &'a HistoricalV2FinalLabel,
}

#[derive(Clone, Copy)]
pub struct HistoricalV2ReleaseGateInputs<'a> {
    pub protocol_bytes: &'a [u8],
    pub artifact_root: &'a Path,
    pub frame: &'a HistoricalV2Frame,
    pub exclusions: &'a HistoricalV2ExclusionManifest,
    pub selection: &'a HistoricalV2SlotSelection,
    pub state_root: &'a Path,
    pub reviewed_slots: &'a [HistoricalV2ReviewedSlotArtifacts<'a>],
}

pub fn build_historical_v2_release_evidence(
    inputs: &HistoricalV2ReleaseGateInputs<'_>,
) -> Result<HistoricalV2ReleaseEvidence, String> {
    let protocol = validate_historical_v2_protocol(inputs.protocol_bytes)?;
    validate_release_protocol(&protocol)?;
    validate_historical_v2_slot_selection(
        inputs.protocol_bytes,
        inputs.artifact_root,
        inputs.frame,
        inputs.exclusions,
        inputs.selection,
    )?;
    validate_historical_v2_state_inventory(inputs.state_root, inputs.selection)?;
    let mut reviews = indexed_reviews(inputs.reviewed_slots)?;
    let mut slots = Vec::with_capacity(inputs.selection.slots.len());
    for slot in &inputs.selection.slots {
        let key = (slot.language.clone(), slot.slot_number);
        let outcome = match &slot.outcome {
            HistoricalV2SlotOutcome::Unfilled => {
                if reviews.remove(&key).is_some() {
                    return Err("historical-v2 review was attached to an unfilled slot".into());
                }
                HistoricalV2ReleaseSlotOutcome::Unfilled
            }
            HistoricalV2SlotOutcome::Selected {
                canonical_repository,
                ..
            } => {
                let terminal = load_historical_v2_terminal_slot(
                    inputs.state_root,
                    inputs.selection,
                    slot,
                    canonical_repository,
                )?;
                match terminal.outcome {
                    HistoricalV2SlotStageOutcome::Excluded { reason, .. } => {
                        if reviews.remove(&key).is_some() {
                            return Err(
                                "historical-v2 review was attached to an execution-excluded slot"
                                    .into(),
                            );
                        }
                        HistoricalV2ReleaseSlotOutcome::Excluded {
                            terminal_checkpoint_sha256: terminal.checkpoint_sha256,
                            stage: terminal.stage,
                            reason,
                        }
                    }
                    HistoricalV2SlotStageOutcome::ReadyForReview => {
                        let reviewed = reviews.remove(&key).ok_or_else(|| {
                            "historical-v2 ready slot has no final independent review".to_string()
                        })?;
                        validated_review_outcome(
                            &protocol,
                            inputs.selection,
                            &terminal.checkpoint_sha256,
                            reviewed,
                        )?
                    }
                    HistoricalV2SlotStageOutcome::Completed { .. } => {
                        return Err("historical-v2 selected slot is not terminal".into());
                    }
                }
            }
        };
        slots.push(HistoricalV2ReleaseSlotEvidence {
            language: slot.language.clone(),
            slot_number: slot.slot_number,
            outcome,
        });
    }
    if !reviews.is_empty() {
        return Err("historical-v2 review does not belong to a frozen ready slot".into());
    }
    validate_historical_v2_state_inventory(inputs.state_root, inputs.selection)?;
    summarize_historical_v2_release(
        &protocol,
        &inputs.selection.selection_sha256,
        inputs.selection.selected_count,
        inputs.selection.unfilled_slot_count,
        slots,
    )
}

pub fn validate_historical_v2_release_evidence(
    inputs: &HistoricalV2ReleaseGateInputs<'_>,
    evidence: &HistoricalV2ReleaseEvidence,
) -> Result<(), String> {
    let expected = build_historical_v2_release_evidence(inputs)?;
    if evidence != &expected {
        return Err("historical-v2 release evidence changed".into());
    }
    Ok(())
}

pub fn require_historical_v2_release_gate(
    inputs: &HistoricalV2ReleaseGateInputs<'_>,
    evidence: &HistoricalV2ReleaseEvidence,
) -> Result<(), String> {
    validate_historical_v2_release_evidence(inputs, evidence)?;
    if evidence.status != HistoricalV2ReleaseGateStatus::Passed {
        return Err("historical-v2 release gate is underfilled".into());
    }
    Ok(())
}

fn indexed_reviews<'a>(
    reviewed: &'a [HistoricalV2ReviewedSlotArtifacts<'a>],
) -> Result<BTreeMap<(String, usize), &'a HistoricalV2ReviewedSlotArtifacts<'a>>, String> {
    let mut indexed = BTreeMap::new();
    for item in reviewed {
        let key = (item.language.to_string(), item.slot_number);
        if item.slot_number == 0 || indexed.insert(key, item).is_some() {
            return Err("historical-v2 reviews repeat or invalidate a fixed slot".into());
        }
    }
    Ok(indexed)
}

fn validate_release_protocol(protocol: &ValidatedHistoricalV2Protocol) -> Result<(), String> {
    let selection = &protocol.protocol.selection;
    let review = &protocol.protocol.review;
    if !selection.failed_candidate_closes_slot
        || !selection.backfill_forbidden
        || !selection.model_access_forbidden
        || !selection.sniff_output_access_forbidden
        || !review.rejected_label_closes_slot
        || !review.underfilled_language_fails_release
    {
        return Err("historical-v2 no-backfill release protocol changed".into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "benchmark_history_v2_release_gate_tests.rs"]
pub(super) mod tests;
