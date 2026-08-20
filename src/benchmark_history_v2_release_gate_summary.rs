use super::*;
use serde::Serialize;
use sha2::{Digest, Sha256};

const RELEASE_CONTRACT: &str = "sniffbench-historical-v2-release-evidence-v1";

pub(super) fn summarize_historical_v2_release(
    protocol: &ValidatedHistoricalV2Protocol,
    selection_sha256: &str,
    expected_selected_count: usize,
    expected_unfilled_count: usize,
    slots: Vec<HistoricalV2ReleaseSlotEvidence>,
) -> Result<HistoricalV2ReleaseEvidence, String> {
    let review = &protocol.protocol.review;
    let mut languages = Vec::new();
    for language in &protocol.protocol.selection.supported_languages {
        let language_slots = slots
            .iter()
            .filter(|slot| &slot.language == language)
            .collect::<Vec<_>>();
        let fixed_slot_count = language_slots.len();
        let unfilled_slot_count = count(&language_slots, |outcome| {
            matches!(outcome, HistoricalV2ReleaseSlotOutcome::Unfilled)
        });
        let execution_excluded_count = count(&language_slots, |outcome| {
            matches!(outcome, HistoricalV2ReleaseSlotOutcome::Excluded { .. })
        });
        let review_closed_count = count(&language_slots, |outcome| {
            matches!(outcome, HistoricalV2ReleaseSlotOutcome::ReviewClosed { .. })
        });
        let accepted_count = count(&language_slots, |outcome| {
            matches!(outcome, HistoricalV2ReleaseSlotOutcome::Accepted { .. })
        });
        let selected_slot_count = fixed_slot_count - unfilled_slot_count;
        if fixed_slot_count != protocol.protocol.selection.slots_per_language
            || selected_slot_count
                != execution_excluded_count + review_closed_count + accepted_count
        {
            return Err("historical-v2 release counts do not cover every fixed slot".into());
        }
        languages.push(HistoricalV2ReleaseLanguageEvidence {
            language: language.clone(),
            fixed_slot_count,
            selected_slot_count,
            unfilled_slot_count,
            execution_excluded_count,
            review_closed_count,
            accepted_count,
            minimum_accepted: review.minimum_accepted_per_language,
            passes: accepted_count >= review.minimum_accepted_per_language,
        });
    }
    let fixed_slot_count = slots.len();
    let selected_slot_count = languages.iter().map(|item| item.selected_slot_count).sum();
    let unfilled_slot_count = languages.iter().map(|item| item.unfilled_slot_count).sum();
    let execution_excluded_count = languages
        .iter()
        .map(|item| item.execution_excluded_count)
        .sum();
    let review_closed_count = languages.iter().map(|item| item.review_closed_count).sum();
    let accepted_count = languages.iter().map(|item| item.accepted_count).sum();
    if fixed_slot_count != protocol.protocol.selection.total_slots
        || selected_slot_count != expected_selected_count
        || unfilled_slot_count != expected_unfilled_count
        || fixed_slot_count != selected_slot_count + unfilled_slot_count
    {
        return Err("historical-v2 release totals changed from the frozen selection".into());
    }
    let status = if accepted_count >= review.minimum_total_accepted
        && languages.iter().all(|item| item.passes)
    {
        HistoricalV2ReleaseGateStatus::Passed
    } else {
        HistoricalV2ReleaseGateStatus::Underfilled
    };
    let mut evidence = HistoricalV2ReleaseEvidence {
        schema_version: HISTORICAL_V2_RELEASE_EVIDENCE_SCHEMA_VERSION,
        release_contract: RELEASE_CONTRACT.to_string(),
        protocol_sha256: protocol.protocol_sha256.clone(),
        selection_sha256: selection_sha256.to_string(),
        fixed_slot_count,
        selected_slot_count,
        unfilled_slot_count,
        execution_excluded_count,
        review_closed_count,
        accepted_count,
        minimum_total_accepted: review.minimum_total_accepted,
        languages,
        slots,
        status,
        evidence_sha256: String::new(),
    };
    evidence.evidence_sha256 = evidence_sha256(&evidence)?;
    Ok(evidence)
}

pub(super) fn validate_historical_v2_release_evidence_structure(
    protocol: &ValidatedHistoricalV2Protocol,
    evidence: &HistoricalV2ReleaseEvidence,
) -> Result<(), String> {
    if !valid_sha256(&evidence.selection_sha256) {
        return Err("historical-v2 release selection commitment is invalid".into());
    }
    validate_slot_ledger(protocol, &evidence.slots)?;
    let unfilled = evidence
        .slots
        .iter()
        .filter(|slot| matches!(slot.outcome, HistoricalV2ReleaseSlotOutcome::Unfilled))
        .count();
    let expected = summarize_historical_v2_release(
        protocol,
        &evidence.selection_sha256,
        evidence.slots.len() - unfilled,
        unfilled,
        evidence.slots.clone(),
    )?;
    if evidence != &expected {
        return Err("historical-v2 release evidence commitment changed".into());
    }
    Ok(())
}

fn validate_slot_ledger(
    protocol: &ValidatedHistoricalV2Protocol,
    slots: &[HistoricalV2ReleaseSlotEvidence],
) -> Result<(), String> {
    let mut index = 0;
    let mut terminal_checkpoints = std::collections::BTreeSet::new();
    let mut review_items = std::collections::BTreeSet::new();
    let mut final_labels = std::collections::BTreeSet::new();
    for language in &protocol.protocol.selection.supported_languages {
        for slot_number in 1..=protocol.protocol.selection.slots_per_language {
            let slot = slots
                .get(index)
                .ok_or_else(|| "historical-v2 release evidence omits a frozen slot".to_string())?;
            if slot.language != *language || slot.slot_number != slot_number {
                return Err("historical-v2 release slot order or identity changed".into());
            }
            validate_slot_outcome(
                &slot.outcome,
                &mut terminal_checkpoints,
                &mut review_items,
                &mut final_labels,
            )?;
            index += 1;
        }
    }
    if index != slots.len() {
        return Err("historical-v2 release evidence adds replacement slots".into());
    }
    Ok(())
}

fn validate_slot_outcome(
    outcome: &HistoricalV2ReleaseSlotOutcome,
    terminal_checkpoints: &mut std::collections::BTreeSet<String>,
    review_items: &mut std::collections::BTreeSet<String>,
    final_labels: &mut std::collections::BTreeSet<String>,
) -> Result<(), String> {
    let terminal = match outcome {
        HistoricalV2ReleaseSlotOutcome::Unfilled => return Ok(()),
        HistoricalV2ReleaseSlotOutcome::Excluded {
            terminal_checkpoint_sha256,
            stage,
            reason,
        } => {
            if *stage != exclusion_stage(reason) {
                return Err("historical-v2 release exclusion changed stages".into());
            }
            terminal_checkpoint_sha256
        }
        HistoricalV2ReleaseSlotOutcome::Accepted {
            terminal_checkpoint_sha256,
            review_item_id,
            source_bundle_sha256,
            label_audit_sha256,
            final_label_sha256,
            basis,
            pattern,
            other_pattern,
        } => {
            let canonical_other = other_pattern
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();
            if !matches!(
                basis,
                HistoricalV2FinalLabelBasis::ReviewerConsensus
                    | HistoricalV2FinalLabelBasis::DisputeResolution
            ) || *pattern == crate::product_contract::SlopPattern::None
                || (*pattern == crate::product_contract::SlopPattern::Other)
                    == other_pattern.is_empty()
                || (*pattern == crate::product_contract::SlopPattern::Other
                    && *other_pattern != canonical_other)
            {
                return Err("historical-v2 accepted release label is invalid".into());
            }
            validate_review_identity(
                review_item_id,
                source_bundle_sha256,
                label_audit_sha256,
                final_label_sha256,
                review_items,
                final_labels,
            )?;
            terminal_checkpoint_sha256
        }
        HistoricalV2ReleaseSlotOutcome::ReviewClosed {
            terminal_checkpoint_sha256,
            review_item_id,
            source_bundle_sha256,
            label_audit_sha256,
            final_label_sha256,
            basis,
        } => {
            if !matches!(
                basis,
                HistoricalV2FinalLabelBasis::ConsensusRejected
                    | HistoricalV2FinalLabelBasis::DisputeResolvedRejected
            ) {
                return Err("historical-v2 closed release label is invalid".into());
            }
            validate_review_identity(
                review_item_id,
                source_bundle_sha256,
                label_audit_sha256,
                final_label_sha256,
                review_items,
                final_labels,
            )?;
            terminal_checkpoint_sha256
        }
    };
    if !valid_sha256(terminal) || !terminal_checkpoints.insert(terminal.clone()) {
        return Err("historical-v2 release repeats or invalidates a terminal checkpoint".into());
    }
    Ok(())
}

fn validate_review_identity(
    review_item_id: &str,
    source_bundle_sha256: &str,
    label_audit_sha256: &str,
    final_label_sha256: &str,
    review_items: &mut std::collections::BTreeSet<String>,
    final_labels: &mut std::collections::BTreeSet<String>,
) -> Result<(), String> {
    let item_hash = review_item_id
        .strip_prefix("hvr-v1:")
        .ok_or_else(|| "historical-v2 release review item is invalid".to_string())?;
    if !valid_sha256(item_hash)
        || !valid_sha256(source_bundle_sha256)
        || !valid_sha256(label_audit_sha256)
        || !valid_sha256(final_label_sha256)
        || !review_items.insert(review_item_id.to_string())
        || !final_labels.insert(final_label_sha256.to_string())
    {
        return Err("historical-v2 release repeats or invalidates a reviewed slot".into());
    }
    Ok(())
}

fn exclusion_stage(reason: &HistoricalV2TerminalExclusionReason) -> HistoricalV2SlotStage {
    match reason {
        HistoricalV2TerminalExclusionReason::Materialization(_) => {
            HistoricalV2SlotStage::Materialization
        }
        HistoricalV2TerminalExclusionReason::TestMaterialization(_) => {
            HistoricalV2SlotStage::TestMaterialization
        }
        HistoricalV2TerminalExclusionReason::SourceCensus(_) => HistoricalV2SlotStage::SourceCensus,
        HistoricalV2TerminalExclusionReason::SemanticCensus(_) => {
            HistoricalV2SlotStage::SemanticCensus
        }
        HistoricalV2TerminalExclusionReason::Qualification(_) => {
            HistoricalV2SlotStage::Qualification
        }
        HistoricalV2TerminalExclusionReason::TestRecipe(_) => HistoricalV2SlotStage::TestRecipe,
        HistoricalV2TerminalExclusionReason::IdenticalTests(_) => {
            HistoricalV2SlotStage::IdenticalTests
        }
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn count(
    slots: &[&HistoricalV2ReleaseSlotEvidence],
    predicate: impl Fn(&HistoricalV2ReleaseSlotOutcome) -> bool,
) -> usize {
    slots.iter().filter(|slot| predicate(&slot.outcome)).count()
}

fn evidence_sha256(evidence: &HistoricalV2ReleaseEvidence) -> Result<String, String> {
    hash_json(&(
        evidence.schema_version,
        &evidence.release_contract,
        &evidence.protocol_sha256,
        &evidence.selection_sha256,
        evidence.fixed_slot_count,
        evidence.selected_slot_count,
        evidence.unfilled_slot_count,
        evidence.execution_excluded_count,
        evidence.review_closed_count,
        evidence.accepted_count,
        evidence.minimum_total_accepted,
        &evidence.languages,
        &evidence.slots,
        evidence.status,
    ))
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v2 release evidence: {error}"))
}
