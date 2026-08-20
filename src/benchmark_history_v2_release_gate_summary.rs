use super::*;
use serde::Serialize;
use sha2::{Digest, Sha256};

const RELEASE_CONTRACT: &str = "sniffbench-historical-v2-release-evidence-v1";

pub(super) fn summarize_historical_v2_release(
    protocol: &ValidatedHistoricalV2Protocol,
    selection: &HistoricalV2SlotSelection,
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
        || selected_slot_count != selection.selected_count
        || unfilled_slot_count != selection.unfilled_slot_count
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
        selection_sha256: selection.selection_sha256.clone(),
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
