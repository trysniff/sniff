use super::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const SELECTION_CONTRACT: &str = "sniffbench-intentional-boundary-fixed-slots-v1";
const RANKING_DOMAIN: &str = "sniffbench-intentional-boundary-v1";

pub fn select_intentional_boundary_slots(
    policy_bytes: &[u8],
    protocol: &ValidatedIntentionalBoundaryProtocol,
    task: &IntentionalBoundaryFrameTask,
    frame: &IntentionalBoundaryCandidateFrame,
) -> Result<IntentionalBoundarySlotSelection, String> {
    validate_intentional_boundary_candidate_frame(task, frame)?;
    if sha256(policy_bytes) != task.policy_sha256
        || protocol.protocol_sha256 != task.protocol_sha256
        || frame.protocol_sha256 != protocol.protocol_sha256
    {
        return Err("intentional-boundary slot inputs changed their frozen protocol".to_string());
    }
    let policy: NonBlindSelectionPolicy = serde_json::from_slice(policy_bytes)
        .map_err(|error| format!("failed to parse intentional-boundary slot policy: {error}"))?;
    if !policy.no_fallbacks
        || policy.intentional_boundaries.cases_per_category
            != protocol.protocol.slot_contract.cases_per_category
        || policy.intentional_boundaries.candidate_ranking_contract
            != protocol.protocol.slot_contract.ranking_contract
    {
        return Err("intentional-boundary slot policy changed".to_string());
    }
    let protocol_categories = protocol
        .protocol
        .category_contracts
        .iter()
        .map(|contract| contract.category)
        .collect::<Vec<_>>();
    let policy_categories = policy
        .intentional_boundaries
        .categories
        .iter()
        .map(|category| parse_category(category))
        .collect::<Result<Vec<_>, _>>()?;
    if policy_categories != protocol_categories {
        return Err("intentional-boundary slot categories changed".to_string());
    }

    let mut ranked = BTreeMap::<IntentionalBoundaryCategory, Vec<RankedCandidate>>::new();
    for candidate in &frame.candidates {
        ranked
            .entry(candidate.category)
            .or_default()
            .push(RankedCandidate {
                digest: candidate_rank_sha256(&policy.ranking_seed, candidate),
                identity: candidate_identity(candidate),
                candidate_id: candidate.candidate_id.clone(),
            });
    }
    for candidates in ranked.values_mut() {
        candidates.sort();
    }
    let cases_per_category = protocol.protocol.slot_contract.cases_per_category;
    let mut slots = Vec::with_capacity(protocol.protocol.slot_contract.total_slots);
    for category in protocol_categories {
        let candidates = ranked.get(&category).map(Vec::as_slice).unwrap_or_default();
        for slot_number in 1..=cases_per_category {
            let outcome = candidates.get(slot_number - 1).map_or_else(
                || IntentionalBoundarySlotOutcome::Unfilled {
                    available_candidate_count: candidates.len(),
                },
                |candidate| IntentionalBoundarySlotOutcome::Selected {
                    candidate_id: candidate.candidate_id.clone(),
                    candidate_rank_sha256: candidate.digest.clone(),
                },
            );
            slots.push(IntentionalBoundarySlot {
                category,
                slot_number,
                outcome,
            });
        }
    }
    if slots.len() != protocol.protocol.slot_contract.total_slots {
        return Err("intentional-boundary fixed-slot cardinality changed".to_string());
    }
    let selected_candidate_count = slots
        .iter()
        .filter(|slot| {
            matches!(
                slot.outcome,
                IntentionalBoundarySlotOutcome::Selected { .. }
            )
        })
        .count();
    let mut selection = IntentionalBoundarySlotSelection {
        schema_version: INTENTIONAL_BOUNDARY_SLOT_SELECTION_SCHEMA_VERSION,
        selection_contract: SELECTION_CONTRACT.to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        candidate_frame_sha256: frame.frame_sha256.clone(),
        protocol_sha256: protocol.protocol_sha256.clone(),
        policy_sha256: task.policy_sha256.clone(),
        ranking_seed: policy.ranking_seed,
        ranking_contract: protocol.protocol.slot_contract.ranking_contract.clone(),
        cases_per_category,
        slots,
        selected_candidate_count,
        unfilled_slot_count: protocol.protocol.slot_contract.total_slots - selected_candidate_count,
        selection_sha256: String::new(),
    };
    selection.selection_sha256 = selection_sha256(&selection)?;
    Ok(selection)
}

pub fn validate_intentional_boundary_slot_selection(
    policy_bytes: &[u8],
    protocol: &ValidatedIntentionalBoundaryProtocol,
    task: &IntentionalBoundaryFrameTask,
    frame: &IntentionalBoundaryCandidateFrame,
    selection: &IntentionalBoundarySlotSelection,
) -> Result<(), String> {
    let expected = select_intentional_boundary_slots(policy_bytes, protocol, task, frame)?;
    if selection != &expected {
        return Err("intentional-boundary fixed-slot selection changed".to_string());
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct RankedCandidate {
    digest: String,
    identity: (String, String, String, String, String),
    candidate_id: String,
}

fn candidate_rank_sha256(seed: &str, candidate: &IntentionalBoundaryCandidate) -> String {
    sha256(
        format!(
            "{RANKING_DOMAIN}\0{seed}\0{}\0{}\0{}",
            candidate.revision, candidate.repository_path, candidate.exact_symbol_identity
        )
        .as_bytes(),
    )
}

fn candidate_identity(
    candidate: &IntentionalBoundaryCandidate,
) -> (String, String, String, String, String) {
    (
        candidate.repository.clone(),
        candidate.revision.clone(),
        candidate.repository_path.clone(),
        candidate.exact_symbol_identity.clone(),
        candidate.candidate_id.clone(),
    )
}

fn parse_category(value: &str) -> Result<IntentionalBoundaryCategory, String> {
    serde_json::from_value(serde_json::Value::String(value.to_string()))
        .map_err(|_| format!("unknown intentional-boundary category {value}"))
}

fn selection_sha256(selection: &IntentionalBoundarySlotSelection) -> Result<String, String> {
    hash_json(&(
        selection.schema_version,
        &selection.selection_contract,
        &selection.frame_task_sha256,
        &selection.candidate_frame_sha256,
        &selection.protocol_sha256,
        &selection.policy_sha256,
        &selection.ranking_seed,
        &selection.ranking_contract,
        selection.cases_per_category,
        &selection.slots,
        selection.selected_candidate_count,
        selection.unfilled_slot_count,
    ))
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to commit intentional-boundary slots: {error}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_slots_tests.rs"]
mod tests;
