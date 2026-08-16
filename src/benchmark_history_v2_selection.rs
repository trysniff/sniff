use super::{
    HISTORICAL_V2_SLOT_SELECTION_SCHEMA_VERSION, HistoricalV2CandidateDecision,
    HistoricalV2CandidateOutcome, HistoricalV2ExclusionManifest, HistoricalV2Frame,
    HistoricalV2FrameDisposition, HistoricalV2Slot, HistoricalV2SlotOutcome,
    HistoricalV2SlotSelection, historical_v2_rank_sha256,
    validate_historical_v2_exclusion_manifest, validate_historical_v2_frame_commitment,
    validate_historical_v2_protocol,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

const SELECTION_CONTRACT: &str = "sniffbench-historical-v2-fixed-slots-v1";

pub fn select_historical_v2_slots(
    protocol_bytes: &[u8],
    artifact_root: &Path,
    frame: &HistoricalV2Frame,
    exclusions: &HistoricalV2ExclusionManifest,
) -> Result<HistoricalV2SlotSelection, String> {
    let protocol = validate_historical_v2_protocol(protocol_bytes)?;
    validate_historical_v2_frame_commitment(frame)?;
    validate_historical_v2_exclusion_manifest(protocol_bytes, artifact_root, exclusions)?;
    if frame.protocol_sha256 != protocol.protocol_sha256
        || frame.dataset_revision != protocol.protocol.dataset.revision
        || frame.ranking_seed != protocol.protocol.selection.ranking_seed
    {
        return Err("historical-v2 frame does not belong to the frozen protocol".to_string());
    }

    let supported = protocol
        .protocol
        .selection
        .supported_languages
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut candidates = frame
        .records
        .iter()
        .filter_map(|record| match &record.disposition {
            HistoricalV2FrameDisposition::Eligible { facts, rank_sha256 } => {
                Some((record, facts.language.as_str(), rank_sha256.as_str()))
            }
            HistoricalV2FrameDisposition::Excluded { .. } => None,
        })
        .map(|(record, language, rank_sha256)| {
            let repository = record
                .canonical_repository
                .as_deref()
                .ok_or_else(|| "eligible historical-v2 row has no repository".to_string())?;
            let pull_number = record
                .pull_number
                .ok_or_else(|| "eligible historical-v2 row has no pull number".to_string())?;
            let revision = record
                .base_revision
                .as_deref()
                .ok_or_else(|| "eligible historical-v2 row has no base revision".to_string())?;
            if !supported.contains(language) {
                return Err(format!(
                    "eligible historical-v2 row has unsupported language {language}"
                ));
            }
            let expected_rank = historical_v2_rank_sha256(
                &frame.ranking_seed,
                repository,
                pull_number,
                revision,
                &record.patch_sha256,
            );
            if rank_sha256 != expected_rank {
                return Err("historical-v2 candidate rank changed".to_string());
            }
            Ok(RankedCandidate {
                global_row_index: record.global_row_index,
                instance_id: record.instance_id.clone(),
                canonical_repository: repository.to_string(),
                pull_number,
                base_revision: revision.to_string(),
                patch_sha256: record.patch_sha256.clone(),
                language: language.to_string(),
                rank_sha256: expected_rank,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let mut pull_requests = BTreeSet::new();
    for candidate in &candidates {
        if !pull_requests.insert((
            candidate.canonical_repository.as_str(),
            candidate.pull_number,
        )) {
            return Err("historical-v2 frame repeats an eligible pull request".to_string());
        }
    }
    candidates.sort();

    let excluded_repositories = excluded_repositories(exclusions);
    let mut selected_repositories = BTreeMap::<String, usize>::new();
    let mut language_counts = BTreeMap::<String, usize>::new();
    let mut decisions = Vec::with_capacity(candidates.len());
    let slots_per_language = protocol.protocol.selection.slots_per_language;
    for (index, candidate) in candidates.into_iter().enumerate() {
        let outcome = if let Some(partitions) =
            excluded_repositories.get(candidate.canonical_repository.as_str())
        {
            HistoricalV2CandidateOutcome::ExcludedPartition {
                partitions: partitions.clone(),
            }
        } else if let Some(selected_global_row_index) =
            selected_repositories.get(candidate.canonical_repository.as_str())
        {
            HistoricalV2CandidateOutcome::RepositoryAlreadySelected {
                selected_global_row_index: *selected_global_row_index,
            }
        } else {
            let count = language_counts
                .entry(candidate.language.clone())
                .or_default();
            if *count == slots_per_language {
                HistoricalV2CandidateOutcome::LanguageSlotsFilled
            } else {
                *count += 1;
                selected_repositories.insert(
                    candidate.canonical_repository.clone(),
                    candidate.global_row_index,
                );
                HistoricalV2CandidateOutcome::Selected {
                    slot_number: *count,
                }
            }
        };
        decisions.push(candidate.into_decision(index + 1, outcome));
    }

    let slots = build_slots(
        &protocol.protocol.selection.supported_languages,
        slots_per_language,
        &decisions,
    )?;
    let selected_count = decisions
        .iter()
        .filter(|decision| {
            matches!(
                decision.outcome,
                HistoricalV2CandidateOutcome::Selected { .. }
            )
        })
        .count();
    let mut selection = HistoricalV2SlotSelection {
        schema_version: HISTORICAL_V2_SLOT_SELECTION_SCHEMA_VERSION,
        selection_contract: SELECTION_CONTRACT.to_string(),
        protocol_sha256: protocol.protocol_sha256,
        frame_sha256: frame.frame_sha256.clone(),
        exclusion_manifest_sha256: exclusions.manifest_sha256.clone(),
        ranking_seed: protocol.protocol.selection.ranking_seed,
        ranking_contract: protocol.protocol.selection.ranking_contract,
        slots_per_language,
        candidate_decisions: decisions,
        unfilled_slot_count: protocol.protocol.selection.total_slots - selected_count,
        slots,
        selected_count,
        excluded_partition_count: 0,
        repository_collision_count: 0,
        language_capacity_count: 0,
        selection_sha256: String::new(),
    };
    selection.excluded_partition_count = count_outcomes(&selection, |outcome| {
        matches!(
            outcome,
            HistoricalV2CandidateOutcome::ExcludedPartition { .. }
        )
    });
    selection.repository_collision_count = count_outcomes(&selection, |outcome| {
        matches!(
            outcome,
            HistoricalV2CandidateOutcome::RepositoryAlreadySelected { .. }
        )
    });
    selection.language_capacity_count = count_outcomes(&selection, |outcome| {
        matches!(outcome, HistoricalV2CandidateOutcome::LanguageSlotsFilled)
    });
    selection.selection_sha256 = selection_sha256(&selection)?;
    Ok(selection)
}

pub fn validate_historical_v2_slot_selection(
    protocol_bytes: &[u8],
    artifact_root: &Path,
    frame: &HistoricalV2Frame,
    exclusions: &HistoricalV2ExclusionManifest,
    selection: &HistoricalV2SlotSelection,
) -> Result<(), String> {
    let expected = select_historical_v2_slots(protocol_bytes, artifact_root, frame, exclusions)?;
    if selection != &expected {
        return Err("historical-v2 fixed-slot selection changed".to_string());
    }
    Ok(())
}

pub fn write_historical_v2_slot_selection(
    protocol_bytes: &[u8],
    artifact_root: &Path,
    frame: &HistoricalV2Frame,
    exclusions: &HistoricalV2ExclusionManifest,
    output_path: &Path,
) -> Result<HistoricalV2SlotSelection, String> {
    let selection = select_historical_v2_slots(protocol_bytes, artifact_root, frame, exclusions)?;
    write_create_new(output_path, &selection, "historical-v2 slot selection")?;
    Ok(selection)
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct RankedCandidate {
    rank_sha256: String,
    canonical_repository: String,
    pull_number: u64,
    base_revision: String,
    patch_sha256: String,
    global_row_index: usize,
    instance_id: String,
    language: String,
}

impl RankedCandidate {
    fn into_decision(
        self,
        global_rank: usize,
        outcome: HistoricalV2CandidateOutcome,
    ) -> HistoricalV2CandidateDecision {
        HistoricalV2CandidateDecision {
            global_rank,
            global_row_index: self.global_row_index,
            instance_id: self.instance_id,
            canonical_repository: self.canonical_repository,
            pull_number: self.pull_number,
            base_revision: self.base_revision,
            patch_sha256: self.patch_sha256,
            language: self.language,
            rank_sha256: self.rank_sha256,
            outcome,
        }
    }
}

fn build_slots(
    languages: &[String],
    slots_per_language: usize,
    decisions: &[HistoricalV2CandidateDecision],
) -> Result<Vec<HistoricalV2Slot>, String> {
    let selected = decisions
        .iter()
        .filter_map(|decision| match decision.outcome {
            HistoricalV2CandidateOutcome::Selected { slot_number } => {
                Some(((decision.language.as_str(), slot_number), decision))
            }
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let selected_decision_count = decisions
        .iter()
        .filter(|decision| {
            matches!(
                decision.outcome,
                HistoricalV2CandidateOutcome::Selected { .. }
            )
        })
        .count();
    if selected.len() != selected_decision_count {
        return Err("historical-v2 candidates repeat a fixed slot".to_string());
    }
    let mut slots = Vec::with_capacity(languages.len() * slots_per_language);
    for language in languages {
        for slot_number in 1..=slots_per_language {
            let outcome = selected.get(&(language.as_str(), slot_number)).map_or(
                HistoricalV2SlotOutcome::Unfilled,
                |decision| HistoricalV2SlotOutcome::Selected {
                    global_row_index: decision.global_row_index,
                    instance_id: decision.instance_id.clone(),
                    canonical_repository: decision.canonical_repository.clone(),
                    pull_number: decision.pull_number,
                    base_revision: decision.base_revision.clone(),
                    patch_sha256: decision.patch_sha256.clone(),
                    rank_sha256: decision.rank_sha256.clone(),
                },
            );
            slots.push(HistoricalV2Slot {
                language: language.clone(),
                slot_number,
                outcome,
            });
        }
    }
    if selected.len()
        != slots
            .iter()
            .filter(|slot| matches!(slot.outcome, HistoricalV2SlotOutcome::Selected { .. }))
            .count()
    {
        return Err("historical-v2 selected candidate occupies an invalid slot".to_string());
    }
    Ok(slots)
}

fn excluded_repositories(manifest: &HistoricalV2ExclusionManifest) -> BTreeMap<&str, Vec<String>> {
    let mut excluded = BTreeMap::<&str, Vec<String>>::new();
    for partition in &manifest.partitions {
        for repository in &partition.repositories {
            excluded
                .entry(repository)
                .or_default()
                .push(partition.partition.clone());
        }
    }
    excluded
}

fn count_outcomes(
    selection: &HistoricalV2SlotSelection,
    predicate: impl Fn(&HistoricalV2CandidateOutcome) -> bool,
) -> usize {
    selection
        .candidate_decisions
        .iter()
        .filter(|decision| predicate(&decision.outcome))
        .count()
}

fn selection_sha256(selection: &HistoricalV2SlotSelection) -> Result<String, String> {
    hash_json(&(
        selection.schema_version,
        &selection.selection_contract,
        &selection.protocol_sha256,
        &selection.frame_sha256,
        &selection.exclusion_manifest_sha256,
        &selection.ranking_seed,
        &selection.ranking_contract,
        selection.slots_per_language,
        &selection.candidate_decisions,
        &selection.slots,
        selection.selected_count,
        selection.unfilled_slot_count,
        selection.excluded_partition_count,
        selection.repository_collision_count,
        selection.language_capacity_count,
    ))
}

fn write_create_new(path: &Path, value: &impl Serialize, label: &str) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("failed to serialize {label}: {error}"))?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("failed to create {label}: {error}"))?;
    output
        .write_all(&bytes)
        .and_then(|()| output.sync_all())
        .map_err(|error| format!("failed to persist {label}: {error}"))
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit historical-v2 artifact: {error}"))
}
