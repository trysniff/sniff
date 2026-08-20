use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

pub(super) fn validate_historical_v2_state_inventory(
    state_root: &Path,
    selection: &HistoricalV2SlotSelection,
) -> Result<(), String> {
    require_plain_directory(state_root, "historical-v2 release state root")?;
    let mut expected = BTreeMap::<String, BTreeSet<String>>::new();
    for slot in &selection.slots {
        if matches!(slot.outcome, HistoricalV2SlotOutcome::Selected { .. }) {
            let names = expected.entry(slot.language.clone()).or_default();
            let slot_name = format!("slot-{:04}", slot.slot_number);
            names.insert(slot_name.clone());
            names.insert(format!("{slot_name}.lock"));
        }
    }
    let actual_languages = directory_names(state_root)?;
    if actual_languages != expected.keys().cloned().collect() {
        return Err("historical-v2 state contains missing or replacement languages".into());
    }
    for (language, expected_entries) in expected {
        let language_root = state_root.join(&language);
        require_plain_directory(&language_root, "historical-v2 release language state")?;
        if directory_entry_names(&language_root)? != expected_entries {
            return Err(format!(
                "historical-v2 state for {language} contains missing or replacement slots"
            ));
        }
    }
    Ok(())
}

pub(super) fn load_historical_v2_terminal_slot(
    state_root: &Path,
    selection: &HistoricalV2SlotSelection,
    slot: &HistoricalV2Slot,
    canonical_repository: &str,
) -> Result<HistoricalV2SlotStageCheckpoint, String> {
    let journal =
        HistoricalV2SlotStageJournal::open_existing(state_root, &slot.language, slot.slot_number)
            .map_err(|error| error.detail)?;
    let first = journal
        .history()
        .first()
        .ok_or_else(|| "historical-v2 selected slot has no durable journal".to_string())?;
    if first.checkpoint.selection_sha256 != selection.selection_sha256
        || first.checkpoint.language != slot.language
        || first.checkpoint.slot_number != slot.slot_number
        || first.checkpoint.canonical_repository != canonical_repository
    {
        return Err("historical-v2 terminal journal changed its frozen slot identity".into());
    }
    let terminal = journal
        .history()
        .last()
        .ok_or_else(|| "historical-v2 selected slot has no terminal checkpoint".to_string())?
        .checkpoint
        .clone();
    if !matches!(
        terminal.outcome,
        HistoricalV2SlotStageOutcome::Excluded { .. }
            | HistoricalV2SlotStageOutcome::ReadyForReview
    ) {
        return Err("historical-v2 selected slot is not terminal".into());
    }
    Ok(terminal)
}

fn require_plain_directory(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {label}: {error}"))?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(format!("{label} is not a plain directory"))
    }
}

fn directory_names(root: &Path) -> Result<BTreeSet<String>, String> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(root)
        .map_err(|error| format!("failed to inspect historical-v2 state: {error}"))?
    {
        let entry =
            entry.map_err(|error| format!("failed to inspect historical-v2 state: {error}"))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("failed to inspect historical-v2 state: {error}"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("historical-v2 state root contains a non-directory".into());
        }
        names.insert(
            entry
                .file_name()
                .into_string()
                .map_err(|_| "historical-v2 state language is not UTF-8".to_string())?,
        );
    }
    Ok(names)
}

fn directory_entry_names(root: &Path) -> Result<BTreeSet<String>, String> {
    fs::read_dir(root)
        .map_err(|error| format!("failed to inspect historical-v2 language state: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| {
                    format!("failed to inspect historical-v2 language state: {error}")
                })?
                .file_name()
                .into_string()
                .map_err(|_| "historical-v2 slot state name is not UTF-8".to_string())
        })
        .collect()
}
