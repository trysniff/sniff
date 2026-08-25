use super::{
    HistoricalV2PayloadStageInputs, HistoricalV2SelectedPayload,
    HistoricalV2SelectedSlotRunSummary, HistoricalV2SelectedSlotSweepInputs,
    HistoricalV2SelectedSlotSweepSummary, HistoricalV2SlotOperations, HistoricalV2SlotOutcome,
    HistoricalV2SlotRunDisposition, HistoricalV2SlotRunIdentity, HistoricalV2SlotStage,
    HistoricalV2SlotStageError, HistoricalV2SlotStageJournal, run_historical_v2_slot_slice_through,
    validate_historical_v2_protocol, validate_historical_v2_selected_payloads_commitment,
    validate_historical_v2_slot_selection,
};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

pub async fn run_historical_v2_selected_slots_bounded<E>(
    inputs: HistoricalV2SelectedSlotSweepInputs<'_, E>,
    maximum_new_slots: NonZeroUsize,
    maximum_new_stages_per_slot: Option<NonZeroUsize>,
) -> Result<HistoricalV2SelectedSlotSweepSummary, HistoricalV2SlotStageError>
where
    E: super::HistoricalV2RecoverableTestExecutor,
{
    run_selected_slots(inputs, maximum_new_slots, maximum_new_stages_per_slot).await
}

async fn run_selected_slots<E>(
    inputs: HistoricalV2SelectedSlotSweepInputs<'_, E>,
    maximum_new_slots: NonZeroUsize,
    maximum_new_stages_per_slot: Option<NonZeroUsize>,
) -> Result<HistoricalV2SelectedSlotSweepSummary, HistoricalV2SlotStageError>
where
    E: super::HistoricalV2RecoverableTestExecutor,
{
    let protocol = validate_historical_v2_protocol(inputs.protocol_bytes).map_err(invalid)?;
    validate_historical_v2_slot_selection(
        inputs.protocol_bytes,
        inputs.artifact_root,
        inputs.frame,
        inputs.exclusions,
        inputs.selection,
    )
    .map_err(invalid)?;
    validate_historical_v2_selected_payloads_commitment(
        &protocol,
        inputs.frame,
        inputs.exclusions,
        inputs.selection,
        inputs.payloads,
    )
    .map_err(invalid)?;
    let roots = SweepRoots::prepare(
        inputs.state_root,
        inputs.work_root,
        inputs.artifact_root,
        inputs.harness_repository_root,
    )?;
    validate_existing_language_roots(
        &roots.state,
        inputs
            .payloads
            .records
            .iter()
            .map(|payload| payload.language.as_str()),
    )?;
    for payload in &inputs.payloads.records {
        validate_slot_entry_shapes(&roots.state, &payload.language, payload.slot_number)?;
    }
    let mut slots = Vec::with_capacity(inputs.payloads.records.len());
    let mut newly_admitted_slot_count = 0;
    for payload in &inputs.payloads.records {
        let canonical_repository = selected_repository(inputs.selection, payload)?;
        let identity = HistoricalV2SlotRunIdentity {
            selection_sha256: &inputs.selection.selection_sha256,
            language: &payload.language,
            slot_number: payload.slot_number,
            canonical_repository,
        };
        let started = slot_has_persisted_stage(&roots.state, identity)?;
        if !started && newly_admitted_slot_count >= maximum_new_slots.get() {
            slots.push(HistoricalV2SelectedSlotRunSummary {
                language: payload.language.clone(),
                slot_number: payload.slot_number,
                canonical_repository: canonical_repository.to_string(),
                run: unadmitted_slot_summary(),
            });
            continue;
        }
        if !started {
            newly_admitted_slot_count += 1;
        }
        let mut operations = HistoricalV2SlotOperations::new(
            inputs.client,
            HistoricalV2PayloadStageInputs {
                protocol_bytes: inputs.protocol_bytes,
                artifact_root: &roots.artifact,
                frame: inputs.frame,
                exclusions: inputs.exclusions,
                selection: inputs.selection,
                payloads: inputs.payloads,
                language: &payload.language,
                slot_number: payload.slot_number,
            },
            &roots.work,
            &roots.harness,
            inputs.test_executor,
        )?;
        let run = run_historical_v2_slot_slice_through(
            &roots.state,
            identity,
            &mut operations,
            maximum_new_stages_per_slot,
            inputs.through_stage,
        )
        .await?;
        super::history_v2_slot_operations_support::reconcile_terminal_slot_work(
            &roots.work,
            &payload.language,
            payload.slot_number,
            &run.disposition,
        )?;
        slots.push(HistoricalV2SelectedSlotRunSummary {
            language: payload.language.clone(),
            slot_number: payload.slot_number,
            canonical_repository: canonical_repository.to_string(),
            run,
        });
    }
    summarize(
        slots,
        inputs.selection.selected_count,
        newly_admitted_slot_count,
    )
}

fn validate_existing_language_roots<'a>(
    state_root: &Path,
    languages: impl IntoIterator<Item = &'a str>,
) -> Result<(), HistoricalV2SlotStageError> {
    for language in languages.into_iter().collect::<BTreeSet<_>>() {
        let language_root = state_root.join(language);
        match fs::symlink_metadata(&language_root) {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(invalid(format!(
                    "failed to inspect historical-v2 language state: {error}"
                )));
            }
        }
        require_plain_directory(&language_root, "historical-v2 language state")?;
        let resolved = fs::canonicalize(&language_root).map_err(|error| {
            infrastructure(format!(
                "failed to resolve historical-v2 language state: {error}"
            ))
        })?;
        if resolved.parent() != Some(state_root) {
            return Err(invalid(
                "historical-v2 language state escaped its state root",
            ));
        }
    }
    Ok(())
}

fn slot_has_persisted_stage(
    state_root: &Path,
    identity: HistoricalV2SlotRunIdentity<'_>,
) -> Result<bool, HistoricalV2SlotStageError> {
    let (slot_exists, lock_exists, staging_exists) =
        validate_slot_entry_shapes(state_root, identity.language, identity.slot_number)?;
    if !slot_exists && !lock_exists && !staging_exists {
        return Ok(false);
    }
    let journal =
        HistoricalV2SlotStageJournal::open(state_root, identity.language, identity.slot_number)?;
    validate_existing_slot_identity(journal.history(), identity)?;
    Ok(!journal.history().is_empty())
}

fn validate_slot_entry_shapes(
    state_root: &Path,
    language: &str,
    slot_number: usize,
) -> Result<(bool, bool, bool), HistoricalV2SlotStageError> {
    let language_root = state_root.join(language);
    let slot_name = format!("slot-{slot_number:04}");
    let slot_root = language_root.join(&slot_name);
    let lock_path = language_root.join(format!("{slot_name}.lock"));
    let staging_root = language_root.join(format!(".{slot_name}.incomplete"));
    let slot_exists = optional_plain_entry(&slot_root, EntryKind::Directory)?;
    let lock_exists = optional_plain_entry(&lock_path, EntryKind::File)?;
    let staging_exists = optional_plain_entry(&staging_root, EntryKind::Directory)?;
    Ok((slot_exists, lock_exists, staging_exists))
}

#[derive(Clone, Copy)]
enum EntryKind {
    Directory,
    File,
}

fn optional_plain_entry(
    path: &Path,
    expected: EntryKind,
) -> Result<bool, HistoricalV2SlotStageError> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if !metadata.file_type().is_symlink()
                && match expected {
                    EntryKind::Directory => metadata.is_dir(),
                    EntryKind::File => metadata.is_file(),
                } =>
        {
            Ok(true)
        }
        Ok(_) => Err(invalid(format!(
            "historical-v2 slot state has the wrong entry type: {}",
            path.display()
        ))),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(invalid(format!(
            "failed to inspect historical-v2 slot state: {error}"
        ))),
    }
}

fn validate_existing_slot_identity(
    history: &[super::HistoricalV2StoredSlotStage],
    identity: HistoricalV2SlotRunIdentity<'_>,
) -> Result<(), HistoricalV2SlotStageError> {
    let Some(first) = history.first() else {
        return Ok(());
    };
    let checkpoint = &first.checkpoint;
    if checkpoint.selection_sha256 != identity.selection_sha256
        || checkpoint.language != identity.language
        || checkpoint.slot_number != identity.slot_number
        || checkpoint.canonical_repository != identity.canonical_repository
    {
        return Err(invalid(
            "historical-v2 runner identity changed across resume",
        ));
    }
    Ok(())
}

fn unadmitted_slot_summary() -> super::HistoricalV2SlotRunSummary {
    super::HistoricalV2SlotRunSummary {
        resumed_after_sequence: 0,
        executed_stages: Vec::new(),
        terminal_checkpoint_sha256: None,
        disposition: HistoricalV2SlotRunDisposition::Paused {
            next_stage: HistoricalV2SlotStage::Payload,
        },
    }
}

fn selected_repository<'a>(
    selection: &'a super::HistoricalV2SlotSelection,
    payload: &HistoricalV2SelectedPayload,
) -> Result<&'a str, HistoricalV2SlotStageError> {
    let slot = selection
        .slots
        .iter()
        .find(|slot| slot.language == payload.language && slot.slot_number == payload.slot_number)
        .ok_or_else(|| invalid("historical-v2 selected payload has no fixed slot"))?;
    match &slot.outcome {
        HistoricalV2SlotOutcome::Selected {
            global_row_index,
            instance_id,
            canonical_repository,
            ..
        } if *global_row_index == payload.global_row_index
            && instance_id == &payload.instance_id =>
        {
            Ok(canonical_repository)
        }
        _ => Err(invalid(
            "historical-v2 selected payload changed from its fixed-slot identity",
        )),
    }
}

fn summarize(
    slots: Vec<HistoricalV2SelectedSlotRunSummary>,
    expected_count: usize,
    newly_admitted_slot_count: usize,
) -> Result<HistoricalV2SelectedSlotSweepSummary, HistoricalV2SlotStageError> {
    if slots.len() != expected_count {
        return Err(invalid(
            "historical-v2 selected slot sweep did not cover every fixed slot",
        ));
    }
    let ready_for_review_count = slots
        .iter()
        .filter(|slot| {
            matches!(
                slot.run.disposition,
                HistoricalV2SlotRunDisposition::ReadyForReview
            )
        })
        .count();
    let excluded_count = slots
        .iter()
        .filter(|slot| {
            matches!(
                slot.run.disposition,
                HistoricalV2SlotRunDisposition::Excluded { .. }
            )
        })
        .count();
    let paused_count = slots
        .iter()
        .filter(|slot| {
            matches!(
                slot.run.disposition,
                HistoricalV2SlotRunDisposition::Paused { .. }
            )
        })
        .count();
    Ok(HistoricalV2SelectedSlotSweepSummary {
        selected_slot_count: slots.len(),
        newly_admitted_slot_count,
        ready_for_review_count,
        excluded_count,
        paused_count,
        slots,
    })
}

#[derive(Debug)]
struct SweepRoots {
    state: PathBuf,
    work: PathBuf,
    artifact: PathBuf,
    harness: PathBuf,
}

impl SweepRoots {
    fn prepare(
        state: &Path,
        work: &Path,
        artifact: &Path,
        harness: &Path,
    ) -> Result<Self, HistoricalV2SlotStageError> {
        let artifact = existing_plain_directory(artifact, "historical-v2 artifact root")?;
        let harness = existing_plain_directory(harness, "historical-v2 harness repository")?;
        let planned_state = prospective_plain_directory(state, "historical-v2 state root")?;
        let planned_work = prospective_plain_directory(work, "historical-v2 work root")?;
        require_separate_roots(&planned_state, &planned_work, &artifact, &harness)?;
        let state = create_plain_directory(state, "historical-v2 state root")?;
        let work = create_plain_directory(work, "historical-v2 work root")?;
        if state != planned_state || work != planned_work {
            return Err(infrastructure(
                "historical-v2 mutable root identity changed during creation",
            ));
        }
        require_separate_roots(&state, &work, &artifact, &harness)?;
        Ok(Self {
            state,
            work,
            artifact,
            harness,
        })
    }
}

fn require_separate_roots(
    state: &Path,
    work: &Path,
    artifact: &Path,
    harness: &Path,
) -> Result<(), HistoricalV2SlotStageError> {
    for (left, right, label) in [
        (state, work, "state and work roots"),
        (state, artifact, "state and artifact roots"),
        (state, harness, "state and harness roots"),
        (work, artifact, "work and artifact roots"),
        (work, harness, "work and harness roots"),
    ] {
        if overlaps(left, right) {
            return Err(invalid(format!("historical-v2 {label} must not overlap")));
        }
    }
    Ok(())
}

fn prospective_plain_directory(
    path: &Path,
    label: &str,
) -> Result<PathBuf, HistoricalV2SlotStageError> {
    if !path.is_absolute() {
        return Err(invalid(format!("{label} must be absolute")));
    }
    if path.exists() {
        return existing_plain_directory(path, label);
    }
    let mut ancestor = path;
    let mut missing = Vec::<OsString>::new();
    while !ancestor.exists() {
        let component = ancestor
            .file_name()
            .ok_or_else(|| invalid(format!("{label} has no existing ancestor")))?;
        if component == "." || component == ".." {
            return Err(invalid(format!("{label} must not contain dot components")));
        }
        missing.push(component.to_os_string());
        ancestor = ancestor
            .parent()
            .ok_or_else(|| invalid(format!("{label} has no existing ancestor")))?;
    }
    let mut resolved = existing_plain_directory(ancestor, label)?;
    for component in missing.into_iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

fn create_plain_directory(path: &Path, label: &str) -> Result<PathBuf, HistoricalV2SlotStageError> {
    if !path.is_absolute() {
        return Err(invalid(format!("{label} must be absolute")));
    }
    if path.exists() {
        require_plain_directory(path, label)?;
    } else {
        fs::create_dir_all(path)
            .map_err(|error| infrastructure(format!("failed to create {label}: {error}")))?;
    }
    existing_plain_directory(path, label)
}

fn existing_plain_directory(
    path: &Path,
    label: &str,
) -> Result<PathBuf, HistoricalV2SlotStageError> {
    if !path.is_absolute() {
        return Err(invalid(format!("{label} must be absolute")));
    }
    require_plain_directory(path, label)?;
    fs::canonicalize(path)
        .map_err(|error| infrastructure(format!("failed to resolve {label}: {error}")))
}

fn require_plain_directory(path: &Path, label: &str) -> Result<(), HistoricalV2SlotStageError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| invalid(format!("failed to inspect {label}: {error}")))?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(invalid(format!("{label} must be a plain directory")))
    }
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn invalid(detail: impl Into<String>) -> HistoricalV2SlotStageError {
    HistoricalV2SlotStageError::invalid(HistoricalV2SlotStage::Payload, detail)
}

fn infrastructure(detail: impl Into<String>) -> HistoricalV2SlotStageError {
    HistoricalV2SlotStageError::infrastructure(HistoricalV2SlotStage::Payload, detail)
}

#[cfg(test)]
#[path = "benchmark_history_v2_slot_sweep_tests.rs"]
mod tests;
