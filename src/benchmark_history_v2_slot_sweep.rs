use super::{
    HistoricalV2PayloadStageInputs, HistoricalV2SelectedPayload,
    HistoricalV2SelectedSlotRunSummary, HistoricalV2SelectedSlotSweepInputs,
    HistoricalV2SelectedSlotSweepSummary, HistoricalV2SlotOperations, HistoricalV2SlotOutcome,
    HistoricalV2SlotRunDisposition, HistoricalV2SlotRunIdentity, HistoricalV2SlotStage,
    HistoricalV2SlotStageError, run_historical_v2_slot_slice, validate_historical_v2_protocol,
    validate_historical_v2_selected_payloads_commitment, validate_historical_v2_slot_selection,
};
use std::ffi::OsString;
use std::fs;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

pub async fn run_historical_v2_selected_slots<E>(
    inputs: HistoricalV2SelectedSlotSweepInputs<'_, E>,
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
    let mut slots = Vec::with_capacity(inputs.payloads.records.len());
    for payload in &inputs.payloads.records {
        let canonical_repository = selected_repository(inputs.selection, payload)?;
        let identity = HistoricalV2SlotRunIdentity {
            selection_sha256: &inputs.selection.selection_sha256,
            language: &payload.language,
            slot_number: payload.slot_number,
            canonical_repository,
        };
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
        let run = run_historical_v2_slot_slice(
            &roots.state,
            identity,
            &mut operations,
            maximum_new_stages_per_slot,
        )
        .await?;
        slots.push(HistoricalV2SelectedSlotRunSummary {
            language: payload.language.clone(),
            slot_number: payload.slot_number,
            canonical_repository: canonical_repository.to_string(),
            run,
        });
    }
    summarize(slots, inputs.selection.selected_count)
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
