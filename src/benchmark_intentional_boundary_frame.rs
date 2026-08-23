use super::*;
use std::fs;
use std::path::Path;

#[cfg(test)]
use super::intentional_boundary_candidate::candidate_census_sha256;
#[cfg(test)]
use std::collections::BTreeMap;

#[path = "benchmark_intentional_boundary_frame_state.rs"]
mod state;
use state::*;

#[path = "benchmark_intentional_boundary_frame_validation.rs"]
mod validation;
use validation::{
    finish_candidate_frame_typed, finish_rank_record, validate_candidate_commitment,
    validate_rank_record,
};

const ARTIFACT_DIRECTORY: &str = "artifacts";
const CHECKPOINT_DIRECTORY: &str = "checkpoints";

pub fn prepare_intentional_boundary_analyzed_rank(
    task: &IntentionalBoundaryFrameTask,
    population_rank: usize,
    inventory_sha256: &str,
    candidate_census: IntentionalBoundaryCandidateCensus,
) -> Result<IntentionalBoundaryFrameRankRecord, String> {
    prepare_intentional_boundary_analyzed_rank_typed(
        task,
        population_rank,
        inventory_sha256,
        candidate_census,
    )
    .map_err(frame_error_detail)
}

pub fn prepare_intentional_boundary_analyzed_rank_typed(
    task: &IntentionalBoundaryFrameTask,
    population_rank: usize,
    inventory_sha256: &str,
    candidate_census: IntentionalBoundaryCandidateCensus,
) -> Result<IntentionalBoundaryFrameRankRecord, IntentionalBoundaryFrameError> {
    if !validation::is_sha256(inventory_sha256) {
        return Err(IntentionalBoundaryFrameError::invalid(
            "intentional-boundary rank inventory commitment is invalid",
        ));
    }
    validate_candidate_commitment(task, population_rank, &candidate_census)?;
    finish_rank_record(
        task,
        population_rank,
        IntentionalBoundaryFrameRankOutcome::Analyzed {
            inventory_sha256: inventory_sha256.to_string(),
            candidate_census: Box::new(candidate_census),
        },
    )
}

pub fn prepare_intentional_boundary_excluded_rank(
    task: &IntentionalBoundaryFrameTask,
    population_rank: usize,
    reason: IntentionalBoundaryFrameExclusionReason,
    evidence_sha256: &str,
) -> Result<IntentionalBoundaryFrameRankRecord, String> {
    prepare_intentional_boundary_excluded_rank_typed(task, population_rank, reason, evidence_sha256)
        .map_err(frame_error_detail)
}

pub fn prepare_intentional_boundary_excluded_rank_typed(
    task: &IntentionalBoundaryFrameTask,
    population_rank: usize,
    reason: IntentionalBoundaryFrameExclusionReason,
    evidence_sha256: &str,
) -> Result<IntentionalBoundaryFrameRankRecord, IntentionalBoundaryFrameError> {
    if !task.terminal_exclusions.contains(&reason) || !validation::is_sha256(evidence_sha256) {
        return Err(IntentionalBoundaryFrameError::invalid(
            "intentional-boundary terminal exclusion is invalid",
        ));
    }
    finish_rank_record(
        task,
        population_rank,
        IntentionalBoundaryFrameRankOutcome::Excluded {
            reason,
            evidence_sha256: evidence_sha256.to_string(),
        },
    )
}

pub fn commit_intentional_boundary_frame_rank(
    root: &Path,
    task: &IntentionalBoundaryFrameTask,
    record: &IntentionalBoundaryFrameRankRecord,
) -> Result<(), String> {
    commit_intentional_boundary_frame_rank_typed(root, task, record).map_err(frame_error_detail)
}

pub fn commit_intentional_boundary_frame_rank_typed(
    root: &Path,
    task: &IntentionalBoundaryFrameTask,
    record: &IntentionalBoundaryFrameRankRecord,
) -> Result<(), IntentionalBoundaryFrameError> {
    reconcile_intentional_boundary_frame_rank_typed(root, task, record).map(|_| ())
}

pub fn reconcile_intentional_boundary_frame_rank(
    root: &Path,
    task: &IntentionalBoundaryFrameTask,
    record: &IntentionalBoundaryFrameRankRecord,
) -> Result<IntentionalBoundaryFrameRankReconciliation, String> {
    reconcile_intentional_boundary_frame_rank_typed(root, task, record).map_err(frame_error_detail)
}

pub fn reconcile_intentional_boundary_frame_rank_typed(
    root: &Path,
    task: &IntentionalBoundaryFrameTask,
    record: &IntentionalBoundaryFrameRankRecord,
) -> Result<IntentionalBoundaryFrameRankReconciliation, IntentionalBoundaryFrameError> {
    validate_rank_record(task, record)?;
    let completed = load_intentional_boundary_frame_ranks_typed(root, task)?;
    let rank = record.repository_task.population_rank;
    if let Some(existing) = completed.get(rank.saturating_sub(1)) {
        return if existing == record {
            Ok(IntentionalBoundaryFrameRankReconciliation::AlreadyCommitted)
        } else {
            Err(IntentionalBoundaryFrameError::corrupt(format!(
                "intentional-boundary frame rank {rank} conflicts with its committed record"
            )))
        };
    }
    let expected_rank = completed.len() + 1;
    if rank != expected_rank {
        return Err(IntentionalBoundaryFrameError::invalid(format!(
            "intentional-boundary frame requires contiguous rank {expected_rank}"
        )));
    }
    let artifacts = root.join(ARTIFACT_DIRECTORY);
    let checkpoints = root.join(CHECKPOINT_DIRECTORY);
    create_state_directory(&artifacts, "artifact")?;
    create_state_directory(&checkpoints, "checkpoint")?;
    let bytes = pretty_json(record, "intentional-boundary rank artifact")?;
    let artifact_path = rank_path(&artifacts, expected_rank);
    persist_create_new(&artifact_path, &bytes, "intentional-boundary rank artifact")?;
    publish_checkpoint(
        &checkpoints,
        &task.task_sha256,
        expected_rank,
        &sha256(&bytes),
    )?;
    Ok(IntentionalBoundaryFrameRankReconciliation::Committed)
}

pub fn load_intentional_boundary_frame_ranks(
    root: &Path,
    task: &IntentionalBoundaryFrameTask,
) -> Result<Vec<IntentionalBoundaryFrameRankRecord>, String> {
    load_intentional_boundary_frame_ranks_typed(root, task).map_err(frame_error_detail)
}

pub fn load_intentional_boundary_frame_ranks_typed(
    root: &Path,
    task: &IntentionalBoundaryFrameTask,
) -> Result<Vec<IntentionalBoundaryFrameRankRecord>, IntentionalBoundaryFrameError> {
    let artifacts = root.join(ARTIFACT_DIRECTORY);
    let checkpoints = root.join(CHECKPOINT_DIRECTORY);
    create_state_directory(&artifacts, "artifact")?;
    create_state_directory(&checkpoints, "checkpoint")?;
    remove_temps(&artifacts)?;
    remove_temps(&checkpoints)?;
    let mut records = Vec::new();
    for repository in &task.repositories {
        let rank = repository.population_rank;
        let artifact_path = rank_path(&artifacts, rank);
        let checkpoint_path = rank_path(&checkpoints, rank);
        let artifact_exists = path_exists(&artifact_path, "boundary rank artifact")?;
        let checkpoint_exists = path_exists(&checkpoint_path, "boundary rank checkpoint")?;
        match (artifact_exists, checkpoint_exists) {
            (false, false) => break,
            (false, true) => {
                return Err(IntentionalBoundaryFrameError::corrupt(format!(
                    "intentional-boundary rank {rank} checkpoint has no artifact"
                )));
            }
            (true, checkpoint_exists) => {
                let bytes = fs::read(&artifact_path).map_err(|error| {
                    IntentionalBoundaryFrameError::infrastructure(format!(
                        "failed to read boundary rank {rank} artifact: {error}"
                    ))
                })?;
                let record: IntentionalBoundaryFrameRankRecord = serde_json::from_slice(&bytes)
                    .map_err(|error| {
                        IntentionalBoundaryFrameError::corrupt(format!(
                            "invalid boundary rank {rank} artifact: {error}"
                        ))
                    })?;
                validate_rank_record(task, &record).map_err(|error| error.into_corrupt())?;
                let artifact_sha256 = sha256(&bytes);
                if checkpoint_exists {
                    validate_checkpoint(
                        &checkpoint_path,
                        &task.task_sha256,
                        rank,
                        &artifact_sha256,
                    )?;
                } else {
                    publish_checkpoint(&checkpoints, &task.task_sha256, rank, &artifact_sha256)?;
                }
                records.push(record);
            }
        }
    }
    reject_unexpected_entries(&artifacts, records.len())?;
    reject_unexpected_entries(&checkpoints, records.len())?;
    Ok(records)
}

pub fn complete_intentional_boundary_candidate_frame(
    root: &Path,
    task: &IntentionalBoundaryFrameTask,
) -> Result<IntentionalBoundaryCandidateFrame, String> {
    complete_intentional_boundary_candidate_frame_typed(root, task).map_err(frame_error_detail)
}

pub fn complete_intentional_boundary_candidate_frame_typed(
    root: &Path,
    task: &IntentionalBoundaryFrameTask,
) -> Result<IntentionalBoundaryCandidateFrame, IntentionalBoundaryFrameError> {
    let records = load_intentional_boundary_frame_ranks_typed(root, task)?;
    finish_candidate_frame_typed(task, records)
}

pub fn validate_intentional_boundary_candidate_frame(
    task: &IntentionalBoundaryFrameTask,
    frame: &IntentionalBoundaryCandidateFrame,
) -> Result<(), String> {
    validate_intentional_boundary_candidate_frame_typed(task, frame).map_err(frame_error_detail)
}

pub fn validate_intentional_boundary_candidate_frame_typed(
    task: &IntentionalBoundaryFrameTask,
    frame: &IntentionalBoundaryCandidateFrame,
) -> Result<(), IntentionalBoundaryFrameError> {
    let expected = finish_candidate_frame_typed(task, frame.rank_records.clone())?;
    if frame != &expected {
        return Err(IntentionalBoundaryFrameError::invalid(
            "intentional-boundary candidate frame changed",
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn finish_candidate_frame(
    task: &IntentionalBoundaryFrameTask,
    rank_records: Vec<IntentionalBoundaryFrameRankRecord>,
) -> Result<IntentionalBoundaryCandidateFrame, String> {
    finish_candidate_frame_typed(task, rank_records).map_err(frame_error_detail)
}

fn create_state_directory(path: &Path, label: &str) -> Result<(), IntentionalBoundaryFrameError> {
    fs::create_dir_all(path).map_err(|error| {
        IntentionalBoundaryFrameError::infrastructure(format!(
            "failed to create boundary {label} directory: {error}"
        ))
    })
}

fn path_exists(path: &Path, label: &str) -> Result<bool, IntentionalBoundaryFrameError> {
    path.try_exists().map_err(|error| {
        IntentionalBoundaryFrameError::infrastructure(format!("failed to inspect {label}: {error}"))
    })
}

fn frame_error_detail(error: IntentionalBoundaryFrameError) -> String {
    error.detail
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_frame_tests.rs"]
mod tests;
