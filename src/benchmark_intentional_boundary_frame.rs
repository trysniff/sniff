use super::intentional_boundary_candidate::candidate_census_sha256;
use super::*;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

#[path = "benchmark_intentional_boundary_frame_state.rs"]
mod state;
use state::*;

const RANK_RECORD_CONTRACT: &str = "sniffbench-intentional-boundary-frame-rank-v1";
const FRAME_CONTRACT: &str = "sniffbench-intentional-boundary-candidate-frame-v1";
const ARTIFACT_DIRECTORY: &str = "artifacts";
const CHECKPOINT_DIRECTORY: &str = "checkpoints";

pub fn prepare_intentional_boundary_analyzed_rank(
    task: &IntentionalBoundaryFrameTask,
    population_rank: usize,
    inventory_sha256: &str,
    candidate_census: IntentionalBoundaryCandidateCensus,
) -> Result<IntentionalBoundaryFrameRankRecord, String> {
    if !is_sha256(inventory_sha256) {
        return Err("intentional-boundary rank inventory commitment is invalid".to_string());
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
    if !task.terminal_exclusions.contains(&reason) || !is_sha256(evidence_sha256) {
        return Err("intentional-boundary terminal exclusion is invalid".to_string());
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
    reconcile_intentional_boundary_frame_rank(root, task, record).map(|_| ())
}

pub fn reconcile_intentional_boundary_frame_rank(
    root: &Path,
    task: &IntentionalBoundaryFrameTask,
    record: &IntentionalBoundaryFrameRankRecord,
) -> Result<IntentionalBoundaryFrameRankReconciliation, String> {
    validate_rank_record(task, record)?;
    let completed = load_intentional_boundary_frame_ranks(root, task)?;
    let rank = record.repository_task.population_rank;
    if let Some(existing) = completed.get(rank.saturating_sub(1)) {
        return if existing == record {
            Ok(IntentionalBoundaryFrameRankReconciliation::AlreadyCommitted)
        } else {
            Err(format!(
                "intentional-boundary frame rank {rank} conflicts with its committed record"
            ))
        };
    }
    let expected_rank = completed.len() + 1;
    if rank != expected_rank {
        return Err(format!(
            "intentional-boundary frame requires contiguous rank {expected_rank}"
        ));
    }
    let artifacts = root.join(ARTIFACT_DIRECTORY);
    let checkpoints = root.join(CHECKPOINT_DIRECTORY);
    fs::create_dir_all(&artifacts)
        .map_err(|error| format!("failed to create boundary artifact directory: {error}"))?;
    fs::create_dir_all(&checkpoints)
        .map_err(|error| format!("failed to create boundary checkpoint directory: {error}"))?;
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
    let artifacts = root.join(ARTIFACT_DIRECTORY);
    let checkpoints = root.join(CHECKPOINT_DIRECTORY);
    fs::create_dir_all(&artifacts)
        .map_err(|error| format!("failed to create boundary artifact directory: {error}"))?;
    fs::create_dir_all(&checkpoints)
        .map_err(|error| format!("failed to create boundary checkpoint directory: {error}"))?;
    remove_temps(&artifacts)?;
    remove_temps(&checkpoints)?;
    let mut records = Vec::new();
    for repository in &task.repositories {
        let rank = repository.population_rank;
        let artifact_path = rank_path(&artifacts, rank);
        let checkpoint_path = rank_path(&checkpoints, rank);
        match (artifact_path.exists(), checkpoint_path.exists()) {
            (false, false) => break,
            (false, true) => {
                return Err(format!(
                    "intentional-boundary rank {rank} checkpoint has no artifact"
                ));
            }
            (true, checkpoint_exists) => {
                let bytes = fs::read(&artifact_path).map_err(|error| {
                    format!("failed to read boundary rank {rank} artifact: {error}")
                })?;
                let record: IntentionalBoundaryFrameRankRecord = serde_json::from_slice(&bytes)
                    .map_err(|error| format!("invalid boundary rank {rank} artifact: {error}"))?;
                validate_rank_record(task, &record)?;
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
    let records = load_intentional_boundary_frame_ranks(root, task)?;
    finish_candidate_frame(task, records)
}

pub fn validate_intentional_boundary_candidate_frame(
    task: &IntentionalBoundaryFrameTask,
    frame: &IntentionalBoundaryCandidateFrame,
) -> Result<(), String> {
    let expected = finish_candidate_frame(task, frame.rank_records.clone())?;
    if frame != &expected {
        return Err("intentional-boundary candidate frame changed".to_string());
    }
    Ok(())
}

fn finish_rank_record(
    task: &IntentionalBoundaryFrameTask,
    population_rank: usize,
    outcome: IntentionalBoundaryFrameRankOutcome,
) -> Result<IntentionalBoundaryFrameRankRecord, String> {
    let repository_task = expected_repository(task, population_rank)?.clone();
    let mut record = IntentionalBoundaryFrameRankRecord {
        schema_version: INTENTIONAL_BOUNDARY_FRAME_RANK_SCHEMA_VERSION,
        frame_task_sha256: task.task_sha256.clone(),
        repository_task,
        outcome,
        record_sha256: String::new(),
    };
    record.record_sha256 = rank_record_sha256(&record)?;
    Ok(record)
}

fn validate_rank_record(
    task: &IntentionalBoundaryFrameTask,
    record: &IntentionalBoundaryFrameRankRecord,
) -> Result<(), String> {
    let expected = expected_repository(task, record.repository_task.population_rank)?;
    if record.schema_version != INTENTIONAL_BOUNDARY_FRAME_RANK_SCHEMA_VERSION
        || record.frame_task_sha256 != task.task_sha256
        || &record.repository_task != expected
        || record.record_sha256 != rank_record_sha256(record)?
    {
        return Err("intentional-boundary rank record commitment changed".to_string());
    }
    match &record.outcome {
        IntentionalBoundaryFrameRankOutcome::Analyzed {
            inventory_sha256,
            candidate_census,
        } => {
            if !is_sha256(inventory_sha256) {
                return Err("intentional-boundary rank inventory commitment changed".to_string());
            }
            validate_candidate_commitment(
                task,
                record.repository_task.population_rank,
                candidate_census,
            )?;
        }
        IntentionalBoundaryFrameRankOutcome::Excluded {
            reason,
            evidence_sha256,
        } => {
            if !task.terminal_exclusions.contains(reason) || !is_sha256(evidence_sha256) {
                return Err("intentional-boundary rank exclusion commitment changed".to_string());
            }
        }
    }
    Ok(())
}

fn validate_candidate_commitment(
    task: &IntentionalBoundaryFrameTask,
    population_rank: usize,
    census: &IntentionalBoundaryCandidateCensus,
) -> Result<(), String> {
    let repository = expected_repository(task, population_rank)?;
    if census.schema_version != INTENTIONAL_BOUNDARY_CANDIDATE_CENSUS_SCHEMA_VERSION
        || census.candidate_contract != "sniffbench-intentional-boundary-candidate-census-v1"
        || census.protocol_sha256 != task.protocol_sha256
        || census.repository != repository.repository
        || !is_git_revision(&census.revision)
        || !is_sha256(&census.source_census_sha256)
        || !is_sha256(&census.semantic_census_sha256)
        || !is_sha256(&census.evidence_census_sha256)
        || census.candidate_census_sha256 != candidate_census_sha256(census)?
    {
        return Err("intentional-boundary candidate commitment changed".to_string());
    }
    if census
        .candidates
        .windows(2)
        .any(|pair| pair[0].candidate_id >= pair[1].candidate_id)
    {
        return Err("intentional-boundary candidate order changed".to_string());
    }
    let mut counts = BTreeMap::new();
    let mut identities = BTreeSet::new();
    for candidate in &census.candidates {
        let expected_id = candidate_id(candidate)?;
        if candidate.candidate_id != expected_id
            || candidate.repository != census.repository
            || candidate.revision != census.revision
            || candidate.repository_path.trim().is_empty()
            || candidate.exact_symbol_identity.trim().is_empty()
            || candidate.parser_unit_id.trim().is_empty()
            || candidate.evidence_kinds.is_empty()
            || candidate.evidence_ids.is_empty()
            || !strictly_increasing(&candidate.evidence_kinds)
            || !strictly_increasing(&candidate.evidence_ids)
            || !identities.insert(candidate.candidate_id.as_str())
        {
            return Err("intentional-boundary candidate identity changed".to_string());
        }
        *counts.entry(candidate.category).or_insert(0) += 1;
    }
    if counts != census.candidate_count_by_category {
        return Err("intentional-boundary candidate counts changed".to_string());
    }
    Ok(())
}

pub(super) fn finish_candidate_frame(
    task: &IntentionalBoundaryFrameTask,
    rank_records: Vec<IntentionalBoundaryFrameRankRecord>,
) -> Result<IntentionalBoundaryCandidateFrame, String> {
    if rank_records.len() != task.repositories.len() {
        return Err(format!(
            "intentional-boundary frame is incomplete: {} of {} ranks",
            rank_records.len(),
            task.repositories.len()
        ));
    }
    for record in &rank_records {
        validate_rank_record(task, record)?;
    }
    let mut candidates = rank_records
        .iter()
        .filter_map(|record| match &record.outcome {
            IntentionalBoundaryFrameRankOutcome::Analyzed {
                candidate_census, ..
            } => Some(candidate_census.candidates.iter()),
            IntentionalBoundaryFrameRankOutcome::Excluded { .. } => None,
        })
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort();
    if candidates
        .windows(2)
        .any(|pair| pair[0].candidate_id == pair[1].candidate_id)
    {
        return Err("intentional-boundary frame repeated a candidate identity".to_string());
    }
    let candidate_count_by_category =
        candidates
            .iter()
            .fold(BTreeMap::new(), |mut counts, candidate| {
                *counts.entry(candidate.category).or_insert(0) += 1;
                counts
            });
    let analyzed_repository_count = rank_records
        .iter()
        .filter(|record| {
            matches!(
                record.outcome,
                IntentionalBoundaryFrameRankOutcome::Analyzed { .. }
            )
        })
        .count();
    let excluded_repository_count = rank_records.len() - analyzed_repository_count;
    let mut frame = IntentionalBoundaryCandidateFrame {
        schema_version: INTENTIONAL_BOUNDARY_CANDIDATE_FRAME_SCHEMA_VERSION,
        frame_contract: FRAME_CONTRACT.to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        protocol_sha256: task.protocol_sha256.clone(),
        rank_records,
        candidates,
        analyzed_repository_count,
        excluded_repository_count,
        candidate_count_by_category,
        frame_sha256: String::new(),
    };
    frame.frame_sha256 = frame_sha256(&frame)?;
    Ok(frame)
}

fn expected_repository(
    task: &IntentionalBoundaryFrameTask,
    population_rank: usize,
) -> Result<&IntentionalBoundaryRepositoryTask, String> {
    let expected = task.repositories.get(population_rank.saturating_sub(1));
    match expected {
        Some(repository) if repository.population_rank == population_rank => Ok(repository),
        _ => Err(format!(
            "intentional-boundary frame rank {population_rank} is outside its immutable task"
        )),
    }
}

fn rank_record_sha256(record: &IntentionalBoundaryFrameRankRecord) -> Result<String, String> {
    hash_json(&(
        RANK_RECORD_CONTRACT,
        record.schema_version,
        &record.frame_task_sha256,
        &record.repository_task,
        &record.outcome,
    ))
}

fn candidate_id(candidate: &IntentionalBoundaryCandidate) -> Result<String, String> {
    hash_json(&(
        "sniffbench-intentional-boundary-candidate-v1",
        candidate.category,
        &candidate.repository,
        &candidate.revision,
        &candidate.repository_path,
        &candidate.exact_symbol_identity,
    ))
    .map(|hash| format!("ibc-v1:{hash}"))
}

fn frame_sha256(frame: &IntentionalBoundaryCandidateFrame) -> Result<String, String> {
    hash_json(&(
        frame.schema_version,
        &frame.frame_contract,
        &frame.frame_task_sha256,
        &frame.protocol_sha256,
        &frame.rank_records,
        &frame.candidates,
        frame.analyzed_repository_count,
        frame.excluded_repository_count,
        &frame.candidate_count_by_category,
    ))
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("failed to commit intentional-boundary frame: {error}"))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_git_revision(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn strictly_increasing<T: Ord>(values: &[T]) -> bool {
    !values.is_empty() && values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_frame_tests.rs"]
mod tests;
