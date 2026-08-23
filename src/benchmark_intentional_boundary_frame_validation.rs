use super::super::intentional_boundary_candidate::candidate_census_sha256;
use super::super::*;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

const RANK_RECORD_CONTRACT: &str = "sniffbench-intentional-boundary-frame-rank-v1";
const FRAME_CONTRACT: &str = "sniffbench-intentional-boundary-candidate-frame-v1";

pub(super) fn finish_rank_record(
    task: &IntentionalBoundaryFrameTask,
    population_rank: usize,
    outcome: IntentionalBoundaryFrameRankOutcome,
) -> Result<IntentionalBoundaryFrameRankRecord, IntentionalBoundaryFrameError> {
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

pub(super) fn validate_rank_record(
    task: &IntentionalBoundaryFrameTask,
    record: &IntentionalBoundaryFrameRankRecord,
) -> Result<(), IntentionalBoundaryFrameError> {
    let expected = expected_repository(task, record.repository_task.population_rank)?;
    if record.schema_version != INTENTIONAL_BOUNDARY_FRAME_RANK_SCHEMA_VERSION
        || record.frame_task_sha256 != task.task_sha256
        || &record.repository_task != expected
        || record.record_sha256 != rank_record_sha256(record)?
    {
        return Err(IntentionalBoundaryFrameError::invalid(
            "intentional-boundary rank record commitment changed",
        ));
    }
    match &record.outcome {
        IntentionalBoundaryFrameRankOutcome::Analyzed {
            inventory_sha256,
            candidate_census,
        } => {
            if !is_sha256(inventory_sha256) {
                return Err(IntentionalBoundaryFrameError::invalid(
                    "intentional-boundary rank inventory commitment changed",
                ));
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
                return Err(IntentionalBoundaryFrameError::invalid(
                    "intentional-boundary rank exclusion commitment changed",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_candidate_commitment(
    task: &IntentionalBoundaryFrameTask,
    population_rank: usize,
    census: &IntentionalBoundaryCandidateCensus,
) -> Result<(), IntentionalBoundaryFrameError> {
    let repository = expected_repository(task, population_rank)?;
    if census.schema_version != INTENTIONAL_BOUNDARY_CANDIDATE_CENSUS_SCHEMA_VERSION
        || census.candidate_contract != "sniffbench-intentional-boundary-candidate-census-v1"
        || census.protocol_sha256 != task.protocol_sha256
        || census.repository != repository.repository
        || !is_git_revision(&census.revision)
        || !is_sha256(&census.source_census_sha256)
        || !is_sha256(&census.semantic_census_sha256)
        || !is_sha256(&census.evidence_census_sha256)
        || census.candidate_census_sha256
            != candidate_census_sha256(census).map_err(IntentionalBoundaryFrameError::invalid)?
    {
        return Err(IntentionalBoundaryFrameError::invalid(
            "intentional-boundary candidate commitment changed",
        ));
    }
    if census
        .candidates
        .windows(2)
        .any(|pair| pair[0].candidate_id >= pair[1].candidate_id)
    {
        return Err(IntentionalBoundaryFrameError::invalid(
            "intentional-boundary candidate order changed",
        ));
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
            return Err(IntentionalBoundaryFrameError::invalid(
                "intentional-boundary candidate identity changed",
            ));
        }
        *counts.entry(candidate.category).or_insert(0) += 1;
    }
    if counts != census.candidate_count_by_category {
        return Err(IntentionalBoundaryFrameError::invalid(
            "intentional-boundary candidate counts changed",
        ));
    }
    Ok(())
}

pub(super) fn finish_candidate_frame_typed(
    task: &IntentionalBoundaryFrameTask,
    rank_records: Vec<IntentionalBoundaryFrameRankRecord>,
) -> Result<IntentionalBoundaryCandidateFrame, IntentionalBoundaryFrameError> {
    if rank_records.len() != task.repositories.len() {
        return Err(IntentionalBoundaryFrameError::invalid(format!(
            "intentional-boundary frame is incomplete: {} of {} ranks",
            rank_records.len(),
            task.repositories.len()
        )));
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
        return Err(IntentionalBoundaryFrameError::invalid(
            "intentional-boundary frame repeated a candidate identity",
        ));
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

pub(super) fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn expected_repository(
    task: &IntentionalBoundaryFrameTask,
    population_rank: usize,
) -> Result<&IntentionalBoundaryRepositoryTask, IntentionalBoundaryFrameError> {
    let expected = task.repositories.get(population_rank.saturating_sub(1));
    match expected {
        Some(repository) if repository.population_rank == population_rank => Ok(repository),
        _ => Err(IntentionalBoundaryFrameError::invalid(format!(
            "intentional-boundary frame rank {population_rank} is outside its immutable task"
        ))),
    }
}

fn rank_record_sha256(
    record: &IntentionalBoundaryFrameRankRecord,
) -> Result<String, IntentionalBoundaryFrameError> {
    hash_json(&(
        RANK_RECORD_CONTRACT,
        record.schema_version,
        &record.frame_task_sha256,
        &record.repository_task,
        &record.outcome,
    ))
}

fn candidate_id(
    candidate: &IntentionalBoundaryCandidate,
) -> Result<String, IntentionalBoundaryFrameError> {
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

fn frame_sha256(
    frame: &IntentionalBoundaryCandidateFrame,
) -> Result<String, IntentionalBoundaryFrameError> {
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

fn hash_json(value: &impl Serialize) -> Result<String, IntentionalBoundaryFrameError> {
    serde_json::to_vec(value)
        .map(|bytes| super::sha256(&bytes))
        .map_err(|error| {
            IntentionalBoundaryFrameError::invalid(format!(
                "failed to commit intentional-boundary frame: {error}"
            ))
        })
}

fn is_git_revision(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn strictly_increasing<T: Ord>(values: &[T]) -> bool {
    !values.is_empty() && values.windows(2).all(|pair| pair[0] < pair[1])
}
