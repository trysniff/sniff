#[path = "benchmark_history_v3_materialization_schema.rs"]
mod schema;

pub use schema::*;

#[path = "benchmark_history_v3_materialization_git.rs"]
mod git;

#[path = "benchmark_history_v3_materialization_layout.rs"]
mod layout;

#[path = "benchmark_history_v3_materialization_commitment.rs"]
mod commitment;

pub use commitment::{
    validate_historical_v3_materialization, validate_historical_v3_materialization_commitment,
    validate_historical_v3_materialization_exclusion,
};

pub(super) fn validate_historical_v3_materialization_resume(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    artifact: &HistoricalV3Materialization,
    roots: &HistoricalV3MaterializedRoots,
) -> Result<(), HistoricalV3MaterializationError> {
    validate_historical_v3_materialization_commitment(protocol, collection, artifact)?;
    layout::validate_root_layout(roots)
}

#[path = "benchmark_history_v3_materialization_runtime.rs"]
mod runtime;

pub use runtime::materialize_historical_v3_candidate;

#[cfg(test)]
pub(super) use runtime::materialize_historical_v3_candidate_from_url;

use super::{
    HistoricalV3CandidateCollection, HistoricalV3CandidateIdentity, HistoricalV3CandidateTask,
    HistoricalV3Protocol, validate_historical_v3_candidate_collection_commitment,
};

pub(super) const MATERIALIZATION_CONTRACT: &str = "sniffbench-historical-v3-materialization-v1";
pub(super) const EXCLUSION_CONTRACT: &str = "sniffbench-historical-v3-materialization-exclusion-v1";

pub(super) struct CandidateContext<'a> {
    pub protocol: &'a HistoricalV3Protocol,
    pub collection: &'a HistoricalV3CandidateCollection,
    pub task: &'a HistoricalV3CandidateTask,
    pub name_with_owner: &'a str,
    pub clone_url: String,
}

pub(super) fn candidate_context<'a>(
    protocol: &'a HistoricalV3Protocol,
    collection: &'a HistoricalV3CandidateCollection,
    stream_rank: usize,
) -> Result<CandidateContext<'a>, HistoricalV3MaterializationError> {
    validate_historical_v3_candidate_collection_commitment(protocol, collection)
        .map_err(invalid)?;
    let task = collection
        .manifest
        .stream_task
        .candidates
        .get(stream_rank.saturating_sub(1))
        .filter(|task| task.stream_rank == stream_rank)
        .ok_or_else(|| invalid("historical-v3 stream rank is absent"))?;
    let repository = collection
        .manifest
        .repositories
        .iter()
        .find(|repository| {
            repository.language == task.identity.language
                && repository.repository_id == task.identity.repository_id
        })
        .ok_or_else(|| invalid("historical-v3 candidate repository is absent"))?;
    if repository.name_with_owner.split('/').count() != 2
        || repository.name_with_owner.contains('\\')
        || repository.name_with_owner.contains(':')
    {
        return Err(invalid(
            "historical-v3 candidate repository is not canonical GitHub",
        ));
    }
    Ok(CandidateContext {
        protocol,
        collection,
        task,
        name_with_owner: &repository.name_with_owner,
        clone_url: format!("https://github.com/{}.git", repository.name_with_owner),
    })
}

pub(super) fn invalid(detail: impl Into<String>) -> HistoricalV3MaterializationError {
    HistoricalV3MaterializationError {
        kind: HistoricalV3MaterializationErrorKind::InvalidInput,
        detail: detail.into(),
    }
}

pub(super) fn infrastructure_unavailable(
    detail: impl Into<String>,
) -> HistoricalV3MaterializationError {
    HistoricalV3MaterializationError {
        kind: HistoricalV3MaterializationErrorKind::InfrastructureUnavailable,
        detail: detail.into(),
    }
}

pub(super) fn failed(detail: impl Into<String>) -> HistoricalV3MaterializationError {
    HistoricalV3MaterializationError {
        kind: HistoricalV3MaterializationErrorKind::InfrastructureFailed,
        detail: detail.into(),
    }
}

#[cfg(test)]
#[path = "benchmark_history_v3_materialization_tests.rs"]
mod tests;
