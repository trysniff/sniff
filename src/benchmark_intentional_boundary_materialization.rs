use super::{
    INTENTIONAL_BOUNDARY_MATERIALIZATION_EXCLUSION_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_MATERIALIZATION_SCHEMA_VERSION, IntentionalBoundaryFrameTask,
    IntentionalBoundaryMaterialization, IntentionalBoundaryMaterializationError,
    IntentionalBoundaryMaterializationErrorKind, IntentionalBoundaryMaterializationExclusion,
    IntentionalBoundaryMaterializationExclusionEvidence,
    IntentionalBoundaryMaterializationExclusionReason, IntentionalBoundaryMaterializationOutcome,
    IntentionalBoundaryMaterializedRepository,
};
use reqwest::StatusCode;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

const MATERIALIZATION_CONTRACT: &str = "sniffbench-intentional-boundary-materialization-v1";
const EXCLUSION_CONTRACT: &str = "sniffbench-intentional-boundary-materialization-exclusion-v1";

#[path = "benchmark_intentional_boundary_materialization_transport.rs"]
mod transport;
use transport::*;

pub async fn materialize_intentional_boundary_repository(
    task: &IntentionalBoundaryFrameTask,
    population_rank: usize,
    destination: &Path,
    github_token: Option<&str>,
) -> Result<IntentionalBoundaryMaterializationOutcome, IntentionalBoundaryMaterializationError> {
    let repository = expected_repository(task, population_rank)?;
    require_new_destination(destination)?;
    let slug = repository
        .repository
        .strip_prefix("github.com/")
        .ok_or_else(|| invalid("intentional-boundary repository is not canonical GitHub"))?;
    let api_url = format!("https://api.github.com/repos/{slug}");
    let status = probe_repository(&api_url, github_token).await?;
    if matches!(status, StatusCode::NOT_FOUND | StatusCode::GONE) {
        return exclusion(
            task,
            population_rank,
            IntentionalBoundaryMaterializationExclusionReason::RepositoryInaccessible,
            IntentionalBoundaryMaterializationExclusionEvidence::RepositoryProbe {
                url: api_url,
                status: status.as_u16(),
            },
        )
        .map(IntentionalBoundaryMaterializationOutcome::Excluded);
    }
    let clone_url = format!("https://{}.git", repository.repository);
    materialize_from_clone_url(task, population_rank, destination, &clone_url, &clone_url)
}

pub fn validate_intentional_boundary_materialization(
    task: &IntentionalBoundaryFrameTask,
    artifact: &IntentionalBoundaryMaterialization,
    checkout_root: &Path,
) -> Result<(), IntentionalBoundaryMaterializationError> {
    validate_intentional_boundary_materialization_commitment(task, artifact)?;
    let facts = inspect_checkout(checkout_root, &artifact.repository, &artifact.clone_url)?;
    if facts.revision != artifact.revision
        || facts.object_format != artifact.git_object_format
        || facts.tree_oid != artifact.tree_oid
    {
        return Err(invalid(
            "intentional-boundary retained checkout changed its immutable identity",
        ));
    }
    Ok(())
}

pub fn validate_intentional_boundary_materialization_commitment(
    task: &IntentionalBoundaryFrameTask,
    artifact: &IntentionalBoundaryMaterialization,
) -> Result<(), IntentionalBoundaryMaterializationError> {
    let repository = expected_repository(task, artifact.population_rank)?;
    let object_id_length = match artifact.git_object_format.as_str() {
        "sha1" => 40,
        "sha256" => 64,
        _ => 0,
    };
    if artifact.schema_version != INTENTIONAL_BOUNDARY_MATERIALIZATION_SCHEMA_VERSION
        || artifact.materialization_contract != MATERIALIZATION_CONTRACT
        || artifact.frame_task_sha256 != task.task_sha256
        || artifact.population_rank_sha256 != repository.population_rank_sha256
        || artifact.repository != repository.repository
        || artifact.clone_url != format!("https://{}.git", repository.repository)
        || !valid_object_id(&artifact.revision, object_id_length)
        || !valid_object_id(&artifact.tree_oid, object_id_length)
        || artifact.materialization_sha256 != materialization_sha256(artifact)?
    {
        return Err(invalid(
            "intentional-boundary materialization commitment changed",
        ));
    }
    Ok(())
}

pub fn rematerialize_intentional_boundary_repository(
    task: &IntentionalBoundaryFrameTask,
    artifact: &IntentionalBoundaryMaterialization,
    destination: &Path,
) -> Result<IntentionalBoundaryMaterializedRepository, IntentionalBoundaryMaterializationError> {
    validate_intentional_boundary_materialization_commitment(task, artifact)?;
    require_new_destination(destination)?;
    let result =
        clone_repository_for_exact_revision(&artifact.clone_url, destination, &artifact.revision)
            .and_then(|()| finalize_exact_rematerialization(task, artifact, destination));
    if result.is_err() {
        remove_partial(destination)?;
    }
    result
}

fn finalize_exact_rematerialization(
    task: &IntentionalBoundaryFrameTask,
    artifact: &IntentionalBoundaryMaterialization,
    destination: &Path,
) -> Result<IntentionalBoundaryMaterializedRepository, IntentionalBoundaryMaterializationError> {
    git_success(
        destination,
        &["remote", "set-url", "origin", &artifact.clone_url],
        git_timeout(),
        "set frozen canonical origin",
    )?;
    git_success(
        destination,
        &[
            "-c",
            "core.autocrlf=false",
            "checkout",
            "--force",
            "--detach",
            &artifact.revision,
        ],
        git_timeout(),
        "checkout frozen revision",
    )?;
    validate_intentional_boundary_materialization(task, artifact, destination)?;
    Ok(IntentionalBoundaryMaterializedRepository {
        artifact: artifact.clone(),
        checkout_root: destination.to_path_buf(),
    })
}

fn valid_object_id(value: &str, expected_length: usize) -> bool {
    expected_length != 0
        && value.len() == expected_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub fn validate_intentional_boundary_materialization_exclusion(
    task: &IntentionalBoundaryFrameTask,
    artifact: &IntentionalBoundaryMaterializationExclusion,
) -> Result<(), IntentionalBoundaryMaterializationError> {
    let repository = expected_repository(task, artifact.population_rank)?;
    let canonical_clone_url = format!("https://{}.git", repository.repository);
    let evidence_is_valid = match (&artifact.reason, &artifact.evidence) {
        (
            IntentionalBoundaryMaterializationExclusionReason::RepositoryInaccessible,
            IntentionalBoundaryMaterializationExclusionEvidence::RepositoryProbe { url, status },
        ) => {
            let slug = repository
                .repository
                .strip_prefix("github.com/")
                .ok_or_else(|| {
                    invalid("intentional-boundary repository is not canonical GitHub")
                })?;
            url == &format!("https://api.github.com/repos/{slug}") && matches!(*status, 404 | 410)
        }
        (
            IntentionalBoundaryMaterializationExclusionReason::EmptyRepository,
            IntentionalBoundaryMaterializationExclusionEvidence::EmptyClone { clone_url },
        ) => clone_url == &canonical_clone_url,
        _ => false,
    };
    if artifact.schema_version != INTENTIONAL_BOUNDARY_MATERIALIZATION_EXCLUSION_SCHEMA_VERSION
        || artifact.exclusion_contract != EXCLUSION_CONTRACT
        || artifact.frame_task_sha256 != task.task_sha256
        || artifact.population_rank_sha256 != repository.population_rank_sha256
        || artifact.repository != repository.repository
        || !evidence_is_valid
        || artifact.exclusion_sha256 != exclusion_sha256(artifact)?
    {
        return Err(invalid(
            "intentional-boundary materialization exclusion commitment changed",
        ));
    }
    Ok(())
}

fn materialize_from_clone_url(
    task: &IntentionalBoundaryFrameTask,
    population_rank: usize,
    destination: &Path,
    source_url: &str,
    canonical_clone_url: &str,
) -> Result<IntentionalBoundaryMaterializationOutcome, IntentionalBoundaryMaterializationError> {
    let repository = expected_repository(task, population_rank)?;
    require_new_destination(destination)?;
    clone_complete_repository(source_url, destination)?;
    let revision = git_optional_text(destination, &["rev-parse", "--verify", "HEAD"])?;
    let Some(revision) = revision else {
        remove_partial(destination)?;
        return exclusion(
            task,
            population_rank,
            IntentionalBoundaryMaterializationExclusionReason::EmptyRepository,
            IntentionalBoundaryMaterializationExclusionEvidence::EmptyClone {
                clone_url: canonical_clone_url.to_string(),
            },
        )
        .map(IntentionalBoundaryMaterializationOutcome::Excluded);
    };
    git_success(
        destination,
        &["remote", "set-url", "origin", canonical_clone_url],
        git_timeout(),
        "set canonical origin",
    )?;
    git_success(
        destination,
        &[
            "-c",
            "core.autocrlf=false",
            "checkout",
            "--force",
            "--detach",
            "HEAD",
        ],
        git_timeout(),
        "checkout immutable revision",
    )?;
    let facts = inspect_checkout(destination, &repository.repository, canonical_clone_url)?;
    if facts.revision != revision.trim().to_ascii_lowercase() {
        return Err(failed(
            "intentional-boundary checkout changed revision during materialization",
        ));
    }
    let mut artifact = IntentionalBoundaryMaterialization {
        schema_version: INTENTIONAL_BOUNDARY_MATERIALIZATION_SCHEMA_VERSION,
        materialization_contract: MATERIALIZATION_CONTRACT.to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        population_rank,
        population_rank_sha256: repository.population_rank_sha256.clone(),
        repository: repository.repository.clone(),
        clone_url: canonical_clone_url.to_string(),
        revision: facts.revision,
        git_object_format: facts.object_format,
        tree_oid: facts.tree_oid,
        materialization_sha256: String::new(),
    };
    artifact.materialization_sha256 = materialization_sha256(&artifact)?;
    Ok(IntentionalBoundaryMaterializationOutcome::Completed(
        IntentionalBoundaryMaterializedRepository {
            artifact,
            checkout_root: destination.to_path_buf(),
        },
    ))
}

fn expected_repository(
    task: &IntentionalBoundaryFrameTask,
    population_rank: usize,
) -> Result<&super::IntentionalBoundaryRepositoryTask, IntentionalBoundaryMaterializationError> {
    if !task.no_fallbacks
        || !task.model_access_forbidden
        || !task.sniff_output_access_forbidden
        || task.task_sha256.len() != 64
    {
        return Err(invalid(
            "intentional-boundary materialization task contract is invalid",
        ));
    }
    task.repositories
        .get(population_rank.saturating_sub(1))
        .filter(|repository| repository.population_rank == population_rank)
        .ok_or_else(|| invalid("intentional-boundary materialization rank is not in the task"))
}

fn require_new_destination(
    destination: &Path,
) -> Result<(), IntentionalBoundaryMaterializationError> {
    if destination.file_name().is_none() || destination.parent().is_none() || destination.exists() {
        return Err(invalid(
            "intentional-boundary materialization destination must be a new child path",
        ));
    }
    Ok(())
}

fn exclusion(
    task: &IntentionalBoundaryFrameTask,
    population_rank: usize,
    reason: IntentionalBoundaryMaterializationExclusionReason,
    evidence: IntentionalBoundaryMaterializationExclusionEvidence,
) -> Result<IntentionalBoundaryMaterializationExclusion, IntentionalBoundaryMaterializationError> {
    let repository = expected_repository(task, population_rank)?;
    let mut exclusion = IntentionalBoundaryMaterializationExclusion {
        schema_version: INTENTIONAL_BOUNDARY_MATERIALIZATION_EXCLUSION_SCHEMA_VERSION,
        exclusion_contract: EXCLUSION_CONTRACT.to_string(),
        frame_task_sha256: task.task_sha256.clone(),
        population_rank,
        population_rank_sha256: repository.population_rank_sha256.clone(),
        repository: repository.repository.clone(),
        reason,
        evidence,
        exclusion_sha256: String::new(),
    };
    exclusion.exclusion_sha256 = exclusion_sha256(&exclusion)?;
    Ok(exclusion)
}

fn exclusion_sha256(
    artifact: &IntentionalBoundaryMaterializationExclusion,
) -> Result<String, IntentionalBoundaryMaterializationError> {
    hash_json(&(
        artifact.schema_version,
        &artifact.exclusion_contract,
        &artifact.frame_task_sha256,
        artifact.population_rank,
        &artifact.population_rank_sha256,
        &artifact.repository,
        artifact.reason,
        &artifact.evidence,
    ))
}

fn materialization_sha256(
    artifact: &IntentionalBoundaryMaterialization,
) -> Result<String, IntentionalBoundaryMaterializationError> {
    hash_json(&(
        artifact.schema_version,
        &artifact.materialization_contract,
        &artifact.frame_task_sha256,
        artifact.population_rank,
        &artifact.population_rank_sha256,
        &artifact.repository,
        &artifact.clone_url,
        &artifact.revision,
        &artifact.git_object_format,
        &artifact.tree_oid,
    ))
}

fn hash_json(value: &impl Serialize) -> Result<String, IntentionalBoundaryMaterializationError> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| invalid(format!("failed to commit materialization: {error}")))
}

fn invalid(detail: impl Into<String>) -> IntentionalBoundaryMaterializationError {
    IntentionalBoundaryMaterializationError {
        kind: IntentionalBoundaryMaterializationErrorKind::InvalidInput,
        detail: detail.into(),
    }
}

fn unavailable(detail: impl Into<String>) -> IntentionalBoundaryMaterializationError {
    IntentionalBoundaryMaterializationError {
        kind: IntentionalBoundaryMaterializationErrorKind::InfrastructureUnavailable,
        detail: detail.into(),
    }
}

fn failed(detail: impl Into<String>) -> IntentionalBoundaryMaterializationError {
    IntentionalBoundaryMaterializationError {
        kind: IntentionalBoundaryMaterializationErrorKind::InfrastructureFailed,
        detail: detail.into(),
    }
}

#[cfg(test)]
pub(super) fn materialize_intentional_boundary_repository_fixture(
    task: &IntentionalBoundaryFrameTask,
    population_rank: usize,
    destination: &Path,
    source: &Path,
) -> Result<IntentionalBoundaryMaterializationOutcome, IntentionalBoundaryMaterializationError> {
    let repository = expected_repository(task, population_rank)?;
    let canonical_clone_url = format!("https://{}.git", repository.repository);
    materialize_from_clone_url(
        task,
        population_rank,
        destination,
        &source.to_string_lossy(),
        &canonical_clone_url,
    )
}

#[cfg(test)]
pub(super) fn rematerialize_intentional_boundary_repository_fixture(
    task: &IntentionalBoundaryFrameTask,
    artifact: &IntentionalBoundaryMaterialization,
    destination: &Path,
    source: &Path,
) -> Result<IntentionalBoundaryMaterializedRepository, IntentionalBoundaryMaterializationError> {
    validate_intentional_boundary_materialization_commitment(task, artifact)?;
    require_new_destination(destination)?;
    let result = clone_repository_for_exact_revision(
        &source.to_string_lossy(),
        destination,
        &artifact.revision,
    )
    .and_then(|()| finalize_exact_rematerialization(task, artifact, destination));
    if result.is_err() {
        remove_partial(destination)?;
    }
    result
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_materialization_tests.rs"]
mod tests;
