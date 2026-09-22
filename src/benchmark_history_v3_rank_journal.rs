#[path = "benchmark_history_v3_rank_journal_schema.rs"]
mod schema;

pub use schema::*;

#[path = "benchmark_history_v3_rank_journal_commitment.rs"]
mod commitment;

pub use commitment::{
    append_historical_v3_rank_checkpoint, historical_v3_rank_identity,
    validate_historical_v3_rank_history,
};

#[path = "benchmark_history_v3_rank_journal_store.rs"]
mod store;

pub use store::{HistoricalV3RankJournal, HistoricalV3StoredRankStage};

use super::{
    HistoricalV3CandidateCollection, HistoricalV3Materialization, HistoricalV3MaterializationError,
    HistoricalV3MaterializationErrorKind, HistoricalV3MaterializationExclusion,
    HistoricalV3MaterializationOutcome, HistoricalV3MaterializedRoots, HistoricalV3Protocol,
    history_v3_materialization::validate_historical_v3_materialization_resume,
    materialize_historical_v3_candidate, validate_historical_v3_materialization,
    validate_historical_v3_materialization_exclusion,
};
use serde::de::DeserializeOwned;
use std::fs;
use std::path::{Path, PathBuf};

pub fn run_historical_v3_materialization_stage(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    stream_rank: usize,
    journal_root: &Path,
    workspace_root: &Path,
) -> Result<HistoricalV3MaterializationStageRun, HistoricalV3RankJournalError> {
    run_materialization_stage_with(
        protocol,
        collection,
        stream_rank,
        journal_root,
        workspace_root,
        |destination| {
            materialize_historical_v3_candidate(protocol, collection, stream_rank, destination)
        },
    )
}

pub(super) fn run_materialization_stage_with<F>(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    stream_rank: usize,
    journal_root: &Path,
    workspace_root: &Path,
    materialize: F,
) -> Result<HistoricalV3MaterializationStageRun, HistoricalV3RankJournalError>
where
    F: FnOnce(
        &Path,
    ) -> Result<HistoricalV3MaterializationOutcome, HistoricalV3MaterializationError>,
{
    let identity = historical_v3_rank_identity(protocol, collection, stream_rank)
        .map_err(|detail| HistoricalV3RankJournalError::invalid(stage(), detail))?;
    let mut journal = HistoricalV3RankJournal::open(journal_root, &identity)?;
    let destination = rank_workspace(workspace_root, &identity)?;
    if let Some(stored) = journal.history().first() {
        return resume_materialization(protocol, collection, stored, &destination);
    }
    remove_uncommitted_workspace(&destination)?;
    let outcome = materialize(&destination).map_err(HistoricalV3RankJournalError::from)?;
    match outcome {
        HistoricalV3MaterializationOutcome::Completed { artifact, roots } => {
            validate_historical_v3_materialization(protocol, collection, &artifact, &roots)
                .map_err(HistoricalV3RankJournalError::from)?;
            journal.append(
                stage(),
                HistoricalV3RankStageOutcome::Completed {
                    artifact_kind: HistoricalV3RankArtifactKind::Materialization,
                    artifact_sha256: artifact.materialization_sha256.clone(),
                },
                Some(artifact.as_ref()),
            )?;
            Ok(HistoricalV3MaterializationStageRun::Completed {
                artifact,
                roots,
                resumed: false,
            })
        }
        HistoricalV3MaterializationOutcome::Excluded(artifact) => {
            validate_historical_v3_materialization_exclusion(protocol, collection, &artifact)
                .map_err(HistoricalV3RankJournalError::from)?;
            if destination.exists() {
                return Err(HistoricalV3RankJournalError::invalid(
                    stage(),
                    "historical-v3 excluded materialization retained a workspace",
                ));
            }
            journal.append(
                stage(),
                HistoricalV3RankStageOutcome::Excluded {
                    artifact_kind: HistoricalV3RankArtifactKind::MaterializationExclusion,
                    artifact_sha256: artifact.exclusion_sha256.clone(),
                },
                Some(artifact.as_ref()),
            )?;
            Ok(HistoricalV3MaterializationStageRun::Excluded {
                artifact,
                resumed: false,
            })
        }
    }
}

fn resume_materialization(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    stored: &HistoricalV3StoredRankStage,
    destination: &Path,
) -> Result<HistoricalV3MaterializationStageRun, HistoricalV3RankJournalError> {
    match &stored.checkpoint.outcome {
        HistoricalV3RankStageOutcome::Completed {
            artifact_kind: HistoricalV3RankArtifactKind::Materialization,
            artifact_sha256,
        } => {
            let artifact = read_required_artifact::<HistoricalV3Materialization>(stored)?;
            if artifact.materialization_sha256 != *artifact_sha256 {
                return Err(HistoricalV3RankJournalError::invalid(
                    stage(),
                    "historical-v3 materialization artifact does not match its checkpoint",
                ));
            }
            let roots = materialized_roots(destination);
            validate_historical_v3_materialization_resume(protocol, collection, &artifact, &roots)
                .map_err(HistoricalV3RankJournalError::from)?;
            Ok(HistoricalV3MaterializationStageRun::Completed {
                artifact: Box::new(artifact),
                roots,
                resumed: true,
            })
        }
        HistoricalV3RankStageOutcome::Excluded {
            artifact_kind: HistoricalV3RankArtifactKind::MaterializationExclusion,
            artifact_sha256,
        } => {
            if destination.exists() {
                return Err(HistoricalV3RankJournalError::invalid(
                    stage(),
                    "historical-v3 excluded rank unexpectedly has a workspace",
                ));
            }
            let artifact = read_required_artifact::<HistoricalV3MaterializationExclusion>(stored)?;
            if artifact.exclusion_sha256 != *artifact_sha256 {
                return Err(HistoricalV3RankJournalError::invalid(
                    stage(),
                    "historical-v3 exclusion artifact does not match its checkpoint",
                ));
            }
            validate_historical_v3_materialization_exclusion(protocol, collection, &artifact)
                .map_err(HistoricalV3RankJournalError::from)?;
            Ok(HistoricalV3MaterializationStageRun::Excluded {
                artifact: Box::new(artifact),
                resumed: true,
            })
        }
        _ => Err(HistoricalV3RankJournalError::invalid(
            stage(),
            "historical-v3 rank journal has an invalid materialization outcome",
        )),
    }
}

fn read_required_artifact<T: DeserializeOwned>(
    stored: &HistoricalV3StoredRankStage,
) -> Result<T, HistoricalV3RankJournalError> {
    stored
        .read_artifact()
        .map_err(|detail| HistoricalV3RankJournalError::invalid(stage(), detail))?
        .ok_or_else(|| {
            HistoricalV3RankJournalError::invalid(
                stage(),
                "historical-v3 materialization checkpoint has no artifact",
            )
        })
}

pub(super) fn rank_workspace(
    root: &Path,
    identity: &HistoricalV3RankIdentity,
) -> Result<PathBuf, HistoricalV3RankJournalError> {
    fs::create_dir_all(root).map_err(|error| {
        HistoricalV3RankJournalError::infrastructure(
            stage(),
            format!("failed to create historical-v3 workspace root: {error}"),
        )
    })?;
    let root = canonical_plain_directory(root, "historical-v3 workspace root")?;
    let task_root = create_workspace_child(&root, &identity.stream_task_sha256, "task")?;
    let language_root = create_workspace_child(&task_root, language_name(identity), "language")?;
    Ok(language_root.join(format!("rank-{:08}", identity.stream_rank)))
}

fn create_workspace_child(
    parent: &Path,
    name: &str,
    label: &str,
) -> Result<PathBuf, HistoricalV3RankJournalError> {
    let child = parent.join(name);
    if child.exists() {
        let resolved =
            canonical_plain_directory(&child, &format!("historical-v3 {label} workspace"))?;
        if resolved.parent() != Some(parent) {
            return Err(HistoricalV3RankJournalError::invalid(
                stage(),
                format!("historical-v3 {label} workspace escaped its parent"),
            ));
        }
        return Ok(resolved);
    }
    fs::create_dir(&child).map_err(|error| {
        HistoricalV3RankJournalError::infrastructure(
            stage(),
            format!("failed to create historical-v3 {label} workspace: {error}"),
        )
    })?;
    canonical_plain_directory(&child, &format!("historical-v3 {label} workspace"))
}

fn canonical_plain_directory(
    path: &Path,
    label: &str,
) -> Result<PathBuf, HistoricalV3RankJournalError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        HistoricalV3RankJournalError::infrastructure(
            stage(),
            format!("failed to inspect {label}: {error}"),
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(HistoricalV3RankJournalError::invalid(
            stage(),
            format!("{label} is not a plain directory"),
        ));
    }
    fs::canonicalize(path).map_err(|error| {
        HistoricalV3RankJournalError::infrastructure(
            stage(),
            format!("failed to resolve {label}: {error}"),
        )
    })
}

fn remove_uncommitted_workspace(destination: &Path) -> Result<(), HistoricalV3RankJournalError> {
    if !destination.exists() {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(destination).map_err(|error| {
        HistoricalV3RankJournalError::infrastructure(
            stage(),
            format!("failed to inspect uncommitted historical-v3 workspace: {error}"),
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(HistoricalV3RankJournalError::invalid(
            stage(),
            "uncommitted historical-v3 workspace is not a plain directory",
        ));
    }
    fs::remove_dir_all(destination).map_err(|error| {
        HistoricalV3RankJournalError::infrastructure(
            stage(),
            format!("failed to remove uncommitted historical-v3 workspace: {error}"),
        )
    })
}

pub(super) fn materialized_roots(destination: &Path) -> HistoricalV3MaterializedRoots {
    HistoricalV3MaterializedRoots {
        repository_root: destination.join("repository"),
        base_root: destination.join("base"),
        head_root: destination.join("head"),
        merge_root: destination.join("merge"),
        reproduced_root: destination.join("reproduced"),
        patch_path: destination.join("merge.patch"),
    }
}

fn language_name(identity: &HistoricalV3RankIdentity) -> &'static str {
    use super::HistoricalV3Language as Language;
    match identity.language() {
        Language::Go => "go",
        Language::JavaScript => "javascript",
        Language::Kotlin => "kotlin",
        Language::Python => "python",
        Language::Rust => "rust",
        Language::TypeScript => "typescript",
    }
}

fn stage() -> HistoricalV3RankStage {
    HistoricalV3RankStage::Materialization
}

impl HistoricalV3RankJournalError {
    pub(super) fn invalid(stage: HistoricalV3RankStage, detail: impl Into<String>) -> Self {
        Self {
            stage,
            kind: HistoricalV3RankJournalErrorKind::InvalidInput,
            detail: detail.into(),
        }
    }

    pub(super) fn infrastructure(stage: HistoricalV3RankStage, detail: impl Into<String>) -> Self {
        Self {
            stage,
            kind: HistoricalV3RankJournalErrorKind::InfrastructureFailed,
            detail: detail.into(),
        }
    }
}

impl From<HistoricalV3MaterializationError> for HistoricalV3RankJournalError {
    fn from(error: HistoricalV3MaterializationError) -> Self {
        let kind = match error.kind {
            HistoricalV3MaterializationErrorKind::InvalidInput => {
                HistoricalV3RankJournalErrorKind::InvalidInput
            }
            HistoricalV3MaterializationErrorKind::InfrastructureUnavailable => {
                HistoricalV3RankJournalErrorKind::InfrastructureUnavailable
            }
            HistoricalV3MaterializationErrorKind::InfrastructureFailed => {
                HistoricalV3RankJournalErrorKind::InfrastructureFailed
            }
        };
        Self {
            stage: stage(),
            kind,
            detail: error.detail,
        }
    }
}

#[cfg(test)]
#[path = "benchmark_history_v3_rank_journal_tests.rs"]
mod tests;
