use super::super::history_v3_rank_journal::{materialized_roots, rank_workspace};
use super::super::intentional_boundary_source_census::{
    INTENTIONAL_BOUNDARY_SOURCE_EXTENSION_CONTRACT, IntentionalBoundarySourceInspection,
    inspect_intentional_boundary_repository_sources_typed,
};
use super::super::{
    HISTORICAL_V3_SOURCE_CENSUS_EXCLUSION_SCHEMA_VERSION,
    HISTORICAL_V3_SOURCE_CENSUS_SCHEMA_VERSION, HistoricalV3CandidateCollection,
    HistoricalV3Materialization, HistoricalV3Protocol, HistoricalV3RankArtifactKind,
    HistoricalV3RankJournal, HistoricalV3RankJournalError, HistoricalV3RankJournalErrorKind,
    HistoricalV3RankStage, HistoricalV3RankStageOutcome, HistoricalV3SourceCensus,
    HistoricalV3SourceCensusExclusion, HistoricalV3SourceCensusExclusionReason,
    HistoricalV3SourceCensusStageRun, HistoricalV3SourceSide, HistoricalV3SourceSnapshot,
    HistoricalV3SourceSnapshotEvidence, HistoricalV3StoredRankStage,
    IntentionalBoundaryInventoryError, IntentionalBoundaryInventoryErrorKind,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundarySourceCensusFailureEvidence,
    historical_v3_rank_identity, inventory_intentional_boundary_repository_typed,
    validate_historical_v3_materialization, validate_historical_v3_source_census_commitment,
    validate_historical_v3_source_census_exclusion,
};
use super::commitment::{seal_snapshot, seal_source_census, seal_source_exclusion};
use super::{SOURCE_CENSUS_CONTRACT, SOURCE_CENSUS_EXCLUSION_CONTRACT};
use serde::de::DeserializeOwned;
use std::path::Path;

enum SnapshotInspection {
    Completed(Box<HistoricalV3SourceSnapshot>),
    Excluded(HistoricalV3SourceSnapshotEvidence),
}

pub fn run_historical_v3_source_census_stage(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    stream_rank: usize,
    journal_root: &Path,
    workspace_root: &Path,
) -> Result<HistoricalV3SourceCensusStageRun, HistoricalV3RankJournalError> {
    let identity =
        historical_v3_rank_identity(protocol, collection, stream_rank).map_err(invalid)?;
    let mut journal = HistoricalV3RankJournal::open(journal_root, &identity)?;
    let materialization_stage = journal
        .history()
        .first()
        .ok_or_else(|| invalid("historical-v3 source census requires materialization"))?;
    let materialization = read_materialization(materialization_stage)?;
    if materialization.identity != identity.candidate
        || materialization.materialization_sha256 != checkpoint_artifact_sha(materialization_stage)?
    {
        return Err(invalid(
            "historical-v3 source census materialization binding changed",
        ));
    }

    if let Some(stored) = journal.history().get(1) {
        return resume_source_census(protocol, collection, &materialization, stored);
    }
    if journal.next_stage() != Some(HistoricalV3RankStage::SourceCensus) {
        return Err(invalid("historical-v3 rank is not open for source census"));
    }

    let destination = rank_workspace(workspace_root, &identity)?;
    let roots = materialized_roots(&destination);
    validate_historical_v3_materialization(protocol, collection, &materialization, &roots)
        .map_err(HistoricalV3RankJournalError::from)?;
    let repository = format!("github.com/{}", identity.name_with_owner);
    let base = inspect_snapshot(
        HistoricalV3SourceSide::Base,
        &repository,
        &materialization.identity.base_commit,
        &roots.base_root,
    )?;
    let merge = inspect_snapshot(
        HistoricalV3SourceSide::Merge,
        &repository,
        &materialization.identity.merge_commit,
        &roots.merge_root,
    )?;

    match (base, merge) {
        (SnapshotInspection::Completed(base), SnapshotInspection::Completed(merge)) => {
            let artifact = seal_source_census(HistoricalV3SourceCensus {
                schema_version: HISTORICAL_V3_SOURCE_CENSUS_SCHEMA_VERSION,
                source_census_contract: SOURCE_CENSUS_CONTRACT.to_string(),
                rank: identity,
                materialization_sha256: materialization.materialization_sha256.clone(),
                source_extension_contract: INTENTIONAL_BOUNDARY_SOURCE_EXTENSION_CONTRACT
                    .to_string(),
                base: *base,
                merge: *merge,
                source_census_sha256: String::new(),
            })
            .map_err(invalid)?;
            validate_historical_v3_source_census_commitment(
                protocol,
                collection,
                &materialization,
                &artifact,
            )
            .map_err(invalid)?;
            journal.append(
                HistoricalV3RankStage::SourceCensus,
                HistoricalV3RankStageOutcome::Completed {
                    artifact_kind: HistoricalV3RankArtifactKind::SourceCensus,
                    artifact_sha256: artifact.source_census_sha256.clone(),
                },
                Some(&artifact),
            )?;
            Ok(HistoricalV3SourceCensusStageRun::Completed {
                artifact: Box::new(artifact),
                resumed: false,
            })
        }
        (base, merge) => {
            let artifact = seal_source_exclusion(HistoricalV3SourceCensusExclusion {
                schema_version: HISTORICAL_V3_SOURCE_CENSUS_EXCLUSION_SCHEMA_VERSION,
                exclusion_contract: SOURCE_CENSUS_EXCLUSION_CONTRACT.to_string(),
                rank: identity,
                materialization_sha256: materialization.materialization_sha256.clone(),
                source_extension_contract: INTENTIONAL_BOUNDARY_SOURCE_EXTENSION_CONTRACT
                    .to_string(),
                sides: vec![side_evidence(base), side_evidence(merge)],
                exclusion_sha256: String::new(),
            })
            .map_err(invalid)?;
            validate_historical_v3_source_census_exclusion(
                protocol,
                collection,
                &materialization,
                &artifact,
            )
            .map_err(invalid)?;
            journal.append(
                HistoricalV3RankStage::SourceCensus,
                HistoricalV3RankStageOutcome::Excluded {
                    artifact_kind: HistoricalV3RankArtifactKind::SourceCensusExclusion,
                    artifact_sha256: artifact.exclusion_sha256.clone(),
                },
                Some(&artifact),
            )?;
            Ok(HistoricalV3SourceCensusStageRun::Excluded {
                artifact: Box::new(artifact),
                resumed: false,
            })
        }
    }
}

fn inspect_snapshot(
    side: HistoricalV3SourceSide,
    repository: &str,
    revision: &str,
    root: &Path,
) -> Result<SnapshotInspection, HistoricalV3RankJournalError> {
    let inventory = inventory_intentional_boundary_repository_typed(repository, revision, root)
        .map_err(map_inventory_error)?;
    let inspection = inspect_intentional_boundary_repository_sources_typed(
        repository, revision, root, &inventory,
    )
    .map_err(map_inventory_error)?;
    match inspection {
        IntentionalBoundarySourceInspection::Completed(source_census)
            if source_census.source_files.is_empty() =>
        {
            Ok(SnapshotInspection::Excluded(excluded_evidence(
                side,
                revision,
                inventory,
                HistoricalV3SourceCensusExclusionReason::NoSupportedSources,
                Vec::new(),
            )))
        }
        IntentionalBoundarySourceInspection::Completed(source_census) => {
            seal_snapshot(HistoricalV3SourceSnapshot {
                side,
                revision: revision.to_string(),
                inventory,
                source_census,
                snapshot_sha256: String::new(),
            })
            .map(Box::new)
            .map(SnapshotInspection::Completed)
            .map_err(invalid)
        }
        IntentionalBoundarySourceInspection::Excluded(failures) => {
            Ok(SnapshotInspection::Excluded(excluded_evidence(
                side,
                revision,
                inventory,
                HistoricalV3SourceCensusExclusionReason::UnsupportedProjectShape,
                failures,
            )))
        }
    }
}

fn excluded_evidence(
    side: HistoricalV3SourceSide,
    revision: &str,
    inventory: IntentionalBoundaryRepositoryInventory,
    reason: HistoricalV3SourceCensusExclusionReason,
    failures: Vec<IntentionalBoundarySourceCensusFailureEvidence>,
) -> HistoricalV3SourceSnapshotEvidence {
    HistoricalV3SourceSnapshotEvidence::Excluded {
        side,
        revision: revision.to_string(),
        inventory: Box::new(inventory),
        reason,
        failures,
    }
}

fn side_evidence(inspection: SnapshotInspection) -> HistoricalV3SourceSnapshotEvidence {
    match inspection {
        SnapshotInspection::Completed(snapshot) => {
            HistoricalV3SourceSnapshotEvidence::Completed { snapshot }
        }
        SnapshotInspection::Excluded(evidence) => evidence,
    }
}

fn resume_source_census(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    materialization: &HistoricalV3Materialization,
    stored: &HistoricalV3StoredRankStage,
) -> Result<HistoricalV3SourceCensusStageRun, HistoricalV3RankJournalError> {
    match &stored.checkpoint.outcome {
        HistoricalV3RankStageOutcome::Completed {
            artifact_kind: HistoricalV3RankArtifactKind::SourceCensus,
            artifact_sha256,
        } => {
            let artifact = read_required_artifact::<HistoricalV3SourceCensus>(stored)?;
            if artifact.source_census_sha256 != *artifact_sha256 {
                return Err(invalid(
                    "historical-v3 source census does not match its checkpoint",
                ));
            }
            validate_historical_v3_source_census_commitment(
                protocol,
                collection,
                materialization,
                &artifact,
            )
            .map_err(invalid)?;
            Ok(HistoricalV3SourceCensusStageRun::Completed {
                artifact: Box::new(artifact),
                resumed: true,
            })
        }
        HistoricalV3RankStageOutcome::Excluded {
            artifact_kind: HistoricalV3RankArtifactKind::SourceCensusExclusion,
            artifact_sha256,
        } => {
            let artifact = read_required_artifact::<HistoricalV3SourceCensusExclusion>(stored)?;
            if artifact.exclusion_sha256 != *artifact_sha256 {
                return Err(invalid(
                    "historical-v3 source exclusion does not match its checkpoint",
                ));
            }
            validate_historical_v3_source_census_exclusion(
                protocol,
                collection,
                materialization,
                &artifact,
            )
            .map_err(invalid)?;
            Ok(HistoricalV3SourceCensusStageRun::Excluded {
                artifact: Box::new(artifact),
                resumed: true,
            })
        }
        _ => Err(invalid(
            "historical-v3 rank journal has an invalid source census outcome",
        )),
    }
}

fn read_materialization(
    stored: &HistoricalV3StoredRankStage,
) -> Result<HistoricalV3Materialization, HistoricalV3RankJournalError> {
    if !matches!(
        stored.checkpoint.outcome,
        HistoricalV3RankStageOutcome::Completed {
            artifact_kind: HistoricalV3RankArtifactKind::Materialization,
            ..
        }
    ) {
        return Err(invalid(
            "historical-v3 source census requires completed materialization",
        ));
    }
    read_required_artifact(stored)
}

fn checkpoint_artifact_sha(
    stored: &HistoricalV3StoredRankStage,
) -> Result<&str, HistoricalV3RankJournalError> {
    match &stored.checkpoint.outcome {
        HistoricalV3RankStageOutcome::Completed {
            artifact_sha256, ..
        } => Ok(artifact_sha256),
        _ => Err(invalid(
            "historical-v3 materialization checkpoint is not completed",
        )),
    }
}

fn read_required_artifact<T: DeserializeOwned>(
    stored: &HistoricalV3StoredRankStage,
) -> Result<T, HistoricalV3RankJournalError> {
    stored
        .read_artifact()
        .map_err(invalid)?
        .ok_or_else(|| invalid("historical-v3 rank checkpoint has no artifact"))
}

fn map_inventory_error(error: IntentionalBoundaryInventoryError) -> HistoricalV3RankJournalError {
    HistoricalV3RankJournalError {
        stage: HistoricalV3RankStage::SourceCensus,
        kind: match error.kind {
            IntentionalBoundaryInventoryErrorKind::InvalidInput => {
                HistoricalV3RankJournalErrorKind::InvalidInput
            }
            IntentionalBoundaryInventoryErrorKind::InfrastructureUnavailable => {
                HistoricalV3RankJournalErrorKind::InfrastructureUnavailable
            }
            IntentionalBoundaryInventoryErrorKind::InfrastructureFailed => {
                HistoricalV3RankJournalErrorKind::InfrastructureFailed
            }
        },
        detail: error.detail,
    }
}

fn invalid(detail: impl Into<String>) -> HistoricalV3RankJournalError {
    HistoricalV3RankJournalError {
        stage: HistoricalV3RankStage::SourceCensus,
        kind: HistoricalV3RankJournalErrorKind::InvalidInput,
        detail: detail.into(),
    }
}
