use super::super::history_v3_rank_journal::{materialized_roots, rank_workspace};
use super::super::intentional_boundary_semantic::build_semantic_census;
use super::super::intentional_boundary_semantic_stage_support::{
    ResolvedSemanticRun, assembly_failure, resolve_semantic_run,
};
use super::super::intentional_boundary_source_census::intentional_boundary_file_records_typed;
use super::super::{
    HISTORICAL_V3_SEMANTIC_CENSUS_EXCLUSION_SCHEMA_VERSION,
    HISTORICAL_V3_SEMANTIC_CENSUS_SCHEMA_VERSION, HistoricalV3CandidateCollection,
    HistoricalV3Protocol, HistoricalV3RankArtifactKind, HistoricalV3RankJournal,
    HistoricalV3RankJournalError, HistoricalV3RankJournalErrorKind, HistoricalV3RankStage,
    HistoricalV3RankStageOutcome, HistoricalV3SemanticCensus, HistoricalV3SemanticCensusExclusion,
    HistoricalV3SemanticCensusStageRun, HistoricalV3SemanticSnapshot,
    HistoricalV3SemanticSnapshotEvidence, HistoricalV3SourceSide, HistoricalV3SourceSnapshot,
    IntentionalBoundarySemanticCensusFailureEvidence, historical_v3_rank_identity,
    validate_historical_v3_materialization, validate_historical_v3_semantic_census_commitment,
    validate_historical_v3_semantic_census_exclusion,
    validate_historical_v3_source_census_commitment,
};
use super::commitment::{seal_semantic_census, seal_semantic_exclusion, seal_snapshot};
use super::store::{
    invalid, map_inventory_error, map_semantic_error, read_completed_materialization,
    read_completed_source_census, resume_semantic_census,
};
use super::surface::{canonicalize_indexes, collect_surface_symbols, index_evidence};
use super::{SEMANTIC_CENSUS_CONTRACT, SEMANTIC_CENSUS_EXCLUSION_CONTRACT};
use crate::semantic_indexer_manifest::INDEXER_INSTALL_CONTRACT;
use crate::semantic_indexer_runner::{SemanticIndexerBatchOutcome, SemanticIndexerRunFailure};
use crate::types::FileRecord;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;

type SemanticRunResult = Result<SemanticIndexerBatchOutcome, SemanticIndexerRunFailure>;
pub(super) type SemanticRunFuture<'a> = Pin<Box<dyn Future<Output = SemanticRunResult> + 'a>>;

enum SnapshotInspection {
    Completed(Box<HistoricalV3SemanticSnapshot>),
    Excluded(HistoricalV3SemanticSnapshotEvidence),
}

pub async fn run_historical_v3_semantic_census_stage(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    stream_rank: usize,
    journal_root: &Path,
    workspace_root: &Path,
) -> Result<HistoricalV3SemanticCensusStageRun, HistoricalV3RankJournalError> {
    run_historical_v3_semantic_census_stage_with(
        protocol,
        collection,
        stream_rank,
        journal_root,
        workspace_root,
        |root, files| {
            Box::pin(
                crate::semantic_indexer_runner::run_required_indexers_exhaustive_typed(root, files),
            )
        },
    )
    .await
}

pub(super) async fn run_historical_v3_semantic_census_stage_with<F>(
    protocol: &HistoricalV3Protocol,
    collection: &HistoricalV3CandidateCollection,
    stream_rank: usize,
    journal_root: &Path,
    workspace_root: &Path,
    run_indexers: F,
) -> Result<HistoricalV3SemanticCensusStageRun, HistoricalV3RankJournalError>
where
    F: for<'a> Fn(&'a Path, &'a [FileRecord]) -> SemanticRunFuture<'a>,
{
    let identity =
        historical_v3_rank_identity(protocol, collection, stream_rank).map_err(invalid)?;
    let mut journal = HistoricalV3RankJournal::open(journal_root, &identity)?;
    let materialization_stage = journal
        .history()
        .first()
        .ok_or_else(|| invalid("historical-v3 semantic census requires materialization"))?;
    let source_stage = journal
        .history()
        .get(1)
        .ok_or_else(|| invalid("historical-v3 semantic census requires source census"))?;
    let materialization = read_completed_materialization(materialization_stage)?;
    let source_census = read_completed_source_census(source_stage)?;
    validate_historical_v3_source_census_commitment(
        protocol,
        collection,
        &materialization,
        &source_census,
    )
    .map_err(invalid)?;

    if let Some(stored) = journal.history().get(2) {
        return resume_semantic_census(
            protocol,
            collection,
            &materialization,
            &source_census,
            stored,
        );
    }
    if journal.next_stage() != Some(HistoricalV3RankStage::SemanticCensus) {
        return Err(invalid(
            "historical-v3 rank is not open for semantic census",
        ));
    }

    let destination = rank_workspace(workspace_root, &identity)?;
    let roots = materialized_roots(&destination);
    validate_historical_v3_materialization(protocol, collection, &materialization, &roots)
        .map_err(HistoricalV3RankJournalError::from)?;
    let base_files = intentional_boundary_file_records_typed(
        &roots.base_root,
        &source_census.base.inventory,
        &source_census.base.source_census,
    )
    .map_err(map_inventory_error)?;
    let merge_files = intentional_boundary_file_records_typed(
        &roots.merge_root,
        &source_census.merge.inventory,
        &source_census.merge.source_census,
    )
    .map_err(map_inventory_error)?;

    let base_run = run_indexers(&roots.base_root, &base_files).await;
    let merge_run = run_indexers(&roots.merge_root, &merge_files).await;
    let base = inspect_snapshot(
        HistoricalV3SourceSide::Base,
        &source_census.base,
        &roots.base_root,
        &base_files,
        base_run,
    );
    let merge = inspect_snapshot(
        HistoricalV3SourceSide::Merge,
        &source_census.merge,
        &roots.merge_root,
        &merge_files,
        merge_run,
    );
    let (base, merge) = resolve_both_sides(base, merge)?;

    match (base, merge) {
        (SnapshotInspection::Completed(base), SnapshotInspection::Completed(merge)) => {
            let artifact = seal_semantic_census(HistoricalV3SemanticCensus {
                schema_version: HISTORICAL_V3_SEMANTIC_CENSUS_SCHEMA_VERSION,
                semantic_census_contract: SEMANTIC_CENSUS_CONTRACT.to_string(),
                indexer_install_contract: INDEXER_INSTALL_CONTRACT.to_string(),
                rank: identity,
                materialization_sha256: materialization.materialization_sha256.clone(),
                source_census_sha256: source_census.source_census_sha256.clone(),
                base: *base,
                merge: *merge,
                semantic_census_sha256: String::new(),
            })
            .map_err(invalid)?;
            validate_historical_v3_semantic_census_commitment(
                protocol,
                collection,
                &materialization,
                &source_census,
                &artifact,
            )
            .map_err(invalid)?;
            journal.append(
                HistoricalV3RankStage::SemanticCensus,
                HistoricalV3RankStageOutcome::Completed {
                    artifact_kind: HistoricalV3RankArtifactKind::SemanticCensus,
                    artifact_sha256: artifact.semantic_census_sha256.clone(),
                },
                Some(&artifact),
            )?;
            Ok(HistoricalV3SemanticCensusStageRun::Completed {
                artifact: Box::new(artifact),
                resumed: false,
            })
        }
        (base, merge) => {
            let artifact = seal_semantic_exclusion(HistoricalV3SemanticCensusExclusion {
                schema_version: HISTORICAL_V3_SEMANTIC_CENSUS_EXCLUSION_SCHEMA_VERSION,
                exclusion_contract: SEMANTIC_CENSUS_EXCLUSION_CONTRACT.to_string(),
                indexer_install_contract: INDEXER_INSTALL_CONTRACT.to_string(),
                rank: identity,
                materialization_sha256: materialization.materialization_sha256.clone(),
                source_census_sha256: source_census.source_census_sha256.clone(),
                sides: vec![side_evidence(base), side_evidence(merge)],
                exclusion_sha256: String::new(),
            })
            .map_err(invalid)?;
            validate_historical_v3_semantic_census_exclusion(
                protocol,
                collection,
                &materialization,
                &source_census,
                &artifact,
            )
            .map_err(invalid)?;
            journal.append(
                HistoricalV3RankStage::SemanticCensus,
                HistoricalV3RankStageOutcome::Excluded {
                    artifact_kind: HistoricalV3RankArtifactKind::SemanticCensusExclusion,
                    artifact_sha256: artifact.exclusion_sha256.clone(),
                },
                Some(&artifact),
            )?;
            Ok(HistoricalV3SemanticCensusStageRun::Excluded {
                artifact: Box::new(artifact),
                resumed: false,
            })
        }
    }
}

fn inspect_snapshot(
    side: HistoricalV3SourceSide,
    source: &HistoricalV3SourceSnapshot,
    root: &Path,
    files: &[FileRecord],
    run: SemanticRunResult,
) -> Result<SnapshotInspection, HistoricalV3RankJournalError> {
    let indexes = match resolve_semantic_run(run).map_err(map_semantic_error)? {
        ResolvedSemanticRun::Completed(indexes) => indexes,
        ResolvedSemanticRun::Excluded(failures) => {
            return Ok(SnapshotInspection::Excluded(excluded_evidence(
                side, source, failures,
            )));
        }
    };
    let built = (|| {
        let indexes = canonicalize_indexes(root, &indexes);
        let semantic_census = build_semantic_census(root, &source.source_census, files, &indexes)?;
        let surface_symbols = collect_surface_symbols(&indexes)?;
        seal_snapshot(HistoricalV3SemanticSnapshot {
            side,
            revision: source.revision.clone(),
            source_snapshot_sha256: source.snapshot_sha256.clone(),
            compiler_indexes: index_evidence(&indexes),
            surface_symbol_count: surface_symbols.len(),
            semantic_census,
            surface_symbols,
            snapshot_sha256: String::new(),
        })
    })();
    match built {
        Ok(snapshot) => super::commitment::validate_snapshot(&snapshot, source, side)
            .map(|()| SnapshotInspection::Completed(Box::new(snapshot)))
            .or_else(|detail| {
                Ok(SnapshotInspection::Excluded(excluded_evidence(
                    side,
                    source,
                    vec![assembly_failure(detail)],
                )))
            }),
        Err(detail) => Ok(SnapshotInspection::Excluded(excluded_evidence(
            side,
            source,
            vec![assembly_failure(detail)],
        ))),
    }
}

fn excluded_evidence(
    side: HistoricalV3SourceSide,
    source: &HistoricalV3SourceSnapshot,
    mut failures: Vec<IntentionalBoundarySemanticCensusFailureEvidence>,
) -> HistoricalV3SemanticSnapshotEvidence {
    failures.sort_by(|left, right| {
        (left.indexer, left.phase, left.reason, &left.detail_sha256).cmp(&(
            right.indexer,
            right.phase,
            right.reason,
            &right.detail_sha256,
        ))
    });
    HistoricalV3SemanticSnapshotEvidence::Excluded {
        side,
        revision: source.revision.clone(),
        source_snapshot_sha256: source.snapshot_sha256.clone(),
        failures,
    }
}

fn side_evidence(inspection: SnapshotInspection) -> HistoricalV3SemanticSnapshotEvidence {
    match inspection {
        SnapshotInspection::Completed(snapshot) => {
            HistoricalV3SemanticSnapshotEvidence::Completed { snapshot }
        }
        SnapshotInspection::Excluded(evidence) => evidence,
    }
}

fn resolve_both_sides(
    base: Result<SnapshotInspection, HistoricalV3RankJournalError>,
    merge: Result<SnapshotInspection, HistoricalV3RankJournalError>,
) -> Result<(SnapshotInspection, SnapshotInspection), HistoricalV3RankJournalError> {
    match (base, merge) {
        (Ok(base), Ok(merge)) => Ok((base, merge)),
        (Err(base), Err(merge)) => Err(combine_errors(base, merge)),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

fn combine_errors(
    first: HistoricalV3RankJournalError,
    second: HistoricalV3RankJournalError,
) -> HistoricalV3RankJournalError {
    let kind = if first.kind == HistoricalV3RankJournalErrorKind::InvalidInput
        || second.kind == HistoricalV3RankJournalErrorKind::InvalidInput
    {
        HistoricalV3RankJournalErrorKind::InvalidInput
    } else if first.kind == HistoricalV3RankJournalErrorKind::InfrastructureFailed
        || second.kind == HistoricalV3RankJournalErrorKind::InfrastructureFailed
    {
        HistoricalV3RankJournalErrorKind::InfrastructureFailed
    } else {
        HistoricalV3RankJournalErrorKind::InfrastructureUnavailable
    };
    HistoricalV3RankJournalError {
        stage: HistoricalV3RankStage::SemanticCensus,
        kind,
        detail: format!("{}; additionally, {}", first.detail, second.detail),
    }
}
