use super::*;

pub async fn census_historical_v2_semantics(
    materialization: &HistoricalV2Materialization,
    roots: &HistoricalV2MaterializedRoots,
    source_census: &HistoricalV2SourceCensus,
) -> Result<HistoricalV2SemanticCensus, String> {
    match census_historical_v2_semantics_typed(materialization, roots, source_census)
        .await
        .map_err(|error| error.detail)?
    {
        HistoricalV2StageResult::Completed(census) => Ok(census),
        HistoricalV2StageResult::Excluded(exclusion) => Err(format!(
            "historical-v2 semantic census excluded: {:?}",
            exclusion.reasons
        )),
    }
}

pub async fn census_historical_v2_semantics_typed(
    materialization: &HistoricalV2Materialization,
    roots: &HistoricalV2MaterializedRoots,
    source_census: &HistoricalV2SourceCensus,
) -> Result<SemanticCensusStageResult, HistoricalV2SlotStageError> {
    census_historical_v2_semantics_typed_internal(materialization, roots, source_census, None).await
}

pub async fn census_historical_v2_semantics_typed_resumable(
    materialization: &HistoricalV2Materialization,
    roots: &HistoricalV2MaterializedRoots,
    source_census: &HistoricalV2SourceCensus,
    progress_root: &Path,
) -> Result<SemanticCensusStageResult, HistoricalV2SlotStageError> {
    census_historical_v2_semantics_typed_internal(
        materialization,
        roots,
        source_census,
        Some(progress_root),
    )
    .await
}

async fn census_historical_v2_semantics_typed_internal(
    materialization: &HistoricalV2Materialization,
    roots: &HistoricalV2MaterializedRoots,
    source_census: &HistoricalV2SourceCensus,
    progress_root: Option<&Path>,
) -> Result<SemanticCensusStageResult, HistoricalV2SlotStageError> {
    validate_historical_v2_source_census_commitment(materialization, roots, source_census)
        .map_err(invalid)?;
    let scope = semantic_scope(materialization, roots, source_census).map_err(infrastructure)?;
    let mut failures = Vec::new();
    let mut stage_errors = Vec::new();
    let progress = progress_root
        .map(progress::HistoricalV2SemanticProgress::open)
        .transpose()
        .map_err(infrastructure)?;
    let base = census_semantic_snapshot(
        HistoricalV2SemanticSnapshotInputs {
            side: HistoricalV2SemanticSnapshotSide::Base,
            root: &roots.base_root,
            source: &source_census.base,
            required_paths: &scope.base_required_paths,
        },
        materialization,
        source_census,
        &scope.changed_indexers,
        progress.as_ref(),
        &mut failures,
        &mut stage_errors,
    )
    .await?;
    let patched = census_semantic_snapshot(
        HistoricalV2SemanticSnapshotInputs {
            side: HistoricalV2SemanticSnapshotSide::Patched,
            root: &roots.patched_root,
            source: &source_census.patched,
            required_paths: &scope.patched_required_paths,
        },
        materialization,
        source_census,
        &scope.changed_indexers,
        progress.as_ref(),
        &mut failures,
        &mut stage_errors,
    )
    .await?;
    if !stage_errors.is_empty() {
        return Err(combine_stage_errors(stage_errors));
    }
    if !failures.is_empty() {
        return terminal_exclusion(materialization, source_census, failures);
    }
    let mut census = HistoricalV2SemanticCensus {
        schema_version: HISTORICAL_V2_SEMANTIC_CENSUS_SCHEMA_VERSION,
        semantic_census_contract: SEMANTIC_CENSUS_CONTRACT.to_string(),
        canonical_repository: materialization.canonical_repository.clone(),
        materialization_sha256: materialization.materialization_sha256.clone(),
        source_census_sha256: source_census.source_census_sha256.clone(),
        changed_indexers: scope
            .changed_indexers
            .iter()
            .copied()
            .map(indexer_kind)
            .collect(),
        base: base.ok_or_else(|| {
            infrastructure("historical-v2 completed base semantic snapshot was not retained")
        })?,
        patched: patched.ok_or_else(|| {
            infrastructure("historical-v2 completed patched semantic snapshot was not retained")
        })?,
        semantic_census_sha256: String::new(),
    };
    census.semantic_census_sha256 = semantic_census_sha256(&census).map_err(infrastructure)?;
    Ok(HistoricalV2StageResult::Completed(census))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn census_semantic_snapshot(
    inputs: HistoricalV2SemanticSnapshotInputs<'_>,
    materialization: &HistoricalV2Materialization,
    source_census: &HistoricalV2SourceCensus,
    changed_indexers: &BTreeSet<SemanticIndexerKind>,
    progress: Option<&progress::HistoricalV2SemanticProgress>,
    failures: &mut Vec<HistoricalV2SemanticCensusFailureEvidence>,
    stage_errors: &mut Vec<HistoricalV2SlotStageError>,
) -> Result<Option<HistoricalV2SemanticSnapshotCensus>, HistoricalV2SlotStageError> {
    if let Some(snapshot) = progress
        .map(|progress| {
            progress.load_snapshot(
                materialization,
                source_census,
                inputs.side,
                inputs.source,
                changed_indexers,
                inputs.required_paths,
            )
        })
        .transpose()
        .map_err(infrastructure)?
        .flatten()
    {
        validation::validate_snapshot(
            inputs.source,
            &snapshot,
            changed_indexers,
            inputs.required_paths,
        )
        .map_err(infrastructure)?;
        return Ok(Some(snapshot));
    }
    let all_files = snapshot_file_records(inputs.root, inputs.source).map_err(infrastructure)?;
    let (scoped_files, required_documents) = scoped_file_records(
        inputs.root,
        &all_files,
        changed_indexers,
        inputs.required_paths,
    )
    .map_err(infrastructure)?;
    let indexer_root = progress.map(|progress| progress.indexer_root(inputs.side));
    let run = run_scoped_indexers(
        inputs.root,
        &scoped_files,
        &required_documents,
        indexer_root.as_deref(),
    )
    .await;
    let Some(indexes) = resolve_indexer_run(
        inputs.side,
        &inputs.source.revision,
        run,
        failures,
        stage_errors,
    ) else {
        return Ok(None);
    };
    let snapshot = resolve_snapshot_build(
        inputs.side,
        &inputs.source.revision,
        build_semantic_snapshot(
            inputs.root,
            inputs.source,
            &all_files,
            changed_indexers,
            inputs.required_paths,
            &indexes,
        ),
        failures,
    );
    if let (Some(progress), Some(snapshot)) = (progress, &snapshot) {
        progress
            .publish_snapshot(
                materialization,
                source_census,
                inputs.side,
                inputs.source,
                changed_indexers,
                inputs.required_paths,
                snapshot,
            )
            .map_err(infrastructure)?;
    }
    Ok(snapshot)
}

async fn run_scoped_indexers(
    repository_root: &Path,
    files: &[FileRecord],
    required_documents: &[FileRecord],
    progress_root: Option<&Path>,
) -> Result<SemanticIndexerBatchOutcome, SemanticIndexerRunFailure> {
    match progress_root {
        Some(progress_root) => {
            crate::semantic_indexer_runner::run_required_indexers_exhaustive_typed_scoped_resumable(
                repository_root,
                files,
                required_documents,
                progress_root,
            )
            .await
        }
        None => {
            crate::semantic_indexer_runner::run_required_indexers_exhaustive_typed_scoped(
                repository_root,
                files,
                required_documents,
            )
            .await
        }
    }
}
