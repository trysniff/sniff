use super::*;
use std::time::Instant;

struct SemanticTiming {
    label: &'static str,
    started: Option<Instant>,
    last: Option<Instant>,
}

impl SemanticTiming {
    fn new(label: &'static str) -> Self {
        let started =
            (std::env::var("SNIFF_BENCH_SEMANTIC_TIMING").as_deref() == Ok("1")).then(Instant::now);
        Self {
            label,
            started,
            last: started,
        }
    }

    fn phase_start(&self, phase: &'static str) {
        if let Some(started) = self.started {
            eprintln!(
                "sniffbench semantic timing label={} phase={} event=start total_ms={}",
                self.label,
                phase,
                started.elapsed().as_millis()
            );
        }
    }

    fn phase(&mut self, phase: &'static str) {
        let (Some(started), Some(last)) = (self.started, self.last) else {
            return;
        };
        let now = Instant::now();
        eprintln!(
            "sniffbench semantic timing label={} phase={} phase_ms={} total_ms={}",
            self.label,
            phase,
            now.duration_since(last).as_millis(),
            now.duration_since(started).as_millis()
        );
        self.last = Some(now);
    }
}

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
    let mut timing = SemanticTiming::new("census");
    timing.phase_start("scope");
    validate_historical_v2_source_census_commitment(materialization, roots, source_census)
        .map_err(invalid)?;
    let scope = semantic_scope(materialization, roots, source_census).map_err(infrastructure)?;
    timing.phase("scope");
    let mut failures = Vec::new();
    let mut stage_errors = Vec::new();
    let progress = progress_root
        .map(progress::HistoricalV2SemanticProgress::open)
        .transpose()
        .map_err(infrastructure)?;
    timing.phase_start("base");
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
    timing.phase("base");
    timing.phase_start("patched");
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
    timing.phase("patched");
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
    timing.phase_start("commitment");
    census.semantic_census_sha256 = semantic_census_sha256(&census).map_err(infrastructure)?;
    timing.phase("commitment");
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
    let mut timing = SemanticTiming::new(match inputs.side {
        HistoricalV2SemanticSnapshotSide::Base => "base",
        HistoricalV2SemanticSnapshotSide::Patched => "patched",
    });
    timing.phase_start("load_snapshot");
    let existing_snapshot = progress
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
        .flatten();
    timing.phase("load_snapshot");
    if let Some(snapshot) = existing_snapshot {
        validation::validate_snapshot(
            inputs.source,
            &snapshot,
            changed_indexers,
            inputs.required_paths,
        )
        .map_err(infrastructure)?;
        timing.phase("validate_reused_snapshot");
        return Ok(Some(snapshot));
    }
    timing.phase_start("prepare_files");
    let all_files = snapshot_file_records(inputs.root, inputs.source).map_err(infrastructure)?;
    let (scoped_files, required_documents) = scoped_file_records(
        inputs.root,
        &all_files,
        changed_indexers,
        inputs.required_paths,
    )
    .map_err(infrastructure)?;
    timing.phase("prepare_files");
    let indexer_root = progress.map(|progress| progress.indexer_root(inputs.side));
    timing.phase_start("compiler_indexing");
    let run = run_scoped_indexers(
        inputs.root,
        inputs.source,
        &scoped_files,
        &required_documents,
        indexer_root.as_deref(),
    )
    .await;
    timing.phase("compiler_indexing");
    let Some(indexes) = resolve_variant_indexer_run(
        inputs.side,
        &inputs.source.revision,
        run,
        failures,
        stage_errors,
    ) else {
        return Ok(None);
    };
    timing.phase("resolve_indexer_run");
    timing.phase_start("assembly");
    let build = build_semantic_snapshot_from_index_sets(
        inputs.root,
        inputs.source,
        &all_files,
        changed_indexers,
        inputs.required_paths,
        indexes,
        progress.map(|store| assembly::SemanticContributionProgress {
            store,
            materialization,
            source_census,
            side: inputs.side,
        }),
    );
    timing.phase("assembly");
    let snapshot = match build {
        Ok(snapshot) => Some(snapshot),
        Err(assembly::SemanticSnapshotAssemblyError::Evidence(detail)) => {
            resolve_snapshot_build(inputs.side, &inputs.source.revision, Err(detail), failures)
        }
        Err(assembly::SemanticSnapshotAssemblyError::Progress(detail)) => {
            return Err(infrastructure(detail));
        }
    };
    timing.phase_start("checkpoint_publication");
    let snapshot = match (progress, snapshot) {
        (Some(progress), Some(snapshot)) => Some(
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
                .map_err(infrastructure)?,
        ),
        (_, snapshot) => snapshot,
    };
    timing.phase("checkpoint_publication");
    Ok(snapshot)
}

async fn run_scoped_indexers(
    repository_root: &Path,
    source: &HistoricalV2SourceSnapshotCensus,
    files: &[FileRecord],
    required_documents: &[FileRecord],
    progress_root: Option<&Path>,
) -> Result<SemanticVariantIndexerBatchOutcome, SemanticIndexerRunFailure> {
    let mut variants = BTreeMap::new();
    if files
        .iter()
        .any(|file| indexer_for_language(&file.language) == Ok(SemanticIndexerKind::Go))
    {
        let semantic_documents = source
            .source_files
            .iter()
            .filter(|file| {
                file.language == "go"
                    && file.semantic_coverage == super::HistoricalV2SourceSemanticCoverage::Required
            })
            .map(|file| crate::semantic_index::RepositoryPath(file.repository_path.clone()))
            .collect();
        variants.insert(
            SemanticIndexerKind::Go,
            variants::go_semantic_variant_plans(&source.go_project_model, &semantic_documents)
                .map_err(|detail| SemanticIndexerRunFailure {
                    kind: SemanticIndexerRunFailureKind::InvalidInput,
                    phase: SemanticIndexerRunPhase::RepositoryValidation,
                    indexer: Some(SemanticIndexerKind::Go),
                    detail,
                    process: None,
                })?,
        );
    }
    if files.iter().any(|file| {
        indexer_for_language(&file.language) == Ok(SemanticIndexerKind::TypeScriptJavaScript)
    }) {
        variants.insert(
            SemanticIndexerKind::TypeScriptJavaScript,
            variants::typescript_semantic_variant_plans(&source.typescript_project_model).map_err(
                |detail| SemanticIndexerRunFailure {
                    kind: SemanticIndexerRunFailureKind::InvalidInput,
                    phase: SemanticIndexerRunPhase::RepositoryValidation,
                    indexer: Some(SemanticIndexerKind::TypeScriptJavaScript),
                    detail,
                    process: None,
                },
            )?,
        );
    }
    match progress_root {
        Some(progress_root) => {
            crate::semantic_indexer_runner::run_required_indexers_exhaustive_typed_scoped_resumable_with_variants(
                repository_root,
                files,
                required_documents,
                progress_root,
                &variants,
            )
            .await
        }
        None => {
            crate::semantic_indexer_runner::run_required_indexers_exhaustive_typed_scoped_with_variants(
                repository_root,
                files,
                required_documents,
                &variants,
            )
            .await
        }
    }
}
