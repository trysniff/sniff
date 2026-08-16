use super::super::intentional_boundary_semantic::{
    SEMANTIC_CENSUS_CONTRACT as SHARED_SEMANTIC_CONTRACT, compute_semantic_census_sha256,
};
use super::super::{
    HISTORICAL_V2_SEMANTIC_CENSUS_SCHEMA_VERSION, HistoricalV2Materialization,
    HistoricalV2MaterializedRoots, HistoricalV2SemanticCensus, HistoricalV2SemanticSnapshotCensus,
    HistoricalV2SourceCensus, HistoricalV2SourceSnapshotCensus,
    INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_SCHEMA_VERSION,
    INTENTIONAL_BOUNDARY_SOURCE_CENSUS_SCHEMA_VERSION, IntentionalBoundaryMethodCensusEntry,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticOrigin,
    IntentionalBoundarySemanticVisibility, IntentionalBoundarySourceCensus,
    IntentionalBoundarySourceFile, validate_historical_v2_source_census,
    validate_intentional_boundary_semantic_census,
};
use super::{SEMANTIC_CENSUS_CONTRACT, semantic_census_sha256, semantic_snapshot_sha256};
use std::collections::BTreeSet;

pub fn validate_historical_v2_semantic_census_commitment(
    materialization: &HistoricalV2Materialization,
    roots: &HistoricalV2MaterializedRoots,
    source_census: &HistoricalV2SourceCensus,
    census: &HistoricalV2SemanticCensus,
) -> Result<(), String> {
    validate_historical_v2_source_census(materialization, roots, source_census)?;
    if census.schema_version != HISTORICAL_V2_SEMANTIC_CENSUS_SCHEMA_VERSION
        || census.semantic_census_contract != SEMANTIC_CENSUS_CONTRACT
        || census.canonical_repository != materialization.canonical_repository
        || census.materialization_sha256 != materialization.materialization_sha256
        || census.source_census_sha256 != source_census.source_census_sha256
        || census.semantic_census_sha256 != semantic_census_sha256(census)?
    {
        return Err("historical-v2 semantic census commitment changed".to_string());
    }
    validate_snapshot(
        &census.canonical_repository,
        &source_census.base,
        &census.base,
    )?;
    validate_snapshot(
        &census.canonical_repository,
        &source_census.patched,
        &census.patched,
    )?;
    Ok(())
}

pub(super) fn validate_snapshot(
    repository: &str,
    source: &HistoricalV2SourceSnapshotCensus,
    semantic: &HistoricalV2SemanticSnapshotCensus,
) -> Result<(), String> {
    if semantic.revision != source.revision
        || semantic.source_snapshot_census_sha256 != source.snapshot_census_sha256
        || !is_sha256(&semantic.semantic_snapshot_sha256)
        || semantic.semantic_snapshot_sha256 != semantic_snapshot_sha256(semantic)?
    {
        return Err("historical-v2 semantic snapshot identity changed".to_string());
    }
    validate_public_symbols(source, semantic)?;
    let source_projection = IntentionalBoundarySourceCensus {
        schema_version: INTENTIONAL_BOUNDARY_SOURCE_CENSUS_SCHEMA_VERSION,
        census_contract: "historical-v2-semantic-validation-projection".to_string(),
        repository: repository.to_string(),
        revision: source.revision.clone(),
        inventory_sha256: source.inventory_sha256.clone(),
        tracked_entry_count: source.tracked_entry_count,
        source_files: source
            .source_files
            .iter()
            .map(|file| IntentionalBoundarySourceFile {
                repository_path: file.repository_path.clone(),
                object_id: file.object_id.clone(),
                byte_length: file.byte_length,
                source_sha256: file.source_sha256.clone(),
                language: file.language.clone(),
                methods: file
                    .methods
                    .iter()
                    .map(|method| IntentionalBoundaryMethodCensusEntry {
                        parser_unit_id: method.parser_unit_id.clone(),
                        symbol_name: method.symbol_name.clone(),
                        start_line: method.start_line,
                        end_line: method.end_line,
                        source_sha256: method.source_sha256.clone(),
                        is_exported: method.is_exported,
                    })
                    .collect(),
            })
            .collect(),
        source_file_count: source.source_file_count,
        method_count: source.method_count,
        census_sha256: source.snapshot_census_sha256.clone(),
    };
    let mut semantic_projection = IntentionalBoundarySemanticCensus {
        schema_version: INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_SCHEMA_VERSION,
        semantic_contract: SHARED_SEMANTIC_CONTRACT.to_string(),
        repository: repository.to_string(),
        revision: semantic.revision.clone(),
        source_census_sha256: source.snapshot_census_sha256.clone(),
        indexers: semantic.indexers.clone(),
        methods: semantic.methods.clone(),
        resolved_method_count: semantic.resolved_method_count,
        compiler_excluded_method_count: semantic.compiler_excluded_method_count,
        unresolved_method_count: semantic.unresolved_method_count,
        semantic_census_sha256: String::new(),
    };
    semantic_projection.semantic_census_sha256 =
        compute_semantic_census_sha256(&semantic_projection)?;
    validate_intentional_boundary_semantic_census(&source_projection, &semantic_projection)
        .map_err(|error| format!("historical-v2 semantic snapshot is invalid: {error}"))
}

fn validate_public_symbols(
    source: &HistoricalV2SourceSnapshotCensus,
    semantic: &HistoricalV2SemanticSnapshotCensus,
) -> Result<(), String> {
    if semantic.public_symbol_count != semantic.public_symbols.len() {
        return Err("historical-v2 public symbol count changed".to_string());
    }
    let indexers = semantic
        .indexers
        .iter()
        .map(|indexer| indexer.indexer)
        .collect::<BTreeSet<_>>();
    let source_paths = source
        .source_files
        .iter()
        .map(|file| file.repository_path.as_str())
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    for public in &semantic.public_symbols {
        if !indexers.contains(&public.indexer)
            || !seen.insert((public.indexer, public.symbol.symbol_id.as_str()))
            || public.symbol.origin != IntentionalBoundarySemanticOrigin::Repository
            || (!matches!(
                public.symbol.visibility,
                IntentionalBoundarySemanticVisibility::Public
                    | IntentionalBoundarySemanticVisibility::Protected
            ) && public.symbol.surfaces.is_empty())
            || public
                .symbol
                .definitions
                .iter()
                .any(|location| !source_paths.contains(location.repository_path.as_str()))
        {
            return Err("historical-v2 public semantic symbol is invalid".to_string());
        }
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
