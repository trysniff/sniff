use super::super::{
    HISTORICAL_V2_SEMANTIC_CENSUS_SCHEMA_VERSION, HistoricalV2Materialization,
    HistoricalV2MaterializedRoots, HistoricalV2SemanticCensus, HistoricalV2SemanticMethodStatus,
    HistoricalV2SemanticSnapshotCensus, HistoricalV2SemanticSymbol, HistoricalV2SourceCensus,
    HistoricalV2SourceSemanticCoverage, HistoricalV2SourceSnapshotCensus,
    IntentionalBoundaryIndexerKind, IntentionalBoundarySemanticOrigin,
    IntentionalBoundarySemanticRange, IntentionalBoundarySemanticVisibility,
    validate_historical_v2_source_census,
};
use super::{
    SEMANTIC_CENSUS_CONTRACT, indexer_for_language, indexer_kind, semantic_census_sha256,
    semantic_scope, semantic_snapshot_sha256,
};
use crate::semantic_indexer_manifest::SemanticIndexerKind;
use std::collections::{BTreeMap, BTreeSet};

pub fn validate_historical_v2_semantic_census_commitment(
    materialization: &HistoricalV2Materialization,
    roots: &HistoricalV2MaterializedRoots,
    source_census: &HistoricalV2SourceCensus,
    census: &HistoricalV2SemanticCensus,
) -> Result<(), String> {
    validate_historical_v2_source_census(materialization, roots, source_census)?;
    let scope = semantic_scope(materialization, roots, source_census)?;
    let changed_indexers = scope
        .changed_indexers
        .iter()
        .copied()
        .map(indexer_kind)
        .collect::<Vec<_>>();
    if census.schema_version != HISTORICAL_V2_SEMANTIC_CENSUS_SCHEMA_VERSION
        || census.semantic_census_contract != SEMANTIC_CENSUS_CONTRACT
        || census.canonical_repository != materialization.canonical_repository
        || census.materialization_sha256 != materialization.materialization_sha256
        || census.source_census_sha256 != source_census.source_census_sha256
        || census.changed_indexers != changed_indexers
        || census.semantic_census_sha256 != semantic_census_sha256(census)?
    {
        return Err("historical-v2 semantic census commitment changed".to_string());
    }
    validate_snapshot(
        &source_census.base,
        &census.base,
        &scope.changed_indexers,
        &scope.base_required_paths,
    )?;
    validate_snapshot(
        &source_census.patched,
        &census.patched,
        &scope.changed_indexers,
        &scope.patched_required_paths,
    )?;
    Ok(())
}

pub(super) fn validate_snapshot(
    source: &HistoricalV2SourceSnapshotCensus,
    semantic: &HistoricalV2SemanticSnapshotCensus,
    changed_indexers: &BTreeSet<SemanticIndexerKind>,
    required_document_paths: &BTreeSet<String>,
) -> Result<(), String> {
    if semantic.revision != source.revision
        || semantic.source_snapshot_census_sha256 != source.snapshot_census_sha256
        || semantic.required_document_paths
            != required_document_paths.iter().cloned().collect::<Vec<_>>()
        || !is_sha256(&semantic.semantic_snapshot_sha256)
        || semantic.semantic_snapshot_sha256 != semantic_snapshot_sha256(semantic)?
    {
        return Err("historical-v2 semantic snapshot identity changed".to_string());
    }

    let expected_indexers = source
        .source_files
        .iter()
        .filter(|file| file.semantic_coverage == HistoricalV2SourceSemanticCoverage::Required)
        .map(|file| indexer_for_language(&file.language))
        .collect::<Result<BTreeSet<_>, String>>()?
        .intersection(changed_indexers)
        .copied()
        .map(indexer_kind)
        .collect::<BTreeSet<_>>();
    let actual_indexers = validate_indexers(semantic)?;
    if actual_indexers != expected_indexers {
        return Err("historical-v2 semantic snapshot indexer coverage changed".to_string());
    }

    let all_source_paths = source
        .source_files
        .iter()
        .map(|file| file.repository_path.as_str())
        .collect::<BTreeSet<_>>();
    let required_source_paths = source
        .source_files
        .iter()
        .filter(|file| file.semantic_coverage == HistoricalV2SourceSemanticCoverage::Required)
        .map(|file| file.repository_path.as_str())
        .collect::<BTreeSet<_>>();
    let symbols = validate_symbols(
        semantic,
        &actual_indexers,
        &all_source_paths,
        &required_source_paths,
    )?;
    let referenced_symbols = validate_methods(
        source,
        semantic,
        &actual_indexers,
        &symbols,
        &all_source_paths,
    )?;
    if semantic.symbols.iter().any(|entry| {
        !entry.is_public_surface
            && !referenced_symbols.contains(&(entry.indexer, entry.symbol.symbol_id.as_str()))
    }) {
        return Err("historical-v2 semantic snapshot contains an unrelated symbol".to_string());
    }
    Ok(())
}

fn validate_indexers(
    semantic: &HistoricalV2SemanticSnapshotCensus,
) -> Result<BTreeSet<IntentionalBoundaryIndexerKind>, String> {
    if semantic
        .indexers
        .windows(2)
        .any(|pair| pair[0].indexer >= pair[1].indexer)
    {
        return Err("historical-v2 semantic indexers are not canonical".to_string());
    }
    let indexers = semantic
        .indexers
        .iter()
        .map(|indexer| indexer.indexer)
        .collect::<BTreeSet<_>>();
    for indexer in &semantic.indexers {
        if indexer.tool_name.trim().is_empty()
            || !is_sha256(&indexer.semantic_facts_sha256)
            || !is_sha256(&indexer.diagnostics_sha256)
        {
            return Err("historical-v2 semantic indexer commitment is invalid".to_string());
        }
    }
    Ok(indexers)
}

type SymbolKey<'a> = (IntentionalBoundaryIndexerKind, &'a str);

fn validate_symbols<'a>(
    semantic: &'a HistoricalV2SemanticSnapshotCensus,
    indexers: &BTreeSet<IntentionalBoundaryIndexerKind>,
    all_source_paths: &BTreeSet<&str>,
    required_source_paths: &BTreeSet<&str>,
) -> Result<BTreeMap<SymbolKey<'a>, &'a HistoricalV2SemanticSymbol>, String> {
    if semantic.symbol_count != semantic.symbols.len()
        || semantic.public_symbol_count
            != semantic
                .symbols
                .iter()
                .filter(|symbol| symbol.is_public_surface)
                .count()
    {
        return Err("historical-v2 semantic symbol counts changed".to_string());
    }
    let mut symbols = BTreeMap::new();
    let mut previous = None;
    for entry in &semantic.symbols {
        let symbol = &entry.symbol;
        let key = (entry.indexer, symbol.symbol_id.as_str());
        if previous.is_some_and(|previous| previous >= key)
            || !indexers.contains(&entry.indexer)
            || symbol.symbol_id.trim().is_empty()
            || symbol.provider_identity.trim().is_empty()
            || symbol.provider_kind.trim().is_empty()
            || symbol.definitions.is_empty()
            || symbol
                .definitions
                .iter()
                .any(|location| !valid_location(location, all_source_paths))
        {
            return Err("historical-v2 semantic symbol is invalid or noncanonical".to_string());
        }
        let is_public_surface = symbol.origin == IntentionalBoundarySemanticOrigin::Repository
            && symbol.definitions.iter().any(|definition| {
                required_source_paths.contains(definition.repository_path.as_str())
            })
            && (matches!(
                symbol.visibility,
                IntentionalBoundarySemanticVisibility::Public
                    | IntentionalBoundarySemanticVisibility::Protected
            ) || !symbol.surfaces.is_empty());
        if entry.is_public_surface != is_public_surface || symbols.insert(key, entry).is_some() {
            return Err("historical-v2 public semantic symbol classification changed".to_string());
        }
        previous = Some(key);
    }
    Ok(symbols)
}

type ExpectedMethod<'a> = (
    &'a str,
    &'a str,
    usize,
    usize,
    IntentionalBoundaryIndexerKind,
);

fn validate_methods<'a>(
    source: &'a HistoricalV2SourceSnapshotCensus,
    semantic: &'a HistoricalV2SemanticSnapshotCensus,
    indexers: &BTreeSet<IntentionalBoundaryIndexerKind>,
    symbols: &BTreeMap<SymbolKey<'a>, &'a HistoricalV2SemanticSymbol>,
    source_paths: &BTreeSet<&str>,
) -> Result<BTreeSet<SymbolKey<'a>>, String> {
    let mut expected = BTreeMap::<&str, ExpectedMethod<'_>>::new();
    for file in source
        .source_files
        .iter()
        .filter(|file| file.semantic_coverage == HistoricalV2SourceSemanticCoverage::Required)
    {
        let indexer = indexer_kind(indexer_for_language(&file.language)?);
        for method in &file.methods {
            if expected
                .insert(
                    method.parser_unit_id.as_str(),
                    (
                        file.repository_path.as_str(),
                        method.symbol_name.as_str(),
                        method.start_line,
                        method.end_line,
                        indexer,
                    ),
                )
                .is_some()
            {
                return Err("historical-v2 source repeats a semantic method".to_string());
            }
        }
    }
    if semantic.methods.len() != expected.len()
        || semantic
            .methods
            .windows(2)
            .any(|pair| pair[0].parser_unit_id >= pair[1].parser_unit_id)
    {
        return Err("historical-v2 semantic method coverage changed".to_string());
    }

    let mut referenced_symbols = BTreeSet::new();
    let mut resolved = 0_usize;
    let mut compiler_excluded = 0_usize;
    for method in &semantic.methods {
        let expected = expected
            .get(method.parser_unit_id.as_str())
            .ok_or_else(|| "historical-v2 semantic census invented a method".to_string())?;
        if method.repository_path != expected.0
            || method.symbol_name != expected.1
            || method.start_line != expected.2
            || method.end_line != expected.3
            || method.indexer != expected.4
            || !(indexers.contains(&method.indexer)
                || matches!(
                    method.status,
                    HistoricalV2SemanticMethodStatus::CompilerExcluded { .. }
                ))
        {
            return Err("historical-v2 semantic method identity changed".to_string());
        }
        match &method.status {
            HistoricalV2SemanticMethodStatus::Resolved {
                symbol_id,
                joined_definition,
            } => {
                let key = (method.indexer, symbol_id.as_str());
                if symbol_id.trim().is_empty()
                    || !symbols.contains_key(&key)
                    || joined_definition
                        .iter()
                        .any(|location| !valid_location(location, source_paths))
                {
                    return Err(
                        "historical-v2 resolved method has invalid compiler evidence".to_string(),
                    );
                }
                referenced_symbols.insert(key);
                resolved += 1;
            }
            HistoricalV2SemanticMethodStatus::CompilerExcluded { reason } => {
                if reason.trim().is_empty() {
                    return Err(
                        "historical-v2 compiler-excluded method has no evidence".to_string()
                    );
                }
                compiler_excluded += 1;
            }
            HistoricalV2SemanticMethodStatus::Unresolved { detail, .. } => {
                if detail.trim().is_empty() {
                    return Err("historical-v2 unresolved method has no evidence".to_string());
                }
            }
        }
    }
    let unresolved = semantic
        .methods
        .len()
        .checked_sub(resolved + compiler_excluded)
        .ok_or_else(|| "historical-v2 semantic method counts underflowed".to_string())?;
    if semantic.resolved_method_count != resolved
        || semantic.compiler_excluded_method_count != compiler_excluded
        || semantic.unresolved_method_count != unresolved
    {
        return Err("historical-v2 semantic method counts changed".to_string());
    }
    Ok(referenced_symbols)
}

fn valid_location(
    location: &IntentionalBoundarySemanticRange,
    source_paths: &BTreeSet<&str>,
) -> bool {
    source_paths.contains(location.repository_path.as_str())
        && (location.end_line_zero_based > location.start_line_zero_based
            || (location.end_line_zero_based == location.start_line_zero_based
                && location.end_character_zero_based >= location.start_character_zero_based))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
