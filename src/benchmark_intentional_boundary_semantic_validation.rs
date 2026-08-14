use super::{
    INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_SCHEMA_VERSION, IntentionalBoundarySemanticCensus,
    IntentionalBoundarySemanticMethodStatus, IntentionalBoundarySemanticRange,
    IntentionalBoundarySemanticResolution, IntentionalBoundarySourceCensus,
    SEMANTIC_CENSUS_CONTRACT, compute_semantic_census_sha256, indexer_for_language, indexer_kind,
    is_sha256,
};
use std::collections::{BTreeMap, BTreeSet};

pub fn validate_intentional_boundary_semantic_census(
    source_census: &IntentionalBoundarySourceCensus,
    census: &IntentionalBoundarySemanticCensus,
) -> Result<(), String> {
    if census.schema_version != INTENTIONAL_BOUNDARY_SEMANTIC_CENSUS_SCHEMA_VERSION
        || census.semantic_contract != SEMANTIC_CENSUS_CONTRACT
        || census.repository != source_census.repository
        || census.revision != source_census.revision
        || census.source_census_sha256 != source_census.census_sha256
    {
        return Err("intentional-boundary semantic census identity changed".to_string());
    }
    let expected_indexers = source_census
        .source_files
        .iter()
        .map(|file| indexer_for_language(&file.language).map(indexer_kind))
        .collect::<Result<BTreeSet<_>, String>>()?;
    let actual_indexers = census
        .indexers
        .iter()
        .map(|indexer| indexer.indexer)
        .collect::<BTreeSet<_>>();
    if actual_indexers != expected_indexers || actual_indexers.len() != census.indexers.len() {
        return Err("intentional-boundary semantic census indexer coverage changed".to_string());
    }
    for indexer in &census.indexers {
        if indexer.tool_name.trim().is_empty()
            || !is_sha256(&indexer.semantic_facts_sha256)
            || !is_sha256(&indexer.diagnostics_sha256)
        {
            return Err("intentional-boundary semantic indexer commitment is invalid".to_string());
        }
    }
    let expected_methods = source_census
        .source_files
        .iter()
        .flat_map(|file| {
            file.methods.iter().map(|method| {
                (
                    method.parser_unit_id.as_str(),
                    (
                        file.repository_path.as_str(),
                        method.symbol_name.as_str(),
                        method.start_line,
                        method.end_line,
                        indexer_for_language(&file.language).map(indexer_kind),
                    ),
                )
            })
        })
        .collect::<BTreeMap<_, _>>();
    if expected_methods.len() != source_census.method_count
        || census.methods.len() != source_census.method_count
    {
        return Err("intentional-boundary semantic method coverage changed".to_string());
    }
    let mut seen_methods = BTreeSet::new();
    let source_paths = source_census
        .source_files
        .iter()
        .map(|file| file.repository_path.as_str())
        .collect::<BTreeSet<_>>();
    for method in &census.methods {
        let expected = expected_methods
            .get(method.parser_unit_id.as_str())
            .ok_or_else(|| "intentional-boundary semantic census invented a method".to_string())?;
        if !seen_methods.insert(method.parser_unit_id.as_str())
            || method.repository_path != expected.0
            || method.symbol_name != expected.1
            || method.start_line != expected.2
            || method.end_line != expected.3
            || Ok(method.indexer) != expected.4
        {
            return Err("intentional-boundary semantic method identity changed".to_string());
        }
        if !matches!(
            method.status,
            IntentionalBoundarySemanticMethodStatus::Resolved { .. }
        ) && (!method.occurrences.is_empty()
            || !method.calls.is_empty()
            || !method.relationships.is_empty()
            || !method.imports.is_empty()
            || !method.test_relationships.is_empty())
        {
            return Err(
                "unresolved intentional-boundary method contains invented semantic facts"
                    .to_string(),
            );
        }
        if let IntentionalBoundarySemanticMethodStatus::Resolved {
            symbol,
            joined_definition,
        } = &method.status
            && (symbol.symbol_id.trim().is_empty()
                || symbol.definitions.is_empty()
                || symbol
                    .definitions
                    .iter()
                    .chain(joined_definition.iter())
                    .any(|location| !valid_location(location, &source_paths))
                || method
                    .occurrences
                    .iter()
                    .any(|fact| !valid_location(&fact.location, &source_paths))
                || method.calls.iter().any(|fact| {
                    !valid_location(&fact.callsite, &source_paths)
                        || (fact.caller != symbol.symbol_id
                            && !matches!(
                                &fact.callee,
                                IntentionalBoundarySemanticResolution::Resolved { value }
                                    if value == &symbol.symbol_id
                            ))
                })
                || method
                    .relationships
                    .iter()
                    .any(|fact| fact.source != symbol.symbol_id && fact.target != symbol.symbol_id)
                || method.imports.iter().any(|fact| {
                    !valid_location(&fact.location, &source_paths)
                        || !matches!(
                            &fact.target,
                            IntentionalBoundarySemanticResolution::Resolved { value }
                                if value == &symbol.symbol_id
                        )
                })
                || method.test_relationships.iter().any(|fact| {
                    fact.test_symbol != symbol.symbol_id
                        && !matches!(
                            &fact.production,
                            IntentionalBoundarySemanticResolution::Resolved { value }
                                if value == &symbol.symbol_id
                        )
                }))
        {
            return Err(
                "intentional-boundary semantic method contains unrelated compiler facts"
                    .to_string(),
            );
        }
    }
    let resolved = census
        .methods
        .iter()
        .filter(|method| {
            matches!(
                method.status,
                IntentionalBoundarySemanticMethodStatus::Resolved { .. }
            )
        })
        .count();
    let compiler_excluded = census
        .methods
        .iter()
        .filter(|method| {
            matches!(
                method.status,
                IntentionalBoundarySemanticMethodStatus::CompilerExcluded { .. }
            )
        })
        .count();
    if census.resolved_method_count != resolved
        || census.compiler_excluded_method_count != compiler_excluded
        || census.unresolved_method_count != census.methods.len() - resolved - compiler_excluded
        || !is_sha256(&census.semantic_census_sha256)
        || compute_semantic_census_sha256(census)? != census.semantic_census_sha256
    {
        return Err("intentional-boundary semantic census commitment changed".to_string());
    }
    Ok(())
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
