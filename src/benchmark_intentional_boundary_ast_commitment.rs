use super::intentional_boundary_ast::{AST_CONTRACT, compute_ast_census_sha256};
use super::{
    INTENTIONAL_BOUNDARY_AST_CENSUS_SCHEMA_VERSION, IntentionalBoundaryAstCensus,
    IntentionalBoundaryAstMethodStatus, IntentionalBoundarySemanticCensus,
    IntentionalBoundarySemanticMethodStatus, IntentionalBoundarySourceCensus,
    validate_intentional_boundary_semantic_census,
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn validate_ast_census_commitment(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    census: &IntentionalBoundaryAstCensus,
) -> Result<(), String> {
    validate_intentional_boundary_semantic_census(source_census, semantic_census)?;
    if census.schema_version != INTENTIONAL_BOUNDARY_AST_CENSUS_SCHEMA_VERSION
        || census.ast_contract != AST_CONTRACT
        || census.repository != source_census.repository
        || census.revision != source_census.revision
        || census.source_census_sha256 != source_census.census_sha256
        || census.semantic_census_sha256 != semantic_census.semantic_census_sha256
        || census.languages.is_empty()
        || census.languages.windows(2).any(|pair| pair[0] >= pair[1])
        || census.method_count != census.methods.len()
        || census.fact_count != fact_count(census)
    {
        return Err("intentional-boundary AST census commitment identity changed".to_string());
    }
    let source_methods = source_census
        .source_files
        .iter()
        .filter(|file| census.languages.contains(&file.language))
        .flat_map(|file| {
            file.methods.iter().map(|method| {
                (
                    method.parser_unit_id.as_str(),
                    (file.language.as_str(), method),
                )
            })
        })
        .collect::<BTreeMap<_, _>>();
    let semantic_methods = semantic_census
        .methods
        .iter()
        .map(|method| (method.parser_unit_id.as_str(), method))
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeSet::new();
    for method in &census.methods {
        let Some((language, source)) = source_methods.get(method.parser_unit_id.as_str()) else {
            return Err("intentional-boundary AST census invented a method".to_string());
        };
        let Some(semantic) = semantic_methods.get(method.parser_unit_id.as_str()) else {
            return Err("intentional-boundary AST census lost semantic lineage".to_string());
        };
        if !seen.insert(method.parser_unit_id.as_str())
            || method.language != *language
            || method.repository_path != semantic.repository_path
            || method.symbol_name != source.symbol_name
            || method.start_line != source.start_line
            || method.end_line != source.end_line
            || !ast_status_matches_semantic(&method.status, &semantic.status)
        {
            return Err("intentional-boundary AST method commitment changed".to_string());
        }
    }
    if seen.len() != source_methods.len()
        || census.ast_census_sha256 != compute_ast_census_sha256(census)?
    {
        return Err("intentional-boundary AST census commitment changed".to_string());
    }
    Ok(())
}

fn fact_count(census: &IntentionalBoundaryAstCensus) -> usize {
    census
        .methods
        .iter()
        .map(|method| match &method.status {
            IntentionalBoundaryAstMethodStatus::Resolved { facts, .. } => facts.len(),
            IntentionalBoundaryAstMethodStatus::CompilerExcluded { .. }
            | IntentionalBoundaryAstMethodStatus::Unresolved { .. } => 0,
        })
        .sum()
}

fn ast_status_matches_semantic(
    ast: &IntentionalBoundaryAstMethodStatus,
    semantic: &IntentionalBoundarySemanticMethodStatus,
) -> bool {
    match (ast, semantic) {
        (
            IntentionalBoundaryAstMethodStatus::Resolved {
                subject_symbol_id, ..
            },
            IntentionalBoundarySemanticMethodStatus::Resolved { symbol, .. },
        ) => subject_symbol_id == &symbol.symbol_id,
        (
            IntentionalBoundaryAstMethodStatus::CompilerExcluded { reason: ast },
            IntentionalBoundarySemanticMethodStatus::CompilerExcluded { reason: semantic },
        ) => ast == semantic,
        (
            IntentionalBoundaryAstMethodStatus::Unresolved {
                reason: ast_reason,
                raw_target: ast_target,
                detail: ast_detail,
            },
            IntentionalBoundarySemanticMethodStatus::Unresolved {
                reason,
                raw_target,
                detail,
            },
        ) => ast_reason == reason && ast_target == raw_target && ast_detail == detail,
        _ => false,
    }
}
