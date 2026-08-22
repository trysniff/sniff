use super::intentional_boundary_ast_compiler_references::{
    AstCompilerReferenceRequirement, compiler_reference_requirements_satisfied,
};
use super::intentional_boundary_ast_generator_marker::exact_generator_marker;
use super::intentional_boundary_ast_outcome::{AstDerivationError, ast_incomplete, ast_invalid};
use super::{
    INTENTIONAL_BOUNDARY_AST_CENSUS_SCHEMA_VERSION, IntentionalBoundaryAstCensus,
    IntentionalBoundaryAstFact, IntentionalBoundaryAstMethod, IntentionalBoundaryAstMethodStatus,
    IntentionalBoundaryMethodCensusEntry, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticMethod,
    IntentionalBoundarySemanticMethodStatus, IntentionalBoundarySemanticRange,
    IntentionalBoundarySemanticResolution, IntentionalBoundarySemanticSourceReference,
    IntentionalBoundarySourceCensus, intentional_boundary_file_records,
    validate_intentional_boundary_semantic_census, validate_intentional_boundary_source_census,
};
use crate::types::FileRecord;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const AST_CONTRACT: &str = "sniffbench-intentional-boundary-source-ast-v12";
pub(super) type AstMethodKey = (String, usize);

pub(super) struct AstMethodSyntaxFact {
    pub end_line: usize,
    pub thin_delegation: Option<IntentionalBoundarySemanticRange>,
    pub distinct_retry_outcomes: Option<(
        IntentionalBoundarySemanticRange,
        IntentionalBoundarySemanticRange,
    )>,
    pub generator_marker: Option<IntentionalBoundarySemanticRange>,
    pub versioned_compatibility_source_contract: Option<IntentionalBoundarySemanticRange>,
    pub versioned_compatibility_compiler_references: Vec<AstCompilerReferenceRequirement>,
}

#[derive(Clone)]
pub(super) struct AstCallableCandidate {
    pub byte_start: usize,
    pub byte_end: usize,
    pub start_line: usize,
    pub end_line: usize,
    pub thin_delegation: Option<IntentionalBoundarySemanticRange>,
    pub distinct_retry_outcomes: Option<(
        IntentionalBoundarySemanticRange,
        IntentionalBoundarySemanticRange,
    )>,
    pub generator_marker: Option<IntentionalBoundarySemanticRange>,
    pub versioned_compatibility_source_contract: Option<IntentionalBoundarySemanticRange>,
    pub versioned_compatibility_compiler_references: Vec<AstCompilerReferenceRequirement>,
}

pub(super) type AstMethodSyntaxFacts = BTreeMap<AstMethodKey, AstMethodSyntaxFact>;
pub(super) type AstSyntaxExtractor =
    fn(&str, &FileRecord) -> Result<AstMethodSyntaxFacts, AstDerivationError>;

pub(super) fn align_callable_candidates(
    repository_path: &str,
    language: &str,
    record: &FileRecord,
    candidates: Vec<AstCallableCandidate>,
) -> Result<AstMethodSyntaxFacts, AstDerivationError> {
    let mut candidates_by_lines = BTreeMap::<(usize, usize), Vec<AstCallableCandidate>>::new();
    let mut seen_spans = BTreeSet::new();
    for candidate in candidates {
        if seen_spans.insert((candidate.byte_start, candidate.byte_end)) {
            candidates_by_lines
                .entry((candidate.start_line, candidate.end_line))
                .or_default()
                .push(candidate);
        }
    }
    let mut methods_by_lines = BTreeMap::<(usize, usize), Vec<&crate::types::MethodRecord>>::new();
    for method in &record.methods {
        methods_by_lines
            .entry((method.start_line, method.end_line))
            .or_default()
            .push(method);
    }
    if candidates_by_lines.keys().collect::<Vec<_>>() != methods_by_lines.keys().collect::<Vec<_>>()
    {
        return Err(ast_incomplete(
            language,
            Some(repository_path),
            format!("{language} AST callable ranges changed from parser census"),
        ));
    }
    let mut facts = BTreeMap::new();
    for (lines, methods) in methods_by_lines {
        let Some(candidates) = candidates_by_lines.get_mut(&lines) else {
            return Err(ast_incomplete(
                language,
                Some(repository_path),
                format!(
                    "{language} AST callable range disappeared at {}-{}",
                    lines.0, lines.1
                ),
            ));
        };
        candidates.sort_by_key(|candidate| (candidate.byte_start, candidate.byte_end));
        if methods.len() != candidates.len() {
            return Err(ast_incomplete(
                language,
                Some(repository_path),
                format!(
                    "{language} AST callable count changed at {}-{}",
                    lines.0, lines.1
                ),
            ));
        }
        for (method, candidate) in methods.into_iter().zip(candidates.iter()) {
            let previous = facts.insert(
                (method.name.clone(), method.start_line),
                AstMethodSyntaxFact {
                    end_line: candidate.end_line,
                    thin_delegation: candidate.thin_delegation.clone(),
                    distinct_retry_outcomes: candidate.distinct_retry_outcomes.clone(),
                    generator_marker: candidate.generator_marker.clone(),
                    versioned_compatibility_source_contract: candidate
                        .versioned_compatibility_source_contract
                        .clone(),
                    versioned_compatibility_compiler_references: candidate
                        .versioned_compatibility_compiler_references
                        .clone(),
                },
            );
            if previous.is_some() {
                return Err(ast_incomplete(
                    language,
                    Some(repository_path),
                    format!(
                        "{language} AST repeated parser method identity at {}:{}",
                        method.start_line, method.name
                    ),
                ));
            }
        }
    }
    Ok(facts)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn census_language_ast(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    language: &str,
    extractor: AstSyntaxExtractor,
) -> Result<IntentionalBoundaryAstCensus, String> {
    validate_intentional_boundary_source_census(
        repository,
        revision,
        root,
        inventory,
        source_census,
    )?;
    validate_intentional_boundary_semantic_census(source_census, semantic_census)?;
    let files = intentional_boundary_file_records(root, inventory, source_census)?;
    derive_language_ast_census(source_census, semantic_census, &files, language, extractor)
        .map_err(|error| error.detail)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_language_ast(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    ast_census: &IntentionalBoundaryAstCensus,
    language: &str,
    extractor: AstSyntaxExtractor,
) -> Result<(), String> {
    let expected = census_language_ast(
        repository,
        revision,
        root,
        inventory,
        source_census,
        semantic_census,
        language,
        extractor,
    )?;
    if ast_census != &expected {
        return Err(format!(
            "intentional-boundary {language} AST census changed"
        ));
    }
    Ok(())
}

pub(super) fn derive_language_ast_census(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    files: &[FileRecord],
    language: &str,
    extractor: AstSyntaxExtractor,
) -> Result<IntentionalBoundaryAstCensus, AstDerivationError> {
    if files.len() != source_census.source_files.len() {
        return Err(ast_invalid(
            language,
            None,
            "intentional-boundary AST input omitted source files",
        ));
    }
    let semantic_methods = semantic_census
        .methods
        .iter()
        .map(|method| (method.parser_unit_id.as_str(), method))
        .collect::<BTreeMap<_, _>>();
    let mut methods = Vec::new();
    for (source_file, file) in source_census.source_files.iter().zip(files) {
        if source_file.language != file.language {
            return Err(ast_invalid(
                language,
                Some(&source_file.repository_path),
                "intentional-boundary AST input changed parser language",
            ));
        }
        if source_file.language != language {
            continue;
        }
        let mut syntax = extractor(&source_file.repository_path, file)?;
        if let Some(marker) = exact_generator_marker(&source_file.repository_path, &file.source) {
            for fact in syntax.values_mut() {
                fact.generator_marker = Some(marker.clone());
            }
        }
        for source_method in &source_file.methods {
            let semantic_method = semantic_methods
                .get(source_method.parser_unit_id.as_str())
                .ok_or_else(|| {
                    ast_invalid(
                        language,
                        Some(&source_file.repository_path),
                        format!(
                            "intentional-boundary AST input omitted semantic method {}",
                            source_method.parser_unit_id
                        ),
                    )
                })?;
            methods.push(derive_method(
                source_method,
                semantic_method,
                &syntax,
                &semantic_census.source_references,
                language,
            )?);
        }
    }
    methods.sort_by(|left, right| left.parser_unit_id.cmp(&right.parser_unit_id));
    let fact_count = methods
        .iter()
        .map(|method| match &method.status {
            IntentionalBoundaryAstMethodStatus::Resolved { facts, .. } => facts.len(),
            _ => 0,
        })
        .sum();
    let mut census = IntentionalBoundaryAstCensus {
        schema_version: INTENTIONAL_BOUNDARY_AST_CENSUS_SCHEMA_VERSION,
        ast_contract: AST_CONTRACT.to_string(),
        repository: semantic_census.repository.clone(),
        revision: semantic_census.revision.clone(),
        source_census_sha256: source_census.census_sha256.clone(),
        semantic_census_sha256: semantic_census.semantic_census_sha256.clone(),
        languages: vec![language.to_string()],
        method_count: methods.len(),
        fact_count,
        methods,
        ast_census_sha256: String::new(),
    };
    census.ast_census_sha256 = compute_ast_census_sha256(&census)
        .map_err(|detail| ast_incomplete(language, None, detail))?;
    Ok(census)
}

fn derive_method(
    source_method: &IntentionalBoundaryMethodCensusEntry,
    semantic_method: &IntentionalBoundarySemanticMethod,
    syntax: &AstMethodSyntaxFacts,
    source_references: &[IntentionalBoundarySemanticSourceReference],
    language: &str,
) -> Result<IntentionalBoundaryAstMethod, AstDerivationError> {
    if semantic_method.symbol_name != source_method.symbol_name
        || semantic_method.start_line != source_method.start_line
        || semantic_method.end_line != source_method.end_line
    {
        return Err(ast_invalid(
            language,
            Some(&semantic_method.repository_path),
            format!(
                "intentional-boundary AST semantic identity changed for {}",
                source_method.parser_unit_id
            ),
        ));
    }
    let syntax_method = syntax
        .get(&(source_method.symbol_name.clone(), source_method.start_line))
        .ok_or_else(|| {
            ast_incomplete(
                language,
                Some(&semantic_method.repository_path),
                format!(
                    "intentional-boundary AST omitted parser method {}",
                    source_method.parser_unit_id
                ),
            )
        })?;
    if syntax_method.end_line > source_method.end_line {
        return Err(ast_incomplete(
            language,
            Some(&semantic_method.repository_path),
            format!(
                "intentional-boundary AST exceeded parser method range {}",
                source_method.parser_unit_id
            ),
        ));
    }
    let status = match &semantic_method.status {
        IntentionalBoundarySemanticMethodStatus::Resolved { symbol, .. } => {
            let mut facts = Vec::new();
            if let Some(call_expression) = &syntax_method.thin_delegation {
                let outgoing = semantic_method
                    .calls
                    .iter()
                    .filter(|call| call.caller == symbol.symbol_id)
                    .collect::<Vec<_>>();
                if let [call] = outgoing.as_slice()
                    && let IntentionalBoundarySemanticResolution::Resolved { value: callee } =
                        &call.callee
                    && range_contains(call_expression, &call.callsite)
                {
                    facts.push(IntentionalBoundaryAstFact::ThinDelegation {
                        call_expression: call_expression.clone(),
                        compiler_callsite: call.callsite.clone(),
                        resolved_callee_symbol_id: callee.clone(),
                    });
                }
            }
            if let Some((retryable_outcome, terminal_outcome)) =
                &syntax_method.distinct_retry_outcomes
            {
                facts.push(IntentionalBoundaryAstFact::DistinctRetryOutcomes {
                    retryable_outcome: retryable_outcome.clone(),
                    terminal_outcome: terminal_outcome.clone(),
                });
            }
            if let Some(marker) = &syntax_method.generator_marker {
                facts.push(IntentionalBoundaryAstFact::GeneratorMarker {
                    marker: marker.clone(),
                });
            }
            if let Some(contract) = &syntax_method.versioned_compatibility_source_contract
                && compiler_reference_requirements_satisfied(
                    &syntax_method.versioned_compatibility_compiler_references,
                    source_references,
                )
            {
                facts.push(
                    IntentionalBoundaryAstFact::VersionedCompatibilitySourceContract {
                        contract: contract.clone(),
                    },
                );
            }
            IntentionalBoundaryAstMethodStatus::Resolved {
                subject_symbol_id: symbol.symbol_id.clone(),
                facts,
            }
        }
        IntentionalBoundarySemanticMethodStatus::CompilerExcluded { reason } => {
            IntentionalBoundaryAstMethodStatus::CompilerExcluded {
                reason: reason.clone(),
            }
        }
        IntentionalBoundarySemanticMethodStatus::Unresolved {
            reason,
            raw_target,
            detail,
        } => IntentionalBoundaryAstMethodStatus::Unresolved {
            reason: *reason,
            raw_target: raw_target.clone(),
            detail: detail.clone(),
        },
    };
    Ok(IntentionalBoundaryAstMethod {
        parser_unit_id: source_method.parser_unit_id.clone(),
        repository_path: semantic_method.repository_path.clone(),
        language: language.to_string(),
        symbol_name: source_method.symbol_name.clone(),
        start_line: source_method.start_line,
        end_line: source_method.end_line,
        status,
    })
}

fn range_contains(
    outer: &IntentionalBoundarySemanticRange,
    inner: &IntentionalBoundarySemanticRange,
) -> bool {
    outer.repository_path == inner.repository_path
        && (
            outer.start_line_zero_based,
            outer.start_character_zero_based,
        ) <= (
            inner.start_line_zero_based,
            inner.start_character_zero_based,
        )
        && (outer.end_line_zero_based, outer.end_character_zero_based)
            >= (inner.end_line_zero_based, inner.end_character_zero_based)
}

fn compute_ast_census_sha256(census: &IntentionalBoundaryAstCensus) -> Result<String, String> {
    let bytes = serde_json::to_vec(&(
        census.schema_version,
        &census.ast_contract,
        &census.repository,
        &census.revision,
        &census.source_census_sha256,
        &census.semantic_census_sha256,
        &census.languages,
        &census.methods,
        census.method_count,
        census.fact_count,
    ))
    .map_err(|error| format!("failed to commit intentional-boundary AST census: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_ast_generator_marker_tests.rs"]
mod generator_marker_tests;
