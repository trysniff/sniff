use super::{
    INTENTIONAL_BOUNDARY_AST_CENSUS_SCHEMA_VERSION, IntentionalBoundaryAstCensus,
    IntentionalBoundaryAstFact, IntentionalBoundaryAstMethod, IntentionalBoundaryAstMethodStatus,
    IntentionalBoundaryMethodCensusEntry, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticMethod,
    IntentionalBoundarySemanticMethodStatus, IntentionalBoundarySemanticRange,
    IntentionalBoundarySemanticResolution, IntentionalBoundarySourceCensus,
    intentional_boundary_file_records, validate_intentional_boundary_semantic_census,
    validate_intentional_boundary_source_census,
};
use crate::types::FileRecord;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const AST_CONTRACT: &str = "sniffbench-intentional-boundary-source-ast-v4";
pub(super) type AstMethodKey = (String, usize);

pub(super) struct AstMethodSyntaxFact {
    pub end_line: usize,
    pub thin_delegation: Option<IntentionalBoundarySemanticRange>,
    pub distinct_retry_outcomes: Option<(
        IntentionalBoundarySemanticRange,
        IntentionalBoundarySemanticRange,
    )>,
    pub generator_marker: Option<IntentionalBoundarySemanticRange>,
    pub versioned_compatibility_annotation: Option<IntentionalBoundarySemanticRange>,
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
    pub versioned_compatibility_annotation: Option<IntentionalBoundarySemanticRange>,
}

pub(super) type AstMethodSyntaxFacts = BTreeMap<AstMethodKey, AstMethodSyntaxFact>;
pub(super) type AstSyntaxExtractor = fn(&str, &FileRecord) -> Result<AstMethodSyntaxFacts, String>;

pub(super) fn align_callable_candidates(
    repository_path: &str,
    language: &str,
    record: &FileRecord,
    candidates: Vec<AstCallableCandidate>,
) -> Result<AstMethodSyntaxFacts, String> {
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
        return Err(format!(
            "{language} AST callable ranges changed from parser census: {repository_path}"
        ));
    }
    let mut facts = BTreeMap::new();
    for (lines, methods) in methods_by_lines {
        let candidates = candidates_by_lines
            .get_mut(&lines)
            .expect("candidate keys were compared");
        candidates.sort_by_key(|candidate| (candidate.byte_start, candidate.byte_end));
        if methods.len() != candidates.len() {
            return Err(format!(
                "{language} AST callable count changed at {}:{}-{}",
                repository_path, lines.0, lines.1
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
                    versioned_compatibility_annotation: candidate
                        .versioned_compatibility_annotation
                        .clone(),
                },
            );
            if previous.is_some() {
                return Err(format!(
                    "{language} AST repeated parser method identity: {}:{}:{}",
                    repository_path, method.start_line, method.name
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
) -> Result<IntentionalBoundaryAstCensus, String> {
    if files.len() != source_census.source_files.len() {
        return Err("intentional-boundary AST input omitted source files".to_string());
    }
    let semantic_methods = semantic_census
        .methods
        .iter()
        .map(|method| (method.parser_unit_id.as_str(), method))
        .collect::<BTreeMap<_, _>>();
    let mut methods = Vec::new();
    for (source_file, file) in source_census.source_files.iter().zip(files) {
        if source_file.language != file.language {
            return Err(format!(
                "intentional-boundary AST input changed parser language: {}",
                source_file.repository_path
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
                    format!(
                        "intentional-boundary AST input omitted semantic method {}",
                        source_method.parser_unit_id
                    )
                })?;
            methods.push(derive_method(
                source_method,
                semantic_method,
                &syntax,
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
    census.ast_census_sha256 = compute_ast_census_sha256(&census)?;
    Ok(census)
}

fn derive_method(
    source_method: &IntentionalBoundaryMethodCensusEntry,
    semantic_method: &IntentionalBoundarySemanticMethod,
    syntax: &AstMethodSyntaxFacts,
    language: &str,
) -> Result<IntentionalBoundaryAstMethod, String> {
    if semantic_method.symbol_name != source_method.symbol_name
        || semantic_method.start_line != source_method.start_line
        || semantic_method.end_line != source_method.end_line
    {
        return Err(format!(
            "intentional-boundary AST semantic identity changed for {}",
            source_method.parser_unit_id
        ));
    }
    let syntax_method = syntax
        .get(&(source_method.symbol_name.clone(), source_method.start_line))
        .ok_or_else(|| {
            format!(
                "intentional-boundary AST omitted parser method {}",
                source_method.parser_unit_id
            )
        })?;
    if syntax_method.end_line > source_method.end_line {
        return Err(format!(
            "intentional-boundary AST exceeded parser method range {}",
            source_method.parser_unit_id
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
            if let Some(annotation) = &syntax_method.versioned_compatibility_annotation {
                facts.push(
                    IntentionalBoundaryAstFact::VersionedCompatibilityAnnotation {
                        annotation: annotation.clone(),
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

fn exact_generator_marker(
    repository_path: &str,
    source: &str,
) -> Option<IntentionalBoundarySemanticRange> {
    source
        .lines()
        .take(20)
        .enumerate()
        .find_map(|(line, text)| {
            let leading = text.len().saturating_sub(text.trim_start().len());
            let trimmed = text.trim();
            let payload = trimmed
                .strip_prefix("//")
                .or_else(|| trimmed.strip_prefix('#'))
                .map(str::trim)
                .or_else(|| {
                    trimmed
                        .strip_prefix("/*")
                        .and_then(|value| value.strip_suffix("*/"))
                        .map(str::trim)
                })?;
            let exact_marker = payload == "@generated"
                || (payload.starts_with("Code generated ") && payload.ends_with(" DO NOT EDIT."));
            exact_marker.then(|| IntentionalBoundarySemanticRange {
                repository_path: repository_path.to_string(),
                start_line_zero_based: line as u32,
                start_character_zero_based: leading as u32,
                end_line_zero_based: line as u32,
                end_character_zero_based: text.len() as u32,
            })
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
