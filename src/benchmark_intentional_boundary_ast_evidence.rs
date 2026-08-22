use super::intentional_boundary_compiler_evidence::{
    derive_compiler_evidence, finish_evidence_census, push_typed_atom,
};
use super::{
    BoundaryEvidenceKind, IntentionalBoundaryAstCensus, IntentionalBoundaryAstFact,
    IntentionalBoundaryAstMethodStatus, IntentionalBoundaryAstProofKind,
    IntentionalBoundaryEvidenceCensus, IntentionalBoundaryEvidenceProof,
    IntentionalBoundaryRepositoryInventory, IntentionalBoundarySemanticCensus,
    IntentionalBoundarySemanticMethod, IntentionalBoundarySemanticMethodStatus,
    IntentionalBoundarySourceCensus, validate_intentional_boundary_go_ast_census,
    validate_intentional_boundary_javascript_ast_census,
    validate_intentional_boundary_kotlin_ast_census,
    validate_intentional_boundary_python_ast_census, validate_intentional_boundary_rust_ast_census,
    validate_intentional_boundary_semantic_census,
    validate_intentional_boundary_typescript_ast_census,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub(super) const AST_INPUT_PREFIX: &str = "source_ast:";

#[allow(clippy::too_many_arguments)]
pub fn extract_intentional_boundary_compiler_and_ast_evidence(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    ast_censuses: &[IntentionalBoundaryAstCensus],
) -> Result<IntentionalBoundaryEvidenceCensus, String> {
    validate_intentional_boundary_semantic_census(source_census, semantic_census)?;
    let ast_by_language = validate_ast_census_set(
        repository,
        revision,
        root,
        inventory,
        source_census,
        semantic_census,
        ast_censuses,
    )?;
    derive_compiler_and_ast_evidence(source_census, semantic_census, &ast_by_language)
}

#[allow(clippy::too_many_arguments)]
pub fn validate_intentional_boundary_compiler_and_ast_evidence(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    ast_censuses: &[IntentionalBoundaryAstCensus],
    evidence_census: &IntentionalBoundaryEvidenceCensus,
) -> Result<(), String> {
    let expected = extract_intentional_boundary_compiler_and_ast_evidence(
        repository,
        revision,
        root,
        inventory,
        source_census,
        semantic_census,
        ast_censuses,
    )?;
    if evidence_census != &expected {
        return Err("intentional-boundary compiler/AST evidence changed".to_string());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_ast_census_set<'a>(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    ast_censuses: &'a [IntentionalBoundaryAstCensus],
) -> Result<BTreeMap<&'a str, &'a IntentionalBoundaryAstCensus>, String> {
    let by_language = index_ast_census_set(source_census, ast_censuses)?;
    for (language, census) in &by_language {
        match *language {
            "go" => validate_intentional_boundary_go_ast_census(
                repository,
                revision,
                root,
                inventory,
                source_census,
                semantic_census,
                census,
            ),
            "javascript" => validate_intentional_boundary_javascript_ast_census(
                repository,
                revision,
                root,
                inventory,
                source_census,
                semantic_census,
                census,
            ),
            "kotlin" => validate_intentional_boundary_kotlin_ast_census(
                repository,
                revision,
                root,
                inventory,
                source_census,
                semantic_census,
                census,
            ),
            "python" => validate_intentional_boundary_python_ast_census(
                repository,
                revision,
                root,
                inventory,
                source_census,
                semantic_census,
                census,
            ),
            "rust" => validate_intentional_boundary_rust_ast_census(
                repository,
                revision,
                root,
                inventory,
                source_census,
                semantic_census,
                census,
            ),
            "typescript" => validate_intentional_boundary_typescript_ast_census(
                repository,
                revision,
                root,
                inventory,
                source_census,
                semantic_census,
                census,
            ),
            _ => {
                return Err(format!(
                    "intentional-boundary AST evidence has unsupported language {language}"
                ));
            }
        }?;
    }
    Ok(by_language)
}

pub(super) fn index_ast_census_set<'a>(
    source_census: &IntentionalBoundarySourceCensus,
    ast_censuses: &'a [IntentionalBoundaryAstCensus],
) -> Result<BTreeMap<&'a str, &'a IntentionalBoundaryAstCensus>, String> {
    let expected_languages = source_census
        .source_files
        .iter()
        .map(|file| file.language.as_str())
        .collect::<BTreeSet<_>>();
    let mut by_language = BTreeMap::new();
    for census in ast_censuses {
        let [language] = census.languages.as_slice() else {
            return Err(
                "intentional-boundary AST evidence requires one language per census".to_string(),
            );
        };
        if !expected_languages.contains(language.as_str())
            || by_language.insert(language.as_str(), census).is_some()
        {
            return Err(format!(
                "intentional-boundary AST evidence has unexpected or repeated language {language}"
            ));
        }
    }
    if by_language.keys().copied().collect::<BTreeSet<_>>() != expected_languages {
        return Err("intentional-boundary AST evidence omitted a source language".to_string());
    }
    Ok(by_language)
}

pub(super) fn derive_compiler_and_ast_evidence(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    ast_by_language: &BTreeMap<&str, &IntentionalBoundaryAstCensus>,
) -> Result<IntentionalBoundaryEvidenceCensus, String> {
    let compiler = derive_compiler_evidence(source_census, semantic_census)?;
    let semantic_methods = semantic_census
        .methods
        .iter()
        .map(|method| (method.parser_unit_id.as_str(), method))
        .collect::<BTreeMap<_, _>>();
    let mut atoms = compiler.atoms;
    let mut input_census_sha256 = compiler.input_census_sha256;
    for (language, census) in ast_by_language {
        input_census_sha256.insert(
            format!("{AST_INPUT_PREFIX}{language}"),
            census.ast_census_sha256.clone(),
        );
        for ast_method in &census.methods {
            let semantic_method = semantic_methods
                .get(ast_method.parser_unit_id.as_str())
                .ok_or_else(|| {
                    format!(
                        "intentional-boundary AST evidence invented method {}",
                        ast_method.parser_unit_id
                    )
                })?;
            append_method_ast_evidence(&mut atoms, semantic_method, ast_method)?;
        }
    }
    finish_evidence_census(source_census, semantic_census, input_census_sha256, atoms)
}

fn append_method_ast_evidence(
    atoms: &mut Vec<super::IntentionalBoundaryEvidenceAtom>,
    semantic_method: &IntentionalBoundarySemanticMethod,
    ast_method: &super::IntentionalBoundaryAstMethod,
) -> Result<(), String> {
    let (
        IntentionalBoundarySemanticMethodStatus::Resolved { symbol, .. },
        IntentionalBoundaryAstMethodStatus::Resolved {
            subject_symbol_id,
            facts,
        },
    ) = (&semantic_method.status, &ast_method.status)
    else {
        if matches!(
            (&semantic_method.status, &ast_method.status),
            (
                IntentionalBoundarySemanticMethodStatus::CompilerExcluded { .. },
                IntentionalBoundaryAstMethodStatus::CompilerExcluded { .. }
            ) | (
                IntentionalBoundarySemanticMethodStatus::Unresolved { .. },
                IntentionalBoundaryAstMethodStatus::Unresolved { .. }
            )
        ) {
            return Ok(());
        }
        return Err(format!(
            "intentional-boundary AST evidence changed method status {}",
            semantic_method.parser_unit_id
        ));
    };
    if subject_symbol_id != &symbol.symbol_id {
        return Err(format!(
            "intentional-boundary AST evidence changed subject symbol {}",
            semantic_method.parser_unit_id
        ));
    }
    for fact in facts {
        match fact {
            IntentionalBoundaryAstFact::ThinDelegation {
                call_expression,
                compiler_callsite,
                resolved_callee_symbol_id,
            } => push_typed_atom(
                atoms,
                semantic_method,
                subject_symbol_id,
                BoundaryEvidenceKind::CompilerResolvedImplementationOrDelegation,
                IntentionalBoundaryEvidenceProof::SourceAst(
                    IntentionalBoundaryAstProofKind::ThinDelegation,
                ),
                vec![call_expression.clone(), compiler_callsite.clone()],
                vec![resolved_callee_symbol_id.clone()],
            )?,
            IntentionalBoundaryAstFact::DistinctRetryOutcomes {
                retryable_outcome,
                terminal_outcome,
            } => push_typed_atom(
                atoms,
                semantic_method,
                subject_symbol_id,
                BoundaryEvidenceKind::DistinctRetryableAndTerminalOutcomes,
                IntentionalBoundaryEvidenceProof::SourceAst(
                    IntentionalBoundaryAstProofKind::DistinctOutcomeBranches,
                ),
                vec![retryable_outcome.clone(), terminal_outcome.clone()],
                Vec::new(),
            )?,
            IntentionalBoundaryAstFact::GeneratorMarker { marker } => push_typed_atom(
                atoms,
                semantic_method,
                subject_symbol_id,
                BoundaryEvidenceKind::GeneratorIdentity,
                IntentionalBoundaryEvidenceProof::SourceAst(
                    IntentionalBoundaryAstProofKind::GeneratorMarker,
                ),
                vec![marker.clone()],
                Vec::new(),
            )?,
            IntentionalBoundaryAstFact::VersionedCompatibilitySourceContract { contract } => {
                append_versioned_compatibility_evidence(
                    atoms,
                    semantic_method,
                    subject_symbol_id,
                    contract,
                )?;
            }
        }
    }
    Ok(())
}

fn append_versioned_compatibility_evidence(
    atoms: &mut Vec<super::IntentionalBoundaryEvidenceAtom>,
    semantic_method: &IntentionalBoundarySemanticMethod,
    subject_symbol_id: &str,
    contract: &super::IntentionalBoundarySemanticRange,
) -> Result<(), String> {
    let retained_consumers = atoms
        .iter()
        .filter(|atom| {
            atom.subject_parser_unit_id == semantic_method.parser_unit_id
                && atom.subject_symbol_id == subject_symbol_id
                && atom.evidence_kind == BoundaryEvidenceKind::ResolvedConsumer
        })
        .cloned()
        .collect::<Vec<_>>();
    push_typed_atom(
        atoms,
        semantic_method,
        subject_symbol_id,
        BoundaryEvidenceKind::VersionedCompatibilityContract,
        IntentionalBoundaryEvidenceProof::SourceAst(
            IntentionalBoundaryAstProofKind::VersionedCompatibilitySourceContract,
        ),
        vec![contract.clone()],
        Vec::new(),
    )?;
    for consumer in retained_consumers {
        let mut locations = consumer.locations;
        locations.push(contract.clone());
        push_typed_atom(
            atoms,
            semantic_method,
            subject_symbol_id,
            BoundaryEvidenceKind::RetainedCompatibilityConsumer,
            consumer.proof,
            locations,
            consumer.related_symbol_ids,
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_ast_evidence_tests.rs"]
mod tests;
