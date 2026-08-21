use super::{
    BoundaryEvidenceKind, INTENTIONAL_BOUNDARY_EVIDENCE_CENSUS_SCHEMA_VERSION,
    IntentionalBoundaryCompilerProofKind, IntentionalBoundaryEvidenceAtom,
    IntentionalBoundaryEvidenceCensus, IntentionalBoundaryEvidenceProof,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticMethod,
    IntentionalBoundarySemanticMethodStatus, IntentionalBoundarySemanticRelationshipKind,
    IntentionalBoundarySemanticResolution, IntentionalBoundarySemanticSurface,
    IntentionalBoundarySemanticTestKind, IntentionalBoundarySemanticVisibility,
    IntentionalBoundarySourceCensus, validate_intentional_boundary_semantic_census,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const EVIDENCE_CENSUS_CONTRACT: &str = "sniffbench-intentional-boundary-typed-evidence-census-v4";
const COMPILER_INPUT: &str = "compiler_semantic_index";

pub fn extract_intentional_boundary_compiler_evidence(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
) -> Result<IntentionalBoundaryEvidenceCensus, String> {
    validate_intentional_boundary_semantic_census(source_census, semantic_census)?;
    derive_compiler_evidence(source_census, semantic_census)
}

pub fn validate_intentional_boundary_compiler_evidence(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    evidence_census: &IntentionalBoundaryEvidenceCensus,
) -> Result<(), String> {
    let expected = extract_intentional_boundary_compiler_evidence(source_census, semantic_census)?;
    if evidence_census != &expected {
        return Err("intentional-boundary compiler evidence changed".to_string());
    }
    Ok(())
}

pub(super) fn validate_evidence_census_commitment(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    census: &IntentionalBoundaryEvidenceCensus,
) -> Result<(), String> {
    if census.schema_version != INTENTIONAL_BOUNDARY_EVIDENCE_CENSUS_SCHEMA_VERSION
        || census.evidence_contract != EVIDENCE_CENSUS_CONTRACT
        || census.repository != source_census.repository
        || census.revision != source_census.revision
        || census.source_census_sha256 != source_census.census_sha256
        || census.semantic_census_sha256 != semantic_census.semantic_census_sha256
        || census.input_census_sha256.get(COMPILER_INPUT)
            != Some(&semantic_census.semantic_census_sha256)
        || census
            .input_census_sha256
            .iter()
            .any(|(key, value)| key.trim().is_empty() || !is_sha256(value))
    {
        return Err("intentional-boundary evidence identity changed".to_string());
    }
    if census
        .atoms
        .windows(2)
        .any(|pair| pair[0].evidence_id >= pair[1].evidence_id)
    {
        return Err("intentional-boundary evidence atom commitment changed".to_string());
    }
    for atom in &census.atoms {
        if atom.evidence_id != compute_atom_id(atom)?
            || atom.subject_parser_unit_id.trim().is_empty()
            || atom.subject_symbol_id.trim().is_empty()
            || atom.locations.is_empty()
            || atom.locations.windows(2).any(|pair| pair[0] >= pair[1])
            || atom
                .related_symbol_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err("intentional-boundary evidence atom commitment changed".to_string());
        }
    }
    let atom_count_by_kind = census
        .atoms
        .iter()
        .fold(BTreeMap::new(), |mut counts, atom| {
            *counts.entry(atom.evidence_kind).or_insert(0) += 1;
            counts
        });
    if census.atom_count_by_kind != atom_count_by_kind
        || compute_evidence_census_sha256(census)? != census.evidence_census_sha256
    {
        return Err("intentional-boundary evidence census commitment changed".to_string());
    }
    Ok(())
}

fn derive_compiler_evidence(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
) -> Result<IntentionalBoundaryEvidenceCensus, String> {
    let mut atoms = Vec::new();
    for method in &semantic_census.methods {
        let IntentionalBoundarySemanticMethodStatus::Resolved {
            symbol,
            joined_definition,
        } = &method.status
        else {
            continue;
        };
        let subject_locations = joined_definition
            .iter()
            .cloned()
            .chain(symbol.definitions.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if subject_locations.is_empty() {
            return Err(format!(
                "resolved intentional-boundary method has no compiler definition: {}",
                method.parser_unit_id
            ));
        }
        if symbol.visibility == IntentionalBoundarySemanticVisibility::Public
            || symbol
                .surfaces
                .contains(&IntentionalBoundarySemanticSurface::PublicApi)
        {
            push_atom(
                &mut atoms,
                method,
                &symbol.symbol_id,
                BoundaryEvidenceKind::ExportedApiIdentity,
                IntentionalBoundaryCompilerProofKind::PublicSymbol,
                subject_locations.clone(),
                Vec::new(),
            )?;
        }
        for call in &method.calls {
            let IntentionalBoundarySemanticResolution::Resolved { value: callee } = &call.callee
            else {
                continue;
            };
            if callee == &symbol.symbol_id && call.caller != symbol.symbol_id {
                push_atom(
                    &mut atoms,
                    method,
                    &symbol.symbol_id,
                    BoundaryEvidenceKind::ResolvedConsumer,
                    IntentionalBoundaryCompilerProofKind::IncomingCall,
                    vec![call.callsite.clone()],
                    vec![call.caller.clone()],
                )?;
            }
        }
        for import in &method.imports {
            if matches!(
                &import.target,
                IntentionalBoundarySemanticResolution::Resolved { value }
                    if value == &symbol.symbol_id
            ) {
                push_atom(
                    &mut atoms,
                    method,
                    &symbol.symbol_id,
                    BoundaryEvidenceKind::ResolvedConsumer,
                    IntentionalBoundaryCompilerProofKind::ResolvedImport,
                    vec![import.location.clone()],
                    Vec::new(),
                )?;
            }
        }
        for relationship in &method.relationships {
            let (proof, evidence_kind) = match relationship.kind {
                IntentionalBoundarySemanticRelationshipKind::Implementation => (
                    IntentionalBoundaryCompilerProofKind::Implementation,
                    BoundaryEvidenceKind::CompilerResolvedImplementationOrDelegation,
                ),
                IntentionalBoundarySemanticRelationshipKind::Override => (
                    IntentionalBoundaryCompilerProofKind::Override,
                    BoundaryEvidenceKind::CompilerResolvedOverrideOrInterface,
                ),
                _ => continue,
            };
            let related = if relationship.source == symbol.symbol_id {
                relationship.target.clone()
            } else {
                relationship.source.clone()
            };
            push_atom(
                &mut atoms,
                method,
                &symbol.symbol_id,
                evidence_kind,
                proof,
                subject_locations.clone(),
                vec![related],
            )?;
            if relationship.kind == IntentionalBoundarySemanticRelationshipKind::Implementation {
                push_atom(
                    &mut atoms,
                    method,
                    &symbol.symbol_id,
                    BoundaryEvidenceKind::CompilerResolvedOverrideOrInterface,
                    proof,
                    subject_locations.clone(),
                    vec![if relationship.source == symbol.symbol_id {
                        relationship.target.clone()
                    } else {
                        relationship.source.clone()
                    }],
                )?;
            }
        }
        for relationship in &method.test_relationships {
            let IntentionalBoundarySemanticResolution::Resolved { value: production } =
                &relationship.production
            else {
                continue;
            };
            if production != &symbol.symbol_id {
                continue;
            }
            let proof = match relationship.kind {
                IntentionalBoundarySemanticTestKind::Mocks => {
                    IntentionalBoundaryCompilerProofKind::TestMock
                }
                IntentionalBoundarySemanticTestKind::Replaces => {
                    IntentionalBoundaryCompilerProofKind::TestReplacement
                }
                _ => continue,
            };
            push_atom(
                &mut atoms,
                method,
                &symbol.symbol_id,
                BoundaryEvidenceKind::ResolvedTestInjectionOrReplacement,
                proof,
                subject_locations.clone(),
                vec![relationship.test_symbol.clone()],
            )?;
        }
        if symbol
            .surfaces
            .contains(&IntentionalBoundarySemanticSurface::FrameworkRegistration)
        {
            push_atom(
                &mut atoms,
                method,
                &symbol.symbol_id,
                BoundaryEvidenceKind::FrameworkRegistration,
                IntentionalBoundaryCompilerProofKind::FrameworkRegistrationSurface,
                subject_locations,
                Vec::new(),
            )?;
        }
    }
    let input_census_sha256 = BTreeMap::from([(
        COMPILER_INPUT.to_string(),
        semantic_census.semantic_census_sha256.clone(),
    )]);
    finish_evidence_census(source_census, semantic_census, input_census_sha256, atoms)
}

pub(super) fn finish_evidence_census(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    input_census_sha256: BTreeMap<String, String>,
    mut atoms: Vec<IntentionalBoundaryEvidenceAtom>,
) -> Result<IntentionalBoundaryEvidenceCensus, String> {
    if input_census_sha256.get(COMPILER_INPUT) != Some(&semantic_census.semantic_census_sha256)
        || input_census_sha256
            .iter()
            .any(|(key, value)| key.trim().is_empty() || !is_sha256(value))
    {
        return Err("intentional-boundary evidence input commitments are incomplete".to_string());
    }
    atoms.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
    if atoms
        .windows(2)
        .any(|pair| pair[0].evidence_id == pair[1].evidence_id && pair[0] != pair[1])
    {
        return Err("intentional-boundary evidence ID collision".to_string());
    }
    atoms.dedup();
    let atom_count_by_kind = atoms.iter().fold(BTreeMap::new(), |mut counts, atom| {
        *counts.entry(atom.evidence_kind).or_insert(0) += 1;
        counts
    });
    let mut census = IntentionalBoundaryEvidenceCensus {
        schema_version: INTENTIONAL_BOUNDARY_EVIDENCE_CENSUS_SCHEMA_VERSION,
        evidence_contract: EVIDENCE_CENSUS_CONTRACT.to_string(),
        repository: semantic_census.repository.clone(),
        revision: semantic_census.revision.clone(),
        source_census_sha256: source_census.census_sha256.clone(),
        semantic_census_sha256: semantic_census.semantic_census_sha256.clone(),
        input_census_sha256,
        atoms,
        atom_count_by_kind,
        evidence_census_sha256: String::new(),
    };
    census.evidence_census_sha256 = compute_evidence_census_sha256(&census)?;
    Ok(census)
}

fn push_atom(
    atoms: &mut Vec<IntentionalBoundaryEvidenceAtom>,
    method: &IntentionalBoundarySemanticMethod,
    subject_symbol_id: &str,
    evidence_kind: BoundaryEvidenceKind,
    compiler_proof: IntentionalBoundaryCompilerProofKind,
    locations: Vec<super::IntentionalBoundarySemanticRange>,
    related_symbol_ids: Vec<String>,
) -> Result<(), String> {
    push_typed_atom(
        atoms,
        method,
        subject_symbol_id,
        evidence_kind,
        IntentionalBoundaryEvidenceProof::CompilerSemanticIndex(compiler_proof),
        locations,
        related_symbol_ids,
    )
}

pub(super) fn push_typed_atom(
    atoms: &mut Vec<IntentionalBoundaryEvidenceAtom>,
    method: &IntentionalBoundarySemanticMethod,
    subject_symbol_id: &str,
    evidence_kind: BoundaryEvidenceKind,
    proof: IntentionalBoundaryEvidenceProof,
    mut locations: Vec<super::IntentionalBoundarySemanticRange>,
    mut related_symbol_ids: Vec<String>,
) -> Result<(), String> {
    locations.sort_by(|left, right| {
        (
            &left.repository_path,
            left.start_line_zero_based,
            left.start_character_zero_based,
            left.end_line_zero_based,
            left.end_character_zero_based,
        )
            .cmp(&(
                &right.repository_path,
                right.start_line_zero_based,
                right.start_character_zero_based,
                right.end_line_zero_based,
                right.end_character_zero_based,
            ))
    });
    locations.dedup();
    if locations.is_empty() {
        return Err("compiler evidence requires an exact source location".to_string());
    }
    related_symbol_ids.sort();
    related_symbol_ids.dedup();
    let mut atom = IntentionalBoundaryEvidenceAtom {
        evidence_id: String::new(),
        evidence_kind,
        subject_parser_unit_id: method.parser_unit_id.clone(),
        subject_symbol_id: subject_symbol_id.to_string(),
        proof,
        locations,
        related_symbol_ids,
    };
    atom.evidence_id = compute_atom_id(&atom)?;
    if atoms.iter().any(|existing| existing == &atom) {
        return Ok(());
    }
    atoms.push(atom);
    Ok(())
}

pub(super) fn compute_atom_id(atom: &IntentionalBoundaryEvidenceAtom) -> Result<String, String> {
    let bytes = serde_json::to_vec(&(
        "sniffbench-intentional-boundary-evidence-atom-v1",
        atom.evidence_kind,
        &atom.subject_parser_unit_id,
        &atom.subject_symbol_id,
        atom.proof,
        &atom.locations,
        &atom.related_symbol_ids,
    ))
    .map_err(|error| format!("failed to commit intentional-boundary evidence atom: {error}"))?;
    Ok(format!("ibe-v1:{}", sha256(&bytes)))
}

pub(super) fn compute_evidence_census_sha256(
    census: &IntentionalBoundaryEvidenceCensus,
) -> Result<String, String> {
    let bytes = serde_json::to_vec(&(
        census.schema_version,
        &census.evidence_contract,
        &census.repository,
        &census.revision,
        &census.source_census_sha256,
        &census.semantic_census_sha256,
        &census.input_census_sha256,
        &census.atoms,
        &census.atom_count_by_kind,
    ))
    .map_err(|error| format!("failed to commit intentional-boundary evidence census: {error}"))?;
    Ok(sha256(&bytes))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_compiler_evidence_tests.rs"]
mod tests;
