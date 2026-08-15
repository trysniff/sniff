use super::intentional_boundary_compiler_evidence::validate_evidence_census_commitment;
use super::{
    BoundaryCategoryContract, BoundaryEvidenceKind,
    INTENTIONAL_BOUNDARY_CANDIDATE_CENSUS_SCHEMA_VERSION, IntentionalBoundaryCandidate,
    IntentionalBoundaryCandidateCensus, IntentionalBoundaryCategory,
    IntentionalBoundaryEvidenceAtom, IntentionalBoundaryEvidenceCensus,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySourceCensus,
    ValidatedIntentionalBoundaryProtocol, validate_intentional_boundary_semantic_census,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const CANDIDATE_CONTRACT: &str = "sniffbench-intentional-boundary-candidate-census-v1";
const CANDIDATE_ID_CONTRACT: &str = "sniffbench-intentional-boundary-candidate-v1";

pub fn qualify_intentional_boundary_candidates(
    protocol: &ValidatedIntentionalBoundaryProtocol,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    evidence_census: &IntentionalBoundaryEvidenceCensus,
) -> Result<IntentionalBoundaryCandidateCensus, String> {
    validate_intentional_boundary_semantic_census(source_census, semantic_census)?;
    validate_evidence_census_commitment(source_census, semantic_census, evidence_census)?;
    let subjects = semantic_census
        .methods
        .iter()
        .filter_map(|method| match &method.status {
            super::IntentionalBoundarySemanticMethodStatus::Resolved { symbol, .. } => Some((
                method.parser_unit_id.as_str(),
                (method.repository_path.as_str(), symbol.symbol_id.as_str()),
            )),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let mut atoms_by_subject =
        BTreeMap::<(&str, &str), Vec<&IntentionalBoundaryEvidenceAtom>>::new();
    for atom in &evidence_census.atoms {
        let Some((_, exact_symbol_id)) = subjects.get(atom.subject_parser_unit_id.as_str()) else {
            return Err(format!(
                "intentional-boundary evidence names an unresolved parser unit {}",
                atom.subject_parser_unit_id
            ));
        };
        if atom.subject_symbol_id != *exact_symbol_id {
            return Err(format!(
                "intentional-boundary evidence changed the exact symbol for {}",
                atom.subject_parser_unit_id
            ));
        }
        atoms_by_subject
            .entry((
                atom.subject_parser_unit_id.as_str(),
                atom.subject_symbol_id.as_str(),
            ))
            .or_default()
            .push(atom);
    }

    let mut candidates = Vec::new();
    for ((parser_unit_id, symbol_id), atoms) in atoms_by_subject {
        let repository_path = subjects
            .get(parser_unit_id)
            .map(|(path, _)| *path)
            .ok_or_else(|| {
                format!("intentional-boundary evidence invented parser unit {parser_unit_id}")
            })?;
        for contract in &protocol.protocol.category_contracts {
            if let Some((evidence_kinds, evidence_ids)) = qualifying_evidence(contract, &atoms) {
                candidates.push(candidate(
                    contract.category,
                    source_census,
                    repository_path,
                    parser_unit_id,
                    symbol_id,
                    evidence_kinds,
                    evidence_ids,
                )?);
            }
        }
    }
    candidates.sort();
    if candidates
        .windows(2)
        .any(|pair| pair[0].candidate_id == pair[1].candidate_id)
    {
        return Err("intentional-boundary candidate identity collision".to_string());
    }
    let candidate_count_by_category =
        candidates
            .iter()
            .fold(BTreeMap::new(), |mut counts, candidate| {
                *counts.entry(candidate.category).or_insert(0) += 1;
                counts
            });
    let mut census = IntentionalBoundaryCandidateCensus {
        schema_version: INTENTIONAL_BOUNDARY_CANDIDATE_CENSUS_SCHEMA_VERSION,
        candidate_contract: CANDIDATE_CONTRACT.to_string(),
        protocol_sha256: protocol.protocol_sha256.clone(),
        repository: source_census.repository.clone(),
        revision: source_census.revision.clone(),
        source_census_sha256: source_census.census_sha256.clone(),
        semantic_census_sha256: semantic_census.semantic_census_sha256.clone(),
        evidence_census_sha256: evidence_census.evidence_census_sha256.clone(),
        candidates,
        candidate_count_by_category,
        candidate_census_sha256: String::new(),
    };
    census.candidate_census_sha256 = candidate_census_sha256(&census)?;
    Ok(census)
}

pub fn validate_intentional_boundary_candidate_census(
    protocol: &ValidatedIntentionalBoundaryProtocol,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    evidence_census: &IntentionalBoundaryEvidenceCensus,
    candidate_census: &IntentionalBoundaryCandidateCensus,
) -> Result<(), String> {
    let expected = qualify_intentional_boundary_candidates(
        protocol,
        source_census,
        semantic_census,
        evidence_census,
    )?;
    if candidate_census != &expected {
        return Err("intentional-boundary candidate census changed".to_string());
    }
    Ok(())
}

fn qualifying_evidence(
    contract: &BoundaryCategoryContract,
    atoms: &[&IntentionalBoundaryEvidenceAtom],
) -> Option<(Vec<BoundaryEvidenceKind>, Vec<String>)> {
    if !contract.required_evidence_groups.iter().all(|group| {
        group
            .any_of
            .iter()
            .any(|kind| atoms.iter().any(|atom| atom.evidence_kind == *kind))
    }) {
        return None;
    }
    let allowed = contract
        .required_evidence_groups
        .iter()
        .flat_map(|group| group.any_of.iter().copied())
        .collect::<BTreeSet<_>>();
    let evidence_kinds = atoms
        .iter()
        .map(|atom| atom.evidence_kind)
        .filter(|kind| allowed.contains(kind))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let evidence_ids = atoms
        .iter()
        .filter(|atom| allowed.contains(&atom.evidence_kind))
        .map(|atom| atom.evidence_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Some((evidence_kinds, evidence_ids))
}

#[allow(clippy::too_many_arguments)]
fn candidate(
    category: IntentionalBoundaryCategory,
    source_census: &IntentionalBoundarySourceCensus,
    repository_path: &str,
    parser_unit_id: &str,
    symbol_id: &str,
    evidence_kinds: Vec<BoundaryEvidenceKind>,
    evidence_ids: Vec<String>,
) -> Result<IntentionalBoundaryCandidate, String> {
    let candidate_id = hash_json(&(
        CANDIDATE_ID_CONTRACT,
        category,
        &source_census.repository,
        &source_census.revision,
        repository_path,
        symbol_id,
    ))?;
    Ok(IntentionalBoundaryCandidate {
        candidate_id: format!("ibc-v1:{candidate_id}"),
        category,
        repository: source_census.repository.clone(),
        revision: source_census.revision.clone(),
        repository_path: repository_path.to_string(),
        parser_unit_id: parser_unit_id.to_string(),
        exact_symbol_identity: symbol_id.to_string(),
        evidence_kinds,
        evidence_ids,
    })
}

pub(super) fn candidate_census_sha256(
    census: &IntentionalBoundaryCandidateCensus,
) -> Result<String, String> {
    hash_json(&(
        census.schema_version,
        &census.candidate_contract,
        &census.protocol_sha256,
        &census.repository,
        &census.revision,
        &census.source_census_sha256,
        &census.semantic_census_sha256,
        &census.evidence_census_sha256,
        &census.candidates,
        &census.candidate_count_by_category,
    ))
}

fn hash_json(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("failed to commit intentional-boundary candidate census: {error}"))
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_candidate_tests.rs"]
mod tests;
