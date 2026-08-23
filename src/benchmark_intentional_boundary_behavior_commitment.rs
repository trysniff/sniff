use super::{
    INTENTIONAL_BOUNDARY_BEHAVIOR_CENSUS_SCHEMA_VERSION, IntentionalBoundaryBehaviorCandidate,
    IntentionalBoundaryBehaviorCandidateStatus, IntentionalBoundaryBehaviorCensus,
    IntentionalBoundaryBehaviorExecution, IntentionalBoundaryBehaviorWitness,
    IntentionalBoundaryBehaviorWitnessOutcome, IntentionalBoundaryEvidenceCensus,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticTestKind,
    IntentionalBoundarySourceCensus,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(super) const BEHAVIOR_CONTRACT: &str = "sniffbench-intentional-boundary-behavior-v1";

pub(super) fn candidate_id(
    parser_unit_id: &str,
    production_symbol_id: &str,
) -> Result<String, String> {
    Ok(format!(
        "ibbc-v1:{}",
        hash_json(&(
            "sniffbench-intentional-boundary-behavior-candidate-v1",
            parser_unit_id,
            production_symbol_id,
        ))?
    ))
}

pub(super) fn witness_id(
    candidate_id: &str,
    test_symbol_id: &str,
    relationship_kind: IntentionalBoundarySemanticTestKind,
    test_parser_unit_id: Option<&str>,
) -> Result<String, String> {
    Ok(format!(
        "ibbw-v1:{}",
        hash_json(&(
            "sniffbench-intentional-boundary-behavior-witness-v1",
            candidate_id,
            test_symbol_id,
            relationship_kind,
            test_parser_unit_id,
        ))?
    ))
}

pub(in crate::benchmark::release) fn finish_behavior_census(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    base_evidence: &IntentionalBoundaryEvidenceCensus,
    mut candidates: Vec<IntentionalBoundaryBehaviorCandidate>,
    mut witnesses: Vec<IntentionalBoundaryBehaviorWitness>,
    mut executions: Vec<IntentionalBoundaryBehaviorExecution>,
) -> Result<IntentionalBoundaryBehaviorCensus, String> {
    candidates.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
    witnesses.sort_by(|left, right| left.witness_id.cmp(&right.witness_id));
    executions.sort_by(|left, right| left.execution_id.cmp(&right.execution_id));
    if candidates
        .windows(2)
        .any(|pair| pair[0].candidate_id >= pair[1].candidate_id)
        || witnesses
            .windows(2)
            .any(|pair| pair[0].witness_id >= pair[1].witness_id)
        || executions
            .windows(2)
            .any(|pair| pair[0].execution_id >= pair[1].execution_id)
    {
        return Err("intentional-boundary behavior census contains duplicate records".to_string());
    }
    let candidate_count_by_status = candidates.iter().fold(
        BTreeMap::new(),
        |mut counts: BTreeMap<String, usize>, candidate| {
            let key = match candidate.status {
                IntentionalBoundaryBehaviorCandidateStatus::Passed { .. } => "passed",
                IntentionalBoundaryBehaviorCandidateStatus::NoResolvedBehaviorTest => {
                    "no_resolved_behavior_test"
                }
                IntentionalBoundaryBehaviorCandidateStatus::Unresolved => "unresolved",
            };
            *counts.entry(key.to_string()).or_default() += 1;
            counts
        },
    );
    let witness_count_by_status = witnesses.iter().fold(
        BTreeMap::new(),
        |mut counts: BTreeMap<String, usize>, witness| {
            let key = match witness.outcome {
                IntentionalBoundaryBehaviorWitnessOutcome::Passed { .. } => "passed",
                IntentionalBoundaryBehaviorWitnessOutcome::Unresolved { .. } => "unresolved",
            };
            *counts.entry(key.to_string()).or_default() += 1;
            counts
        },
    );
    let mut census = IntentionalBoundaryBehaviorCensus {
        schema_version: INTENTIONAL_BOUNDARY_BEHAVIOR_CENSUS_SCHEMA_VERSION,
        behavior_contract: BEHAVIOR_CONTRACT.to_string(),
        repository: source_census.repository.clone(),
        revision: source_census.revision.clone(),
        source_census_sha256: source_census.census_sha256.clone(),
        semantic_census_sha256: semantic_census.semantic_census_sha256.clone(),
        base_evidence_census_sha256: base_evidence.evidence_census_sha256.clone(),
        candidates,
        witnesses,
        executions,
        candidate_count_by_status,
        witness_count_by_status,
        behavior_census_sha256: String::new(),
    };
    census.behavior_census_sha256 = compute_behavior_census_sha256(&census)?;
    Ok(census)
}

pub(super) fn compute_behavior_census_sha256(
    census: &IntentionalBoundaryBehaviorCensus,
) -> Result<String, String> {
    hash_json(&(
        census.schema_version,
        &census.behavior_contract,
        &census.repository,
        &census.revision,
        &census.source_census_sha256,
        &census.semantic_census_sha256,
        &census.base_evidence_census_sha256,
        &census.candidates,
        &census.witnesses,
        &census.executions,
        &census.candidate_count_by_status,
        &census.witness_count_by_status,
    ))
}

pub(super) fn hash_json(value: &impl serde::Serialize) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("failed to commit behavior-test evidence: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub(super) fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
