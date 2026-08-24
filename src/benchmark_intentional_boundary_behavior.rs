use super::intentional_boundary_behavior_outcome::{
    BehaviorDerivationError, BehaviorExecutionAttempt, behavior_invalid, legacy_behavior_error,
};
use super::intentional_boundary_compiler_evidence::validate_evidence_census_commitment;
use super::intentional_boundary_compiler_evidence::{finish_evidence_census, push_typed_atom};
use super::{
    BoundaryEvidenceKind, INTENTIONAL_BOUNDARY_BEHAVIOR_CENSUS_SCHEMA_VERSION,
    IntentionalBoundaryBehaviorCandidate, IntentionalBoundaryBehaviorCandidateStatus,
    IntentionalBoundaryBehaviorCensus, IntentionalBoundaryBehaviorExecution,
    IntentionalBoundaryBehaviorSelector, IntentionalBoundaryBehaviorTestProofKind,
    IntentionalBoundaryBehaviorUnresolvedReason, IntentionalBoundaryBehaviorWitness,
    IntentionalBoundaryBehaviorWitnessOutcome, IntentionalBoundaryEvidenceCensus,
    IntentionalBoundaryEvidenceProof, IntentionalBoundaryRepositoryInventory,
    IntentionalBoundarySemanticCensus, IntentionalBoundarySemanticMethod,
    IntentionalBoundarySemanticMethodStatus, IntentionalBoundarySemanticResolution,
    IntentionalBoundarySemanticTestFacts, IntentionalBoundarySemanticTestKind,
    IntentionalBoundarySourceCensus, validate_intentional_boundary_repository_inventory,
    validate_intentional_boundary_semantic_census, validate_intentional_boundary_source_census,
};
#[cfg(test)]
use super::{IntentionalBoundaryIndexerKind, IntentionalBoundarySemanticSymbolCategory};
#[cfg(test)]
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[path = "benchmark_intentional_boundary_behavior_commitment.rs"]
pub(super) mod commitment;
use commitment::{
    BEHAVIOR_CONTRACT, candidate_id, compute_behavior_census_sha256, finish_behavior_census,
    hash_json, is_sha256, witness_id,
};

#[path = "benchmark_intentional_boundary_behavior_selector.rs"]
mod selector;
#[cfg(test)]
use selector::{is_safe_repository_path, parent_repository_path, rust_harness_name};
use selector::{resolved_symbol_id, selector_for};

#[path = "benchmark_intentional_boundary_behavior_runtime.rs"]
mod runtime;

#[path = "benchmark_intentional_boundary_behavior_output.rs"]
mod output;
use output::{TestCount, count_tests};

#[path = "benchmark_intentional_boundary_behavior_receipt.rs"]
mod receipt;

#[path = "benchmark_intentional_boundary_behavior_validation.rs"]
mod validation;
pub use validation::validate_intentional_boundary_behavior_census_commitment;

#[allow(clippy::too_many_arguments)]
pub fn census_intentional_boundary_behavior_tests(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    base_evidence: &IntentionalBoundaryEvidenceCensus,
) -> Result<IntentionalBoundaryBehaviorCensus, String> {
    census_intentional_boundary_behavior_tests_typed(
        repository,
        revision,
        root,
        inventory,
        source_census,
        semantic_census,
        base_evidence,
    )
    .map_err(legacy_behavior_error)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn census_intentional_boundary_behavior_tests_typed(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    base_evidence: &IntentionalBoundaryEvidenceCensus,
) -> Result<IntentionalBoundaryBehaviorCensus, BehaviorDerivationError> {
    census_behavior_tests_with_executor(
        repository,
        revision,
        root,
        inventory,
        source_census,
        semantic_census,
        base_evidence,
        |selector| runtime::execute_behavior_selector(root, revision, selector),
    )
}

pub fn compose_intentional_boundary_behavior_evidence(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    base_evidence: &IntentionalBoundaryEvidenceCensus,
    behavior_census: &IntentionalBoundaryBehaviorCensus,
) -> Result<IntentionalBoundaryEvidenceCensus, String> {
    validate_intentional_boundary_behavior_census_commitment(
        source_census,
        semantic_census,
        base_evidence,
        behavior_census,
    )?;
    let methods = semantic_census
        .methods
        .iter()
        .map(|method| (method.parser_unit_id.as_str(), method))
        .collect::<BTreeMap<_, _>>();
    let mut atoms = base_evidence.atoms.clone();
    for witness in &behavior_census.witnesses {
        let IntentionalBoundaryBehaviorWitnessOutcome::Passed {
            proof: IntentionalBoundaryBehaviorTestProofKind::TargetedBehaviorPass,
            ..
        } = witness.outcome
        else {
            continue;
        };
        let production = methods
            .get(witness.production_parser_unit_id.as_str())
            .copied()
            .ok_or_else(|| "behavior evidence invented a production method".to_string())?;
        let test = witness
            .test_parser_unit_id
            .as_deref()
            .and_then(|unit| methods.get(unit).copied())
            .ok_or_else(|| "passing behavior evidence has no test method".to_string())?;
        let locations = definition_locations(production)
            .into_iter()
            .chain(definition_locations(test))
            .collect();
        push_typed_atom(
            &mut atoms,
            production,
            &witness.production_symbol_id,
            BoundaryEvidenceKind::PassingBehaviorTest,
            IntentionalBoundaryEvidenceProof::ExecutedBehaviorTest(
                IntentionalBoundaryBehaviorTestProofKind::TargetedBehaviorPass,
            ),
            locations,
            vec![witness.test_symbol_id.clone()],
        )?;
    }
    let mut inputs = base_evidence.input_census_sha256.clone();
    inputs.insert(
        "targeted_behavior_tests".to_string(),
        behavior_census.behavior_census_sha256.clone(),
    );
    finish_evidence_census(source_census, semantic_census, inputs, atoms)
}

pub fn validate_intentional_boundary_behavior_evidence(
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    base_evidence: &IntentionalBoundaryEvidenceCensus,
    behavior_census: &IntentionalBoundaryBehaviorCensus,
    evidence_census: &IntentionalBoundaryEvidenceCensus,
) -> Result<(), String> {
    let expected = compose_intentional_boundary_behavior_evidence(
        source_census,
        semantic_census,
        base_evidence,
        behavior_census,
    )?;
    if evidence_census != &expected {
        return Err("intentional-boundary behavior evidence changed".to_string());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn census_behavior_tests_with_executor<F>(
    repository: &str,
    revision: &str,
    root: &Path,
    inventory: &IntentionalBoundaryRepositoryInventory,
    source_census: &IntentionalBoundarySourceCensus,
    semantic_census: &IntentionalBoundarySemanticCensus,
    base_evidence: &IntentionalBoundaryEvidenceCensus,
    mut executor: F,
) -> Result<IntentionalBoundaryBehaviorCensus, BehaviorDerivationError>
where
    F: FnMut(
        &IntentionalBoundaryBehaviorSelector,
    ) -> Result<BehaviorExecutionAttempt, BehaviorDerivationError>,
{
    validate_intentional_boundary_repository_inventory(repository, revision, root, inventory)
        .map_err(behavior_invalid)?;
    validate_intentional_boundary_source_census(
        repository,
        revision,
        root,
        inventory,
        source_census,
    )
    .map_err(behavior_invalid)?;
    validate_intentional_boundary_semantic_census(source_census, semantic_census)
        .map_err(behavior_invalid)?;
    validate_evidence_census_commitment(source_census, semantic_census, base_evidence)
        .map_err(behavior_invalid)?;
    validate_behavior_base_evidence(base_evidence).map_err(behavior_invalid)?;

    let methods = semantic_census
        .methods
        .iter()
        .map(|method| (method.parser_unit_id.as_str(), method))
        .collect::<BTreeMap<_, _>>();
    let symbol_methods = semantic_census
        .methods
        .iter()
        .filter_map(|method| resolved_symbol_id(method).map(|symbol| (symbol, method)))
        .collect::<BTreeMap<_, _>>();
    let candidate_units = base_evidence
        .atoms
        .iter()
        .filter(|atom| is_behavior_candidate_evidence_kind(atom.evidence_kind))
        .map(|atom| atom.subject_parser_unit_id.as_str())
        .collect::<BTreeSet<_>>();

    let mut candidates = Vec::new();
    let mut witnesses = Vec::new();
    let mut executions = Vec::new();
    let mut execution_ids = BTreeSet::new();
    let mut attempts =
        BTreeMap::<IntentionalBoundaryBehaviorSelector, BehaviorExecutionAttempt>::new();
    for parser_unit_id in candidate_units {
        let method = methods.get(parser_unit_id).copied().ok_or_else(|| {
            behavior_invalid(format!(
                "intentional-boundary behavior evidence invented method {parser_unit_id}"
            ))
        })?;
        let production_symbol_id = resolved_symbol_id(method).ok_or_else(|| {
            behavior_invalid(format!(
                "behavior-test candidate has no compiler identity: {parser_unit_id}"
            ))
        })?;
        if base_evidence.atoms.iter().any(|atom| {
            atom.subject_parser_unit_id == parser_unit_id
                && matches!(
                    atom.evidence_kind,
                    BoundaryEvidenceKind::CompilerResolvedImplementationOrDelegation
                        | BoundaryEvidenceKind::DistinctRetryableAndTerminalOutcomes
                )
                && atom.subject_symbol_id != production_symbol_id
        }) {
            return Err(behavior_invalid(format!(
                "behavior-test candidate changed compiler identity: {parser_unit_id}"
            )));
        }
        let candidate_id =
            candidate_id(parser_unit_id, production_symbol_id).map_err(behavior_invalid)?;
        let behavior_relationships = method
            .test_relationships
            .iter()
            .filter(|relationship| {
                matches!(
                    relationship.kind,
                    IntentionalBoundarySemanticTestKind::Exercises
                        | IntentionalBoundarySemanticTestKind::AssertsContract
                )
            })
            .filter(|relationship| match &relationship.production {
                IntentionalBoundarySemanticResolution::Resolved { value } => {
                    value == production_symbol_id
                }
                IntentionalBoundarySemanticResolution::Unresolved { .. } => true,
            })
            .collect::<Vec<_>>();
        let witness_start = witnesses.len();
        for relationship in behavior_relationships {
            let (test_method, selector, attempt) = match &relationship.production {
                IntentionalBoundarySemanticResolution::Unresolved { detail, .. } => (
                    None,
                    None,
                    BehaviorExecutionAttempt {
                        execution: None,
                        outcome: unresolved(
                            IntentionalBoundaryBehaviorUnresolvedReason::ProductionRelationshipUnresolved,
                            detail.clone(),
                        ),
                    },
                ),
                IntentionalBoundarySemanticResolution::Resolved { .. } => {
                    match symbol_methods.get(relationship.test_symbol.as_str()).copied() {
                        None => (
                            None,
                            None,
                            BehaviorExecutionAttempt {
                                execution: None,
                                outcome: unresolved(
                                    IntentionalBoundaryBehaviorUnresolvedReason::TestMethodUnavailable,
                                    format!(
                                        "compiler test symbol has no parser method: {}",
                                        relationship.test_symbol
                                    ),
                                ),
                            },
                        ),
                        Some(test_method) => match selector_for(test_method) {
                            Ok(selector) => {
                                let attempt = match attempts.get(&selector) {
                                    Some(attempt) => attempt.clone(),
                                    None => {
                                        let attempt = executor(&selector)?;
                                        attempts.insert(selector.clone(), attempt.clone());
                                        attempt
                                    }
                                };
                                (Some(test_method), Some(selector), attempt)
                            }
                            Err((reason, detail)) => (
                                Some(test_method),
                                None,
                                BehaviorExecutionAttempt {
                                    execution: None,
                                    outcome: unresolved(reason, detail),
                                },
                            ),
                        },
                    }
                }
            };
            if let Some(execution) = attempt.execution
                && execution_ids.insert(execution.execution_id.clone())
            {
                executions.push(execution);
            }
            let test_parser_unit_id = test_method.map(|method| method.parser_unit_id.clone());
            let witness_id = witness_id(
                &candidate_id,
                &relationship.test_symbol,
                relationship.kind,
                test_parser_unit_id.as_deref(),
            )
            .map_err(behavior_invalid)?;
            witnesses.push(IntentionalBoundaryBehaviorWitness {
                witness_id,
                candidate_id: candidate_id.clone(),
                production_parser_unit_id: method.parser_unit_id.clone(),
                production_symbol_id: production_symbol_id.to_string(),
                test_parser_unit_id,
                test_symbol_id: relationship.test_symbol.clone(),
                relationship_kind: relationship.kind,
                selector,
                outcome: attempt.outcome,
            });
        }
        let candidate_witnesses = &witnesses[witness_start..];
        let mut passed_witness_ids = candidate_witnesses
            .iter()
            .filter(|witness| {
                matches!(
                    witness.outcome,
                    IntentionalBoundaryBehaviorWitnessOutcome::Passed { .. }
                )
            })
            .map(|witness| witness.witness_id.clone())
            .collect::<Vec<_>>();
        passed_witness_ids.sort();
        let status = if !passed_witness_ids.is_empty() {
            IntentionalBoundaryBehaviorCandidateStatus::Passed {
                witness_ids: passed_witness_ids,
            }
        } else if candidate_witnesses.is_empty() {
            IntentionalBoundaryBehaviorCandidateStatus::NoResolvedBehaviorTest
        } else {
            IntentionalBoundaryBehaviorCandidateStatus::Unresolved
        };
        candidates.push(IntentionalBoundaryBehaviorCandidate {
            candidate_id,
            production_parser_unit_id: method.parser_unit_id.clone(),
            production_symbol_id: production_symbol_id.to_string(),
            status,
        });
    }
    validate_intentional_boundary_repository_inventory(repository, revision, root, inventory)
        .map_err(behavior_invalid)?;
    let census = finish_behavior_census(
        source_census,
        semantic_census,
        base_evidence,
        candidates,
        witnesses,
        executions,
    )
    .map_err(behavior_invalid)?;
    validate_intentional_boundary_behavior_census_commitment(
        source_census,
        semantic_census,
        base_evidence,
        &census,
    )
    .map_err(behavior_invalid)?;
    Ok(census)
}

fn is_behavior_candidate_evidence_kind(kind: BoundaryEvidenceKind) -> bool {
    matches!(
        kind,
        BoundaryEvidenceKind::CompilerResolvedImplementationOrDelegation
            | BoundaryEvidenceKind::DistinctRetryableAndTerminalOutcomes
    )
}

fn definition_locations(
    method: &IntentionalBoundarySemanticMethod,
) -> BTreeSet<super::IntentionalBoundarySemanticRange> {
    match &method.status {
        IntentionalBoundarySemanticMethodStatus::Resolved {
            symbol,
            joined_definition,
        } => joined_definition
            .iter()
            .cloned()
            .chain(symbol.definitions.iter().cloned())
            .collect(),
        _ => BTreeSet::new(),
    }
}

fn unresolved(
    reason: IntentionalBoundaryBehaviorUnresolvedReason,
    detail: String,
) -> IntentionalBoundaryBehaviorWitnessOutcome {
    IntentionalBoundaryBehaviorWitnessOutcome::Unresolved {
        reason,
        detail,
        execution_id: None,
    }
}

fn validate_behavior_base_evidence(
    base_evidence: &IntentionalBoundaryEvidenceCensus,
) -> Result<(), String> {
    if base_evidence
        .input_census_sha256
        .contains_key("targeted_behavior_tests")
        || base_evidence
            .atoms
            .iter()
            .any(|atom| atom.evidence_kind == BoundaryEvidenceKind::PassingBehaviorTest)
    {
        return Err(
            "intentional-boundary behavior evidence cannot be used as its own base".to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "benchmark_intentional_boundary_behavior_tests.rs"]
mod tests;
